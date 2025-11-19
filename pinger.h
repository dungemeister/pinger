#ifndef _PINGER_H
#define _PINGER_H

#include <stdio.h>
#include <unistd.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <netdb.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <sys/time.h>

#define SHIFT_ARG(argc, arg) (--(*(argc)) > 0 ? ((arg)++)[0] : (arg)[0])

#define PRINT_BUF(buf, size) do{\
                                char* ptr = buf;\
                                int i, j, k; \
                                for(i = 0; i < sizeof(struct iphdr); i++){\
                                    printf("0x%02x ", ptr[i] & 0xFF);\
                                }\
                                printf("\n"); \
                                for(j = 0; j < sizeof(struct icmphdr); j++){\
                                    printf("0x%02x ", ptr[i + j] & 0xFF);\
                                } \
                                printf("\n");\
                                }while(0);
#ifdef DEBUG
    #define DEBUG_ARG_PARSER(msg, ...) printf("[ARG_PARSER]: "msg, ##__VA_ARGS__)
#else
    #define DEBUG_ARG_PARSER(msg, ...)
#endif

#define PINGER_DEFAULT_COUNT        (10)
#define PINGER_DEFAULT_TTL          (64)
#define PINGER_DEFAULT_TOS          (0x0)
#define PINGER_DEFAULT_TIMEOUT      (1)
#define PINGER_DEFAULT_INTERVAL     (1.f)

#define PINGER_ARG_COUNT_CHAR       ("-c")
#define PINGER_ARG_TTL_CHAR         ("-t")
#define PINGER_ARG_TOS_CHAR         ("-Q")
#define PINGER_ARG_TIMEOUT_CHAR     ("-w")
#define PINGER_ARG_INTERVAL_CHAR    ("-i")

static char dst_ipstr[INET6_ADDRSTRLEN];

typedef struct{
    uint16_t seq;
    uint16_t id;
    struct timeval send_time;
}sended_packet_data_t;

typedef struct{
    char* buf;
    char* recv_addr;
    int recv_size;
    struct timeval recv_timestamp;
}received_packet_data_t;

#pragma pack(push, 1)
typedef struct {
    struct icmphdr header;
    uint8_t data[64 - sizeof(struct icmphdr)];
}icmp_pkt_t;
#pragma pack(pop)

typedef struct{
    size_t count;
    size_t ttl;
    size_t cos;
    size_t timeout;
    float interval;
    char* bind_interface;
    char* bind_addr;
    char* dst_ip;
    char* dst_hostname;
}pinger_opts_t;

typedef struct{
    size_t transmitted;
    size_t received;
    float min_rtt;
    float max_rtt;
    float avg_rtt;
    float mdev_rtt;
    float sq_rtt_sum;
    double execution_time;
    char dst_host[256];
}pinger_stats_t;

typedef struct{
    ssize_t id;
    ssize_t ttl;
    time_t  time;
}packet_stats_t;

typedef struct{
    pinger_opts_t opts;
    pinger_stats_t stats;
    int sock_fd;
}pinger_t;

//Declarations
static int      run_ping(int* argc, char* args[]);
static void     print_pinger_opts(pinger_t* opts);
static int      parse_args(pinger_t* pinger, int* argc, char* args[]);
static int      resolve_hostname(pinger_t* pinger, struct addrinfo* res);
static int      resolve_bind_address(pinger_t* pinger);
static size_t   build_icmp_packet(icmp_pkt_t* pkt, uint16_t seq);
static int      set_socket_opts(pinger_t* pinger);
static int      send_packet(int sock_fd, struct sockaddr_in dst_addr, icmp_pkt_t* packet, size_t packet_len);
static uint16_t icmp_check_sum(icmp_pkt_t* packet);
static int recv_packet(int sock_fd, struct sockaddr_in* recv_addr, socklen_t* recv_len,
                       char* recv_buf, size_t recv_size);
static bool parse_recv_packet(received_packet_data_t* recv_data, sended_packet_data_t* send_data, pinger_stats_t* stats);
static void init_pinger_stats(pinger_stats_t* stats);
static void print_pinger_statistics(pinger_stats_t* stats);
//Implementation
static int run_ping(int* argc, char* args[]){
    pinger_t pinger = {0};
    icmp_pkt_t packet = {0};
    init_pinger_stats(&pinger.stats);

    char recv_buf[256];

    struct sockaddr_in source_addr;
    source_addr.sin_family = AF_INET;
    source_addr.sin_port = htons(0);

    struct sockaddr_in dst_addr;
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(0);

    struct sockaddr_in recv_addr;
    socklen_t recv_len = sizeof(recv_addr);
    if(parse_args(&pinger, argc, args) != 0){
        return -1;
    }

    print_pinger_opts(&pinger);
    
    dst_addr.sin_addr.s_addr = inet_addr(pinger.opts.dst_ip);
    if (dst_addr.sin_addr.s_addr == INADDR_NONE) {
        printf("ERROR: Invalid IP address\n");
        return -1;
    }
    if((pinger.sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0){
        perror("Fail to create socket");
        return -1;
    }
    set_socket_opts(&pinger);

    if(pinger.opts.bind_addr != NULL){
        source_addr.sin_addr.s_addr = inet_addr(pinger.opts.bind_addr);
        if (bind(pinger.sock_fd, (struct sockaddr*)(&source_addr), sizeof(pinger.opts.bind_addr)) < 0) {
            return -1;
        }

    }
    strcpy(pinger.stats.dst_host, inet_ntoa(dst_addr.sin_addr));
    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);
    for(uint16_t i = 1; i <= pinger.opts.count; i++){
        size_t len = build_icmp_packet(&packet, i);
        packet_stats_t pkt_stats = {0};
        sended_packet_data_t sended_data = {.id = packet.header.un.echo.id,
                                            .seq = packet.header.un.echo.sequence,
                                            .send_time = 0
                                           };
        received_packet_data_t received_data = {0};

        gettimeofday(&sended_data.send_time, NULL);
        int sended = send_packet(pinger.sock_fd, dst_addr, &packet, len);
        if (sended <= 0) continue;
        pinger.stats.transmitted++;
        // printf("\nSended %d, seq 0x%x ", sended, ntohs(packet.header.un.echo.sequence));

        int received = recv_packet(pinger.sock_fd, &recv_addr, &recv_len, recv_buf, sizeof(recv_buf));
        received_data.buf = recv_buf;
        received_data.recv_size = received;
        received_data.recv_addr = inet_ntoa(recv_addr.sin_addr);
        
        if(received > 0){
            if(parse_recv_packet(&received_data, &sended_data, &pinger.stats)){
                float rtt = (received_data.recv_timestamp.tv_sec - sended_data.send_time.tv_sec) * 1000.0 +
                            (received_data.recv_timestamp.tv_usec - sended_data.send_time.tv_usec) / 1000.0;
                pinger.stats.min_rtt = fminf(pinger.stats.min_rtt, rtt);
                pinger.stats.max_rtt = fmaxf(pinger.stats.max_rtt, rtt);
                pinger.stats.avg_rtt = (pinger.stats.avg_rtt * (pinger.stats.received - 1) + rtt) / pinger.stats.received;
                pinger.stats.sq_rtt_sum += rtt * rtt;
                
                printf(" time=%.3f\n", rtt);
            }
        }
        else{
            printf("no answer yet for icmp_seq=%u\n", ntohs(sended_data.seq));
        }
        float diff = (float)(received_data.recv_timestamp.tv_sec - sended_data.send_time.tv_sec);
        float sleep_interval = pinger.opts.interval - diff;
        if(sleep_interval > 0 && i != pinger.opts.count){
            printf("sleep %f\n", sleep_interval);
            sleep((uint32_t)sleep_interval);
        }

        memset(&packet, 0x0, sizeof(packet));
    }
    gettimeofday(&end_time, NULL);
    if(pinger.stats.received > 0){
        float avg_squares = pinger.stats.sq_rtt_sum / pinger.stats.received;
        float avg = pinger.stats.avg_rtt;
        pinger.stats.mdev_rtt = sqrt(avg_squares - avg * avg);
    }
    pinger.stats.execution_time = (end_time.tv_sec - start_time.tv_sec) * 1000.0 +
             (end_time.tv_usec - start_time.tv_usec) / 1000.0;
    print_pinger_statistics(&pinger.stats);
    return 0;
}

static int parse_args(pinger_t* pinger, int* argc, char* args[]){
    pinger->opts.ttl = PINGER_DEFAULT_TTL;
    pinger->opts.cos = PINGER_DEFAULT_TOS;
    pinger->opts.timeout = PINGER_DEFAULT_TIMEOUT;
    pinger->opts.count = PINGER_DEFAULT_COUNT;
    pinger->opts.interval = PINGER_DEFAULT_INTERVAL;

    char* dst_host = SHIFT_ARG(argc, args);
    uint32_t ip = 0;
    struct addrinfo* res = NULL;
    while(*argc > 0){
        char* arg = SHIFT_ARG(argc, args);
        DEBUG_ARG_PARSER("arg %s\n", arg);
        if(strcmp(PINGER_ARG_COUNT_CHAR, arg) == 0){
            pinger->opts.count = atoi(SHIFT_ARG(argc, args));
            DEBUG_ARG_PARSER("count %lu\n", pinger->opts.count);
            assert(pinger->opts.count > 0);
        }
        if(strcmp(PINGER_ARG_TOS_CHAR, arg) == 0){
            pinger->opts.cos = atoi(SHIFT_ARG(argc, args));
            DEBUG_ARG_PARSER("tos 0x%lx\n", pinger->opts.cos);
            assert(pinger->opts.cos > 0);
        }
        if(strcmp(PINGER_ARG_INTERVAL_CHAR, arg) == 0){
            pinger->opts.interval = atof(SHIFT_ARG(argc, args));
            DEBUG_ARG_PARSER("interval %f\n", pinger->opts.interval);
            assert(pinger->opts.interval > 0);
        }
        if(strcmp(PINGER_ARG_TIMEOUT_CHAR, arg) == 0){
            pinger->opts.timeout = atoi(SHIFT_ARG(argc, args));
            DEBUG_ARG_PARSER("timeout %lu\n", pinger->opts.timeout);
            assert(pinger->opts.timeout > 0);
        }
        if(strcmp(PINGER_ARG_TTL_CHAR, arg) == 0){
            char* value = SHIFT_ARG(argc, args);
            char* substr = strstr(value, "0x");
            if(substr != NULL){
                pinger->opts.ttl = strtoul(substr, NULL, 16);
            }
            else{
                pinger->opts.ttl = atoi(value);
            }
            DEBUG_ARG_PARSER("tos 0x%lx\n", pinger->opts.ttl);
            assert(pinger->opts.ttl > 0);
            
        }
    }

    if(inet_pton(AF_INET, dst_host, &ip) == 1){
        pinger->opts.dst_ip = dst_host;
    }
    else{
        pinger->opts.dst_hostname = dst_host;
    }

    if(resolve_hostname(pinger, res) != 0){
        return -1;
    }
    if(resolve_bind_address(pinger) != 0){
        return -1;
    }
    return 0;
}

static void print_pinger_opts(pinger_t* pinger){
    printf("Binded interface: %4s\n", pinger->opts.bind_interface);
    printf("Binded address: %s\n", pinger->opts.bind_addr);
    printf("Dest address: %4s\n", pinger->opts.dst_ip);
    printf("Dest hostname: %4s\n", pinger->opts.dst_hostname);
    printf("Count: %zu ", pinger->opts.count);
    printf("TTL: %zu ", pinger->opts.ttl);
    printf("COS: 0x%lx ", pinger->opts.cos);
    printf("Timeout: %zu ", pinger->opts.timeout);
    printf("Interval: %.2f\n", pinger->opts.interval);
}

static int resolve_hostname(pinger_t* pinger, struct addrinfo* res) {
    if(pinger->opts.dst_hostname == NULL) return 0;

    struct addrinfo hints = {0};
    int status;

    if((status = getaddrinfo(pinger->opts.dst_hostname, NULL, &hints, &res)) != 0) {
        fprintf(stderr, "Error resolving hostname %s: %s\n", pinger->opts.dst_hostname, gai_strerror(status));
        return -1;
    }
    for(struct addrinfo *p = res; p != NULL; p = p->ai_next) {
        void *addr;
        if(p->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in*)(p->ai_addr);
            addr = &ipv4->sin_addr;
            inet_ntop(AF_INET, addr, dst_ipstr, sizeof(dst_ipstr));
            pinger->opts.dst_ip = dst_ipstr;
            return 0;
        }
        //IPv6 support not implemented

    }
    return -1;
}

static int resolve_bind_address(pinger_t* pinger) {
    if(pinger->opts.bind_addr != NULL) {
        struct ifaddrs *ifAddrs = NULL;
        struct ifaddrs *ifAddrsPtr = NULL;
        if(getifaddrs(&ifAddrs)) {
            fprintf(stderr, "Fail to get interfaces addresses");
            return -1;
        }

        for(ifAddrsPtr = ifAddrs; ifAddrsPtr != NULL; ifAddrsPtr = ifAddrsPtr->ifa_next) {
            if(ifAddrsPtr->ifa_addr == NULL) continue;

            if(ifAddrsPtr->ifa_addr->sa_family == AF_INET || ifAddrsPtr->ifa_addr->sa_family == AF_INET6) {
                char addrBuffer[INET6_ADDRSTRLEN];
                void *addrPtr;

                if(ifAddrsPtr->ifa_addr->sa_family == AF_INET) {
                    addrPtr = &((struct sockaddr_in*)(ifAddrsPtr->ifa_addr))->sin_addr;
                }
                if(ifAddrsPtr->ifa_addr->sa_family == AF_INET6) {
                    addrPtr = &((struct sockaddr_in6*)(ifAddrsPtr->ifa_addr))->sin6_addr;
                }
                inet_ntop(ifAddrsPtr->ifa_addr->sa_family, addrPtr, addrBuffer, sizeof(addrBuffer));
                if(strstr(pinger->opts.bind_addr, addrBuffer) != NULL) {
                    printf("Found %s on iface %s\n",addrBuffer, ifAddrsPtr->ifa_name);
                    freeifaddrs(ifAddrs);
                    return 0;
                }
                else{
                    printf("interface is not found\n");
                }
            }   
        }
    }
    return 0;
}

static int set_socket_opts(pinger_t* pinger){
    if(setsockopt(pinger->sock_fd, SOL_IP, IP_TTL, (void *)(&pinger->opts.ttl), sizeof(pinger->opts.ttl))) {
        perror("Fail to set TTL to socket opt");
        return -1;
    }
    if(setsockopt(pinger->sock_fd, SOL_IP, IP_TOS, (void *)(&pinger->opts.cos), sizeof(pinger->opts.cos))) {
        perror("Fail to set TOS (COS) to socket opt");
        return -1;
    }
    struct timeval recv_timeout = {pinger->opts.timeout, 0};
    if(setsockopt(pinger->sock_fd, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(recv_timeout))) {
        perror("Fail to set Timeout to socket opt");
        return -1;
    }
    // struct timeval send_timeout = {0, 0};
    // if(setsockopt(pinger->sock_fd, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(send_timeout))) {
    //     perror("Fail to set Timeout to socket opt");
    //     return -1;
    // }
    return 0;
}

static size_t build_icmp_packet(icmp_pkt_t* pkt, uint16_t seq){
    pkt->header.type = ICMP_ECHO;
    pkt->header.code = 0;
    pkt->header.un.echo.id = htons(getpid() & 0xFFFF);
    struct timeval sentTime;
    gettimeofday(&sentTime, NULL);
    memcpy(pkt->data, &sentTime, sizeof(sentTime));
    pkt->header.un.echo.sequence = htons(seq);
    pkt->header.checksum = htons(icmp_check_sum(pkt));
    return sizeof(icmp_pkt_t);
}

static int send_packet(int sock_fd, struct sockaddr_in remote_addr, icmp_pkt_t* packet, size_t packet_len) {
    int n = 0;
    // std::cout <<std::hex << "time sec " << sentTime.tv_sec << " time usec " << sentTime.tv_usec << "\n";
    if( (n = sendto(sock_fd, packet, packet_len, 0, 
                    (struct sockaddr*)&remote_addr, sizeof(remote_addr))) <= 0 ) {
        
        perror(" ERROR: send icmp packet");
    }
    return n;
}

static int recv_packet(int sock_fd, struct sockaddr_in* recv_addr, socklen_t* recv_len,
                       char* recv_buf, size_t recv_size){
    int received = recvfrom(sock_fd, recv_buf, recv_size, 0,(struct sockaddr*)recv_addr, recv_len);
    if(received < 0){
        // perror("ERROR: Receive packet");
    }
    return received;
}

static uint16_t icmp_check_sum(icmp_pkt_t* packet)
{
    uint32_t sum = 0;
    size_t size = sizeof(icmp_pkt_t);
    uint8_t* buffer = (uint8_t*)(packet);

    // Summarize 2 bytes
    for (size_t i = 0; i < size; i += 2) {
        if (i + 1 < size) {
            uint16_t tmp = ((uint16_t)(buffer[i]) << 8) | buffer[i + 1];
            sum += tmp;
        } else {
            // Sum up the odd remaining byte
            sum += (uint16_t)(buffer[i]) << 8;
        }
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

static bool parse_recv_packet(received_packet_data_t* recv_data, sended_packet_data_t* send_data, pinger_stats_t* stats){
    gettimeofday(&recv_data->recv_timestamp, NULL);
    
    struct iphdr* ip_header = (struct iphdr*)recv_data->buf;
    icmp_pkt_t* icmp = (icmp_pkt_t*)((char*)ip_header + sizeof(struct iphdr));
    
    uint8_t  icmp_type = icmp->header.type;
    uint8_t  icmp_code = icmp->header.code;
    uint16_t recv_seq  = ntohs(icmp->header.un.echo.sequence);
    uint16_t recv_id   = ntohs(icmp->header.un.echo.id);
    // printf("Echo Reply (id=%d, seq=%d)\n", 
    //        ntohs(icmp->header.un.echo.id),
    //        ntohs(icmp->header.un.echo.sequence));
    if(icmp_type == ICMP_ECHOREPLY){
        printf("From %s: ", recv_data->recv_addr);
        printf("%ld bytes icmp seq=%d ttl=%d ",
                recv_data->recv_size - sizeof(struct iphdr),
                ntohs(icmp->header.un.echo.sequence),
                ip_header->ttl);
        stats->received++;

        return true;
    }
    if(recv_seq != send_data->seq || recv_id != send_data->id){
        return false;
        // PRINT_BUF(recv_data->buf, recv_data->recv_size);
        // printf("received %d ", recv_data->recv_size);
        struct iphdr* nested_ip_header = (struct iphdr*)((char*)icmp + sizeof(struct icmphdr));
        icmp_pkt_t* nested_icmp = (icmp_pkt_t*)((char*)nested_ip_header + sizeof(struct iphdr));
        // PRINT_BUF(nested_ip_header, recv_data->recv_size - sizeof(struct iphdr) - sizeof(struct icmphdr));
        // printf("Nested id 0x%x, nested seq %d\n",
        //         nested_icmp->header.un.echo.id,
        //         nested_icmp->header.un.echo.sequence);
        // printf("Sended id 0x%x, sended seq %d\n",
        //         send_data->id,
        //         send_data->seq);
        if(nested_icmp->header.un.echo.id == send_data->id &&
           nested_icmp->header.un.echo.sequence == send_data->seq){
            printf("From %s: ", recv_data->recv_addr);
            
            switch (icmp_type) {
                case ICMP_DEST_UNREACH:
                    printf("Destination Unreachable - ");
                    switch (icmp_code) {
                        case ICMP_NET_UNREACH:
                            printf("Network Unreachable");
                            break;
                        case ICMP_HOST_UNREACH:
                            printf("Host Unreachable");
                            break;
                        case ICMP_PROT_UNREACH:
                            printf("Protocol Unreachable");
                            break;
                        case ICMP_PORT_UNREACH:
                            printf("Port Unreachable");
                            break;
                        case ICMP_FRAG_NEEDED:
                            printf("Fragmentation Needed (MTU=%d)", 
                                ntohs(icmp->header.un.frag.mtu));
                            break;
                        case ICMP_SR_FAILED:
                            printf("Source Route Failed");
                            break;
                        default:
                            printf("Code %d", icmp_code);
                    }
                    
                    break;
                    
                case ICMP_SOURCE_QUENCH:
                    printf("Source Quench");
                    break;
                    
                case ICMP_REDIRECT:
                    printf("Redirect - ");
                    switch (icmp_code) {
                        case ICMP_REDIR_NET:
                            printf("For Network");
                            break;
                        case ICMP_REDIR_HOST:
                            printf("For Host");
                            break;
                        case ICMP_REDIR_NETTOS:
                            printf("For Type of Service and Network");
                            break;
                        case ICMP_REDIR_HOSTTOS:
                            printf("For Type of Service and Host");
                            break;
                    }
                    break;
                    
                case ICMP_TIME_EXCEEDED:
                    printf("Time Exceeded - ");
                    switch (icmp_code) {
                        case ICMP_EXC_TTL:
                            printf("TTL Count Exceeded");
                            break;
                        case ICMP_EXC_FRAGTIME:
                            printf("Fragment Reassembly Time Exceeded");
                            break;
                    }
                    break;
                    
                case ICMP_PARAMETERPROB:
                    printf("Parameter Problem");
                    break;
                    
                case ICMP_TIMESTAMP:
                    printf("Timestamp Request");
                    break;
                    
                case ICMP_TIMESTAMPREPLY:
                    printf("Timestamp Reply");
                    break;
                    
                case ICMP_INFO_REQUEST:
                    printf("Information Request");
                    break;
                    
                case ICMP_INFO_REPLY:
                    printf("Information Reply");
                    break;
                    
                default:
                    printf("Unknown ICMP type %d, code %d", icmp_type, icmp_code);
            }
        }
    }
    return false;    
}

static void print_pinger_statistics(pinger_stats_t* stats){
    printf("--- %s ping statistics ---\n", stats->dst_host);
    printf("%ld packets transmitted, %ld received, %u%% packet loss, time %.3lfms\n",
            stats->transmitted,
            stats->received,
            (int)(1 - (float)stats->received / (float)stats->transmitted) * 100,
            stats->execution_time);

    printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n",
            stats->min_rtt,
            stats->avg_rtt,
            stats->max_rtt,
            stats->mdev_rtt);
}

static void init_pinger_stats(pinger_stats_t* stats){
    stats->avg_rtt = 0;
    stats->min_rtt = INT_MAX;
    stats->max_rtt = 0;
    stats->mdev_rtt = 0;
    stats->received = 0;
    stats->transmitted = 0;
    stats->sq_rtt_sum = 0;
}
#endif //_PINGER_H