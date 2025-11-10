#ifndef _PINGER_H
#define _PINGER_H

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

#define SHIFT_ARG(argc, arg) (--(*(argc)) > 0 ? ((arg)++)[0] : (arg)[0])

char dst_ipstr[INET6_ADDRSTRLEN];

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
    char* bind_interface;
    char* bind_addr;
    char* dst_ip;
    char* dst_hostname;
}pinger_opts_t;

typedef struct{
    size_t transmitted;
    size_t received;
    size_t min_rtt;
    size_t max_rtt;
    size_t avg_rtt;
}pinger_stats_t;

typedef struct{
    pinger_opts_t opts;
    pinger_stats_t stats;
    int sock_fd;
}pinger_t;

static int      run_ping(int* argc, char* args[]);
static void     print_pinger_opts(pinger_t* opts);
static int      parse_args(pinger_t* pinger, int* argc, char* args[]);
static int      resolve_hostname(pinger_t* pinger, struct addrinfo* res);
static int      resolve_bind_address(pinger_t* pinger);
static size_t   build_icmp_packet(icmp_pkt_t* pkt);
static int      set_socket_opts(pinger_t* pinger);
static int      send_packet(int sock_fd, struct sockaddr_in dst_addr, icmp_pkt_t* packet, size_t packet_len);
static uint16_t icmp_check_sum(icmp_pkt_t* packet);

static int run_ping(int* argc, char* args[]){
    pinger_t pinger = {0};
    icmp_pkt_t packet = {0};

    struct sockaddr_in source_addr;
    source_addr.sin_family = AF_INET;
    source_addr.sin_port = htons(0);

    struct sockaddr_in dst_addr;
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(0);

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
    // set_socket_opts(&pinger);

    if(pinger.opts.bind_addr != NULL){
        source_addr.sin_addr.s_addr = inet_addr(pinger.opts.bind_addr);
        if (bind(pinger.sock_fd, (struct sockaddr*)(&source_addr), sizeof(pinger.opts.bind_addr)) < 0) {
            return -1;
        }

    }
    for(size_t i = 0; i < pinger.opts.count; i++){

        size_t len = build_icmp_packet(&packet);
        int sended = send_packet(pinger.sock_fd, dst_addr, &packet, sizeof(packet));
        // ssize_t sended = sendto(pinger.sock_fd, &packet, sizeof(packet), 0,
        //                      (struct sockaddr*)&dst_addr, sizeof(dst_addr));
        printf("Sended %d bytes\n", sended);
        memset(&packet, 0x0, sizeof(packet));
    }

    return 0;
}

static int parse_args(pinger_t* pinger, int* argc, char* args[]){
    char* dst_host = SHIFT_ARG(argc, args);
    uint32_t ip = 0;
    struct addrinfo* res = NULL;

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
    pinger->opts.ttl = 64;
    pinger->opts.cos = 0xc;
    pinger->opts.timeout = 1;
    pinger->opts.count = 1;
    return 0;
}

static void print_pinger_opts(pinger_t* pinger){
    printf("Binded interface: %4s ", pinger->opts.bind_interface);
    printf("Binded address: %s\n", pinger->opts.bind_addr);
    printf("Dest address: %4s ", pinger->opts.dst_ip);
    printf("Dest hostname: %4s ", pinger->opts.dst_hostname);
    printf("Count: %zu\n", pinger->opts.count);
    printf("TTL: %zu ", pinger->opts.ttl);
    printf("COS: %zu\n", pinger->opts.cos);
}

static int resolve_hostname(pinger_t* pinger, struct addrinfo* res) {
    struct addrinfo hints = {0};
    int status;
    if((status = getaddrinfo(pinger->opts.dst_hostname, NULL, &hints, &res)) != 0) {
        char err[128];
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
    //TODO: implement functionality
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
    if(setsockopt(pinger->sock_fd, SOL_IP, SO_RCVTIMEO, (void *)(&pinger->opts.timeout), sizeof(pinger->opts.timeout))) {
        perror("Fail to set Timeout to socket opt");
        return -1;
    }
    return 0;
}

static size_t build_icmp_packet(icmp_pkt_t* pkt){
    pkt->header.type = ICMP_ECHO;
    pkt->header.code = 0;
    pkt->header.un.echo.id = htons(getpid() & 0xFFFF);
    struct timeval sentTime;
    gettimeofday(&sentTime, NULL);
    memcpy(pkt->data, &sentTime, sizeof(sentTime));
    pkt->header.un.echo.sequence = htons(1);
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

static uint16_t icmp_check_sum(icmp_pkt_t* packet)
{
    uint32_t sum = 0;
    size_t size = sizeof(icmp_pkt_t);
    uint8_t* buffer = (uint8_t*)(packet);

    // Суммируем 16-битные слова
    for (size_t i = 0; i < size; i += 2) {
        if (i + 1 < size) {
            uint16_t tmp = ((uint16_t)(buffer[i]) << 8) | buffer[i + 1];
            sum += tmp;
        } else {
            // Обработка нечётного байта
            sum += (uint16_t)(buffer[i]) << 8;
        }
    }

    // Складываем переносы
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Инвертируем результат
    return (uint16_t)(~sum);
}

static int check_network_connectivity() {
    printf("=== Network Connectivity Check ===\n");
    
    // Пробуем обычный UDP сокет
    int test_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (test_sock < 0) {
        perror("Cannot create test socket");
        return -1;
    }
    
    struct sockaddr_in google_dns = {
        .sin_family = AF_INET,
        .sin_port = htons(53),
        .sin_addr.s_addr = inet_addr("8.8.8.8")
    };
    
    // Простая отправка (не обязательно получим ответ)
    char test_data[] = "test";
    ssize_t result = sendto(test_sock, test_data, sizeof(test_data), 0,
                           (struct sockaddr*)&google_dns, sizeof(google_dns));
    
    if (result < 0) {
        perror("Basic network test failed");
        printf("Check your network connection!\n");
    } else {
        printf("Basic network connectivity: OK\n");
    }
    
    close(test_sock);
    return result;
}

static void check_system_raw_socket_support() {
    printf("=== Raw Socket Support Check ===\n");
    
    // Проверяем несколько способов создания raw socket
    int protocols[] = {IPPROTO_ICMP, IPPROTO_RAW, IPPROTO_TCP, 0};
    const char *protocol_names[] = {"ICMP", "RAW", "TCP", NULL};
    
    for (int i = 0; protocols[i] != 0; i++) {
        int sock = socket(AF_INET, SOCK_RAW, protocols[i]);
        if (sock >= 0) {
            printf("✓ RAW socket with protocol %s: SUCCESS (fd=%d)\n", 
                   protocol_names[i], sock);
            
            // Проверяем отправку
            struct sockaddr_in test_addr;
            memset(&test_addr, 0, sizeof(test_addr));
            test_addr.sin_family = AF_INET;
            test_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
            
            char test_data[] = "test";
            ssize_t sent = sendto(sock, test_data, sizeof(test_data), 0,
                                 (struct sockaddr*)&test_addr, sizeof(test_addr));
            
            if (sent > 0) {
                printf("  → Send test: SUCCESS (%zd bytes)\n", sent);
            } else {
                printf("  → Send test: FAILED - ");
                perror("");
            }
            close(sock);
        } else {
            printf("✗ RAW socket with protocol %s: FAILED - ", protocol_names[i]);
            perror("");
        }
    }
}

static void check_kernel_restrictions() {
    printf("\n=== Kernel Restrictions Check ===\n");
    
    // Проверяем sysctl параметры
    FILE *fp;
    char buffer[256];
    
    const char *sysctls[] = {
        "net.ipv4.ping_group_range",
        "net.ipv4.ip_unprivileged_port_start",
        "net.ipv4.ip_local_port_range",
        NULL
    };
    
    for (int i = 0; sysctls[i] != NULL; i++) {
        char command[128];
        snprintf(command, sizeof(command), "sysctl %s 2>/dev/null", sysctls[i]);
        fp = popen(command, "r");
        if (fp) {
            if (fgets(buffer, sizeof(buffer), fp)) {
                printf("%s: %s", sysctls[i], buffer);
            } else {
                printf("%s: not available\n", sysctls[i]);
            }
            pclose(fp);
        }
    }
    
    // Проверяем capabilities
    fp = popen("capsh --print 2>/dev/null | grep -i cap_net_raw", "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            printf("Capabilities with CAP_NET_RAW: %s", buffer);
        } else {
            printf("CAP_NET_RAW: not found in capabilities\n");
        }
        pclose(fp);
    }
}

int test_icmp_echo_with_different_methods() {
    printf("\n=== ICMP Echo Test Different Methods ===\n");
    
    // Метод 1: Стандартный ICMP
    printf("Method 1: Standard ICMP Echo\n");
    int sock1 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock1 >= 0) {
        struct icmphdr icmp;
        memset(&icmp, 0, sizeof(icmp));
        icmp.type = ICMP_ECHO;
        icmp.code = 0;
        icmp.un.echo.id = htons(getpid());
        icmp.un.echo.sequence = htons(1);
        icmp.checksum = 0;
        icmp.checksum = ~((icmp.type << 8) + icmp.code + 
                         icmp.un.echo.id + icmp.un.echo.sequence);
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr("8.8.8.8");
        
        ssize_t sent = sendto(sock1, &icmp, sizeof(icmp), 0,
                             (struct sockaddr*)&dest, sizeof(dest));
        if (sent > 0) {
            printf("✓ SUCCESS: Sent %zd bytes\n", sent);
            close(sock1);
            return 1;
        } else {
            printf("✗ FAILED: ");
            perror("sendto");
        }
        close(sock1);
    } else {
        printf("✗ Cannot create ICMP socket: ");
        perror("socket");
    }
    
    // Метод 2: IPPROTO_RAW с ручным IP заголовком
    printf("\nMethod 2: IPPROTO_RAW with manual IP header\n");
    int sock2 = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock2 >= 0) {
        printf("✓ IPPROTO_RAW socket created\n");
        
        // Включаем IP_HDRINCL для ручного создания IP заголовка
        int one = 1;
        if (setsockopt(sock2, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) == 0) {
            printf("✓ IP_HDRINCL set successfully\n");
            
            // Создаём полный IP+ICMP пакет
            char packet[sizeof(struct iphdr) + sizeof(struct icmphdr)];
            struct iphdr *ip = (struct iphdr*)packet;
            struct icmphdr *icmp = (struct icmphdr*)(packet + sizeof(struct iphdr));
            
            // Заполняем IP заголовок
            ip->version = 4;
            ip->ihl = 5;
            ip->tos = 0;
            ip->tot_len = htons(sizeof(packet));
            ip->id = htons(getpid());
            ip->frag_off = 0;
            ip->ttl = 64;
            ip->protocol = IPPROTO_ICMP;
            ip->check = 0;
            ip->saddr = INADDR_ANY;
            ip->daddr = inet_addr("8.8.8.8");
            
            // Заполняем ICMP
            memset(icmp, 0, sizeof(struct icmphdr));
            icmp->type = ICMP_ECHO;
            icmp->code = 0;
            icmp->un.echo.id = htons(getpid());
            icmp->un.echo.sequence = htons(1);
            icmp->checksum = 0;
            // Расчет checksum только для ICMP части
            icmp->checksum = ~((icmp->type << 8) + icmp->code + 
                              icmp->un.echo.id + icmp->un.echo.sequence);
            
            struct sockaddr_in dest;
            memset(&dest, 0, sizeof(dest));
            dest.sin_family = AF_INET;
            dest.sin_addr.s_addr = ip->daddr;
            
            ssize_t sent = sendto(sock2, packet, sizeof(packet), 0,
                                 (struct sockaddr*)&dest, sizeof(dest));
            if (sent > 0) {
                printf("✓ SUCCESS: Sent %zd bytes with IPPROTO_RAW\n", sent);
                close(sock2);
                return 1;
            } else {
                printf("✗ FAILED with IPPROTO_RAW: ");
                perror("sendto");
            }
        } else {
            printf("✗ Cannot set IP_HDRINCL: ");
            perror("setsockopt");
        }
        close(sock2);
    } else {
        printf("✗ Cannot create IPPROTO_RAW socket: ");
        perror("socket");
    }
    
    return 0;
}

#endif //_PINGER_H