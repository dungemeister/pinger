#include "../pinger.h"

#define TEST_DEBUG(msg, ...)    printf("%s "msg, __func__, ##__VA_ARGS__)
#define TEST_ERROR(msg, ...)    fprintf(stderr, "%s"msg, __func__, ##__VA_ARGS__)

static int test_network_connectivity() {
    TEST_DEBUG("=== Network Connectivity Check ===\n");
    
    // Пробуем обычный UDP сокет
    int test_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (test_sock < 0) {
        TEST_ERROR("Cannot create test socket");
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
    if(result < 0) TEST_ERROR("Send to");
    assert(result >= 0);

    TEST_DEBUG(" PASS\n");
    close(test_sock);
    return result;
}

static void test_system_raw_socket_support() {
    TEST_DEBUG("=== Raw Socket Support Check ===\n");
    
    // Проверяем несколько способов создания raw socket
    int protocols[] = {IPPROTO_ICMP, IPPROTO_RAW, IPPROTO_TCP, 0};
    const char *protocol_names[] = {"ICMP", "RAW", "TCP", NULL};
    
    for (int i = 0; protocols[i] != 0; i++) {
        int sock = socket(AF_INET, SOCK_RAW, protocols[i]);
        if (sock >= 0) {
            TEST_DEBUG("RAW socket with protocol %s: SUCCESS (fd=%d)\n", 
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
            printf("RAW socket with protocol %s: FAILED - ", protocol_names[i]);
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
            printf("FAILED: ");
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
        printf("IPPROTO_RAW socket created\n");
        
        // Включаем IP_HDRINCL для ручного создания IP заголовка
        int one = 1;
        if (setsockopt(sock2, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) == 0) {
            printf("IP_HDRINCL set successfully\n");
            
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
                printf("SUCCESS: Sent %zd bytes with IPPROTO_RAW\n", sent);
                close(sock2);
                return 1;
            } else {
                printf("FAILED with IPPROTO_RAW: ");
                perror("sendto");
            }
        } else {
            printf("Cannot set IP_HDRINCL: ");
            perror("setsockopt");
        }
        close(sock2);
    } else {
        printf("Cannot create IPPROTO_RAW socket: ");
        perror("socket");
    }
    
    return 0;
}

int main(int argc, char* argv[]){
    test_network_connectivity();
    return 0;
}