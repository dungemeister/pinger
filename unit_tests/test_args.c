#define PINGER_IMPLEMENTATION
#include "../pinger.h"
#include <assert.h>
#include <string.h>

#define DEBUG_TEST(msg, ...) printf("[%s]"msg,__func__, ##__VA_ARGS__)

void test_count(){
    DEBUG_TEST("\n");
    pinger_t pinger;
    init_pinger(&pinger);

    int argc = 3;
    size_t count = 2; 
    char* argv[] = {"google.com", PINGER_ARG_COUNT_CHAR, ""};
    argv[2] = malloc(256);
    sprintf(argv[2], "%lu", count);

    parse_args(&pinger, &argc, argv);
    assert(pinger.opts.count == count);
    
    free(argv[2]);
    DEBUG_TEST("PASS\n");
}

void test_interval(){
    DEBUG_TEST("\n");
    pinger_t pinger;
    init_pinger(&pinger);

    int argc = 3;
    float interval = 2.;
    char* argv[] = {"google.com", PINGER_ARG_INTERVAL_CHAR, ""};
    argv[2] = malloc(256);
    sprintf(argv[2], "%.2f", interval);
    
    parse_args(&pinger, &argc, argv);
    assert(pinger.opts.interval == interval);
    
    free(argv[2]);
    DEBUG_TEST("PASS\n");
}

void test_timeout(){
    DEBUG_TEST("\n");
    pinger_t pinger;
    init_pinger(&pinger);

    int argc = 3;
    size_t timeout = 2;
    char* argv[] = {"google.com", PINGER_ARG_TIMEOUT_CHAR, ""};
    argv[2] = malloc(256);
    sprintf(argv[2], "%lu", timeout);
    
    parse_args(&pinger, &argc, argv);
    assert(pinger.opts.timeout == timeout);
    
    free(argv[2]);
    DEBUG_TEST("PASS\n");
}

void test_tos_dec(){
    DEBUG_TEST("\n");
    pinger_t pinger;
    init_pinger(&pinger);

    int argc = 3;
    size_t tos = 69; 
    char* argv[] = {"google.com", PINGER_ARG_TOS_CHAR, ""};
    argv[2] = malloc(256);
    sprintf(argv[2], "%d", tos);

    parse_args(&pinger, &argc, argv);
    DEBUG_TEST("%x\n", tos);
    assert(pinger.opts.cos == tos);
    
    free(argv[2]);
    DEBUG_TEST("PASS\n");
}

void test_tos_hex(){
    DEBUG_TEST("\n");
    pinger_t pinger;
    init_pinger(&pinger);

    int argc = 3;
    size_t tos = 0xEC; 
    char* argv[] = {"google.com", PINGER_ARG_TOS_CHAR, ""};
    argv[2] = malloc(256);
    sprintf(argv[2], "0x%x", tos);

    parse_args(&pinger, &argc, argv);
    DEBUG_TEST("0x%x\n", tos);
    assert(pinger.opts.cos == tos);
    
    free(argv[2]);
    DEBUG_TEST("PASS\n");
}

void test_ttl(){
    DEBUG_TEST("\n");
    pinger_t pinger;
    init_pinger(&pinger);

    int argc = 3;
    size_t ttl = 69; 
    char* argv[] = {"google.com", PINGER_ARG_TTL_CHAR, ""};
    argv[2] = malloc(256);
    sprintf(argv[2], "%lu", ttl);

    parse_args(&pinger, &argc, argv);
    assert(pinger.opts.ttl == ttl);
    
    free(argv[2]);
    DEBUG_TEST("PASS\n");
}

int main(){
    test_count();
    test_interval();
    test_timeout();
    test_tos_dec();
    test_tos_hex();
    test_ttl();
    return 0;
}