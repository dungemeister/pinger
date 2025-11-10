#include <stdio.h>
#include "pinger.h"

    
int main(int argc, char* argv[]){
    printf("Hello from pinger\n");
    char* arg = SHIFT_ARG(&argc, argv);
    // check_network_connectivity();
    // check_system_raw_socket_support();
    // check_kernel_restrictions();
    // test_icmp_echo_with_different_methods();
    run_ping(&argc, argv);

    return 0;
}