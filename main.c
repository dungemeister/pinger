#include <stdio.h>
#define PINGER_IMPLEMENTATION
#include "pinger.h"
    
int main(int argc, char* argv[]){
    printf("Hello from pinger\n");
    int res = 0;
    char* prog_path = SHIFT_ARG(&argc, argv);
    // (void)prog_path;
    if(argc <= 0){
        fprintf(stderr, "ERROR: Wrong program usage\n");
        help();
        return -1;
    }
    pinger_t pinger;
    init_pinger(&pinger);
    res = run_ping(&pinger, &argc, &argv[0]);

    return 0;
}