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
    res = run_ping(&argc, &argv[0]);

    return 0;
}