#include <stdio.h>
#include "pinger.h"

    
int main(int argc, char* argv[]){
    printf("Hello from pinger\n");
    char* prog_path = SHIFT_ARG(&argc, argv);
    (void)prog_path;
    
    run_ping(&argc, argv);

    return 0;
}