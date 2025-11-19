#include <stdio.h>
#include "pinger.h"

    
int main(int argc, char* argv[]){
    printf("Hello from pinger\n");
    char* arg = SHIFT_ARG(&argc, argv);

    run_ping(&argc, argv);

    return 0;
}