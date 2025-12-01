# pinger
A pure C application for sending ICMP requests based on raw socket

# Description
One header file library. This library coping functionality of network ping util.

# Building

```bash
    make pinger # to build project
    make install-cap # to set file capabilities
```

# Dependencies

List of dependencies:
- math

Linker flags:

```make
   gcc ... -lm
```

# Library Usage

To use library add preprocessor macro
```c
#define PINGER_IMPLEMENTATION
#include "pinger.h"
```

Main functions is run_ping(), with constrains. Skip program path argument is necessary
```c
int main(int argc, char* argv[]){
    argc--;
    run_ping(&argc, &argv[1]);
}
```
Or you can use library macro to extract first argument:
```c
int main(int argc, char* argv[]){
    char* prog_path = SHIFT_ARG(&argc, argv);
    run_ping(&argc, &argv[0]);
}
```

# Constrains

- For main library function run_ping it is necessary to shift executable args list

# Testing

## Unit testing

To build all tests from make
```bash
    make tests
```

To run all test from make
```bash

```

### Args parsing

Building
```bash
    make test_args
```
Running
```bash
    ./build/unit_tests/test_args
```
Test analyzes available arguments and checks their correctness

# WARNINGS

# ERRATA
- Sending icmp echo request to localhost leads to receive sended request and brokes parsing

# TODO
- [ ] Separate sending and receiving components
- [ ] Add more options
