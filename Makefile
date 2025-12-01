APP := pinger
BUILD_DIR := build
COMPILER_FLAGS := -g -O2 -Wall -Wextra -Wpedantic 
LINKER_FLAGS := -lm

DEBUG_FLAGS := ${COMPILER_FLAGS} -DDEBUG
TESTS_BUILD_DIR := ${BUILD_DIR}/unit_tests
TESTS_DIR := unit_tests

ARGS_TEST_FLAGS := ${COMPILER_FLAGS} -DDEBUG
ARGS_TEST_BUILD_DIR := ${BUILD_DIR}/unit_tests
ARGS_TEST_DIR := ${TESTS_DIR}

TEST_FLAGS := -g -O2

.PHONY: all 
all: ${APP} install-cap-${APP}

.PHONY: tests
tests: mkdir_tests args_test install-cap-test-args_test



${APP}: build_dir main.c
	cc main.c -o ${BUILD_DIR}/${APP} ${LINKER_FLAGS} ${DEBUG_FLAGS}

.PHONY: build_dir
build_dir:
	mkdir -p ${BUILD_DIR}

.PHONY: rebuild
rebuild: clean ${APP}

.PHONY: clean
clean:
	rm -rf ${BUILD_DIR}

mkdir_tests:
	mkdir -p ${TESTS_BUILD_DIR}

build_tests:
	cc ${TEST_FLAGS} -o ${TESTS_BUILD_DIR}/tests ${TESTS_DIR}/tests.c

args_test: build_args_test 
	
build_args_test: ${ARGS_TEST_DIR}/args_test.c
	cc ${ARGS_TEST_FLAGS} -o ${ARGS_TEST_BUILD_DIR}/args_test ${ARGS_TEST_DIR}/args_test.c ${LINKER_FLAGS} 

.PHONY: install-cap-%
install-cap-%:
	sudo setcap cap_net_raw+ep ${BUILD_DIR}/$*

install-cap-test-%:
	sudo setcap cap_net_raw+ep ${TESTS_BUILD_DIR}/$*

.PHONY: install-group
install-group:
	sudo chgrp netsocket ${BUILD_DIR}/${APP}
	sudo chmod 0750 ${BUILD_DIR}/${APP}