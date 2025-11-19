APP := pinger
BUILD_DIR := build
COMPILER_FLAGS := -g -O2 -Wall -Wextra -Wpedantic 
LINKER_FLAGS := -lm

TESTS_BUILD_DIR := ${BUILD_DIR}/unit_tests
TESTS_DIR := unit_tests

TEST_FLAGS := -g -O2

.PHONY: all 
all: ${APP} install-cap

${APP}: build_dir main.c
	cc main.c -o ${BUILD_DIR}/${APP} ${COMPILER_FLAGS} ${LINKER_FLAGS}

.PHONY: build_dir
build_dir:
	mkdir -p ${BUILD_DIR}

.PHONY: rebuild
rebuild: clean ${APP}

.PHONY: clean
clean:
	rm -rf ${BUILD_DIR}

.PHONY: tests
tests: mkdir_tests build_tests

mkdir_tests:
	mkdir -p ${TESTS_BUILD_DIR}

build_tests:
	cc ${TEST_FLAGS} -o ${TESTS_BUILD_DIR}/tests ${TESTS_DIR}/tests.c

.PHONY: install-cap
install-cap:
	sudo setcap cap_net_raw+ep ${BUILD_DIR}/${APP}

.PHONY: install-group
install-group:
	sudo chgrp netsocket ${BUILD_DIR}/${APP}
	sudo chmod 0750 ${BUILD_DIR}/${APP}