APP := pinger
BUILD_DIR := build
FLAGS := -g -O0 -Wall -Wextra -Wpedantic

.PHONY: all
all: ${APP}

${APP}: build_dir main.c
	cc ${FLAGS} main.c -o ${BUILD_DIR}/${APP}

.PHONY: build_dir
build_dir:
	mkdir -p ${BUILD_DIR}

.PHONY: rebuild
rebuild: clean ${APP}

.PHONY: clean
clean:
	rm -rf ${BUILD_DIR}
