ARM_CC ?= arm-linux-gnueabihf-gcc
HOST_CC ?= cc
CFLAGS ?= -std=gnu11 -O2 -Wall -Wextra -Werror
ARM_CFLAGS ?= $(CFLAGS) -static -pthread -DKARA_RECLAIM_LIBRARY_ONLY

SRC := src/kara_ghostlock_v2.c \
	src/kara_ghostlock_logic.c \
	src/kara_reclaim_stage.c \
	src/kara_reclaim_layout.c \
	src/kara_reclaim_readback.c
OUT := out/kara-ghostlock-PS7713-5443.arm

.PHONY: all clean host-tests

all: $(OUT)

$(OUT): $(SRC) src/kara_ghostlock.c src/kara_ghostlock.h \
		src/kara_reclaim_engine.h src/kara_reclaim_hash.h \
		src/kara_reclaim_layout.h
	mkdir -p out
	$(ARM_CC) $(ARM_CFLAGS) -o $@ $(SRC)

host-tests:
	CC=$(HOST_CC) ./tests/run-host-tests.sh

clean:
	rm -rf out
