#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "kara_reclaim_engine.h"

__attribute__((weak)) int kara_reclaim_find_payload_mutation(
    const struct kara_reclaim_hold *hold,
    unsigned *pair_index,
    unsigned *byte_offset)
{
    (void)hold;
    (void)pair_index;
    (void)byte_offset;
    return -2;
}

static void fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

static void send_full(int fd, const uint8_t *buffer, size_t length)
{
    size_t sent = 0;
    while (sent < length) {
        ssize_t result = send(fd, buffer + sent, length - sent, 0);
        if (result <= 0)
            fail("socket send did not complete");
        sent += (size_t)result;
    }
}

static void recv_full(int fd, uint8_t *buffer, size_t length)
{
    size_t received = 0;
    while (received < length) {
        ssize_t result = recv(fd, buffer + received, length - received, 0);
        if (result <= 0)
            fail("socket receive did not complete");
        received += (size_t)result;
    }
}

int main(void)
{
    struct kara_reclaim_hold hold = {0};
    uint8_t expected[KARA_MM_SLAB_SIZE];
    uint8_t observed[KARA_MM_SLAB_SIZE];
    uint8_t changed[KARA_MM_SLAB_SIZE];
    int pair[2];

    for (unsigned i = 0; i < KARA_MM_SLAB_SIZE; ++i)
        expected[i] = (uint8_t)(i * 37u + 11u);
    memcpy(changed, expected, sizeof(changed));
    changed[KARA_FAKE_LOCK_OFF + 4u] ^= 0x80u;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0)
        fail("socketpair failed");

    hold.socket_pairs = calloc(1, sizeof(*hold.socket_pairs));
    if (!hold.socket_pairs)
        fail("socket pair table allocation failed");
    hold.socket_pairs[0][0] = pair[0];
    hold.socket_pairs[0][1] = pair[1];
    hold.socket_count = 1;
    hold.sent_count = 1;
    hold.payload = expected;

    send_full(pair[0], expected, sizeof(expected));
    unsigned pair_index = UINT_MAX;
    unsigned byte_offset = UINT_MAX;
    int result = kara_reclaim_find_payload_mutation(
        &hold, &pair_index, &byte_offset);
    if (result != 0 || pair_index != UINT_MAX || byte_offset != UINT_MAX)
        fail("unchanged queued payload reported as mutated");

    recv_full(pair[1], observed, sizeof(observed));
    send_full(pair[0], changed, sizeof(changed));
    result = kara_reclaim_find_payload_mutation(
        &hold, &pair_index, &byte_offset);
    if (result != 1)
        fail("changed queued payload reported as clean");
    if (pair_index != 0)
        fail("wrong mutated socket pair reported");
    if (byte_offset != KARA_FAKE_LOCK_OFF + 4u)
        fail("wrong first mutated byte reported");

    close(pair[0]);
    close(pair[1]);
    free(hold.socket_pairs);
    puts("kara_reclaim_readback_test: PASS");
    return 0;
}
