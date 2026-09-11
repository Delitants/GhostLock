#include "kara_reclaim_engine.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

int kara_reclaim_find_payload_mutation(const struct kara_reclaim_hold *hold,
                                       unsigned *pair_index,
                                       unsigned *byte_offset)
{
    if (pair_index)
        *pair_index = UINT_MAX;
    if (byte_offset)
        *byte_offset = UINT_MAX;
    if (!hold || !hold->socket_pairs || !hold->payload ||
        !hold->sent_count || hold->sent_count > hold->socket_count) {
        errno = EINVAL;
        return -1;
    }

    uint8_t *observed = malloc(KARA_MM_SLAB_SIZE);
    if (!observed)
        return -1;

    for (unsigned pair = 0; pair < hold->sent_count; ++pair) {
        ssize_t got = recv(hold->socket_pairs[pair][1], observed,
                           KARA_MM_SLAB_SIZE, MSG_PEEK | MSG_DONTWAIT);
        if (got != KARA_MM_SLAB_SIZE) {
            free(observed);
            if (got >= 0)
                errno = EIO;
            return -1;
        }
        if (!memcmp(observed, hold->payload, KARA_MM_SLAB_SIZE))
            continue;

        unsigned offset = 0;
        while (offset < KARA_MM_SLAB_SIZE &&
               observed[offset] == hold->payload[offset])
            ++offset;
        if (pair_index)
            *pair_index = pair;
        if (byte_offset)
            *byte_offset = offset;
        free(observed);
        return 1;
    }

    free(observed);
    return 0;
}
