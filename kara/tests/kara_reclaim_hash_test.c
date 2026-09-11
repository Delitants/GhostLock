#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "kara_reclaim_hash.h"

static void expect_u32(const char *name, uint32_t got, uint32_t want)
{
    if (got != want) {
        fprintf(stderr, "FAIL %s: got=%08x want=%08x\n", name, got, want);
        exit(1);
    }
}

static void test_kernel_vectors(void)
{
    expect_u32("vector-1", kara_futex_hash(0x12345000u, 0x001001c0u,
                                             0x3ffu), 0x00000051u);
    expect_u32("vector-2", kara_futex_hash(0x7e008088u, 0xdeadc1c0u,
                                             0x3ffu), 0x00000384u);
    expect_u32("vector-3", kara_futex_hash(0xb6f01004u, 0xc47a91c0u,
                                             0x3ffu), 0x00000384u);
}

static void test_solver(void)
{
    const uint32_t known_mm = 0xc00101c0u;
    const uintptr_t target = 0x71234080u;
    uintptr_t hits[KARA_MAX_HITS];
    unsigned count = 0;
    const uint32_t wanted = kara_futex_hash(target, known_mm, 0x3ffu);

    hits[count++] = target;
    for (uintptr_t p = 0x72000000u;
         p < 0x78000000u && count < KARA_MAX_HITS; p += 0x1008u) {
        if (kara_futex_hash(p, known_mm, 0x3ffu) == wanted)
            hits[count++] = p;
    }
    if (count != KARA_MAX_HITS) {
        fprintf(stderr, "FAIL solver fixture: only %u hits\n", count);
        exit(1);
    }

    uint32_t got = kara_solve_mm_range(hits, count,
                                       known_mm - 0x400u,
                                       known_mm + 0x404u,
                                       4u, 0x3ffu);
    expect_u32("solver", got, known_mm);
}

static void test_grid_solver_with_noise(void)
{
    const uint32_t known_mm = 0xc00101c0u;
    const uintptr_t target = 0x71234080u;
    uintptr_t candidates[KARA_MAX_HITS];
    unsigned count = 0;
    const uint32_t wanted = kara_futex_hash(target, known_mm, 0x3ffu);

    for (uintptr_t p = 0x72000000u;
         p < 0x78000000u && count < KARA_MAX_HITS - 1u; p += 0x1008u) {
        if (kara_futex_hash(p, known_mm, 0x3ffu) == wanted)
            candidates[count++] = p;
    }
    candidates[count++] = 0x79001004u; /* Deliberate timing false positive. */

    uint32_t got = kara_solve_mm_grid(target, candidates, count,
                                      0xc0000000u, 0xc0020000u,
                                      0x2000u, 0x1c0u, 18u,
                                      6u, 0x3ffu);
    expect_u32("grid-solver", got, known_mm);
}

static void test_best_score_requires_unique_global_maximum(void)
{
    struct kara_best_score best = {0};

    kara_best_score_consider(&best, 0xc00101c0u, 8u);
    expect_u32("first-best", kara_best_score_unique(&best, 8u),
               0xc00101c0u);

    kara_best_score_consider(&best, 0xc00201c0u, 12u);
    kara_best_score_consider(&best, 0xc00301c0u, 11u);
    expect_u32("global-best", kara_best_score_unique(&best, 8u),
               0xc00201c0u);

    kara_best_score_consider(&best, 0xc00401c0u, 12u);
    expect_u32("tied-best", kara_best_score_unique(&best, 8u), 0u);

    kara_best_score_consider(&best, 0xc00501c0u, 13u);
    expect_u32("new-unique-best", kara_best_score_unique(&best, 13u),
               0xc00501c0u);
    expect_u32("below-floor", kara_best_score_unique(&best, 14u), 0u);
}

int main(void)
{
    test_kernel_vectors();
    test_solver();
    test_grid_solver_with_noise();
    test_best_score_requires_unique_global_maximum();
    puts("kara_reclaim_hash_test: PASS");
    return 0;
}
