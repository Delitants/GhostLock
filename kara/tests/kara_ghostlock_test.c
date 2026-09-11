#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kara_ghostlock.h"
#include "kara_reclaim_engine.h"

static void test_stamp_maps_waiter_and_ldisc_fields(void) {
    struct kara_select_stamp stamp;
    kara_build_select_stamp(&stamp, &KARA_PS7713_PROFILE);

    assert(stamp.in[0] == 0);
    assert(stamp.in[1] == 0xc120d700u);
    assert(stamp.in[2] == 0xc14aba40u);
    assert(stamp.in[3] == 0);
    assert(stamp.in[4] == 0xc05e950cu);
    for (size_t i = 5; i < KARA_SELECT_WORDS; ++i)
        assert(stamp.in[i] == 0);
    for (size_t i = 0; i < KARA_SELECT_WORDS; ++i) {
        assert(stamp.out[i] == 0);
        assert(stamp.ex[i] == 0);
    }
    assert(KARA_PS7713_PROFILE.prepare_kernel_cred == 0xc01524d0u);
}

static void test_fd_plan_matches_hand_derived_bits(void) {
    static const int expected[] = {
        40, 41, 42, 44, 46, 47, 53, 56, 62, 63,
        70, 73, 75, 76, 77, 79, 81, 83, 86, 88, 94, 95,
        130, 131, 136, 138, 140, 143, 145, 146, 147, 148, 150, 158, 159,
    };
    struct kara_select_stamp stamp;
    int actual[64] = {0};
    kara_build_select_stamp(&stamp, &KARA_PS7713_PROFILE);
    size_t count = kara_collect_read_fds(&stamp, actual, 64);

    assert(count == sizeof(expected) / sizeof(expected[0]));
    assert(memcmp(actual, expected, sizeof(expected)) == 0);
}

static void test_preflight_requires_every_gate(void) {
    struct kara_preflight observed = {
        .arm32 = 1,
        .four_cpus = 1,
        .kernel_exact = 1,
        .device_kara = 1,
        .model_aftka = 1,
        .build_exact = 1,
        .uid_shell = 1,
        .selinux_enforcing = 1,
        .cec_standby_blocked = 1,
    };
    assert(kara_preflight_missing(&observed) == 0);

    const uint32_t gates[] = {
        KARA_GATE_ARM32, KARA_GATE_FOUR_CPUS, KARA_GATE_KERNEL,
        KARA_GATE_DEVICE, KARA_GATE_MODEL, KARA_GATE_BUILD,
        KARA_GATE_UID, KARA_GATE_SELINUX, KARA_GATE_CEC_GUARD,
    };
    int *fields[] = {
        &observed.arm32, &observed.four_cpus, &observed.kernel_exact,
        &observed.device_kara, &observed.model_aftka, &observed.build_exact,
        &observed.uid_shell, &observed.selinux_enforcing,
        &observed.cec_standby_blocked,
    };
    for (size_t i = 0; i < sizeof(gates) / sizeof(gates[0]); ++i) {
        *fields[i] = 0;
        assert(kara_preflight_missing(&observed) == gates[i]);
        *fields[i] = 1;
    }
}

static void test_live_confirmation_and_command_limits(void) {
    assert(kara_live_confirmation_valid("RUN-KARA-PS7713-GHOSTLOCK"));
    assert(!kara_live_confirmation_valid("RUN-KARA-PS7713"));
    assert(kara_command_length_valid(1));
    assert(kara_command_length_valid(65536));
    assert(!kara_command_length_valid(0));
    assert(!kara_command_length_valid(65537));
}

static void test_live_state_machine_rejects_skips_and_rewinds(void) {
    enum kara_phase phase = KARA_PHASE_NEW;
    assert(!kara_phase_step(&phase, KARA_PHASE_FDS_READY));
    assert(phase == KARA_PHASE_NEW);

    for (int next = KARA_PHASE_PREFLIGHT_OK;
         next <= KARA_PHASE_DAEMON_READY; ++next) {
        assert(kara_phase_step(&phase, (enum kara_phase)next));
        assert(phase == (enum kara_phase)next);
    }

    assert(!kara_phase_step(&phase, KARA_PHASE_ROOT));
    assert(phase == KARA_PHASE_DAEMON_READY);
}

static void test_tcp_copy_requires_exact_post_copy_error(void) {
    assert(kara_tcp_mcast_copy_confirmed(-1, EADDRNOTAVAIL));
    assert(!kara_tcp_mcast_copy_confirmed(0, 0));
    assert(!kara_tcp_mcast_copy_confirmed(-1, EACCES));
    assert(!kara_tcp_mcast_copy_confirmed(-1, ENOPROTOOPT));
}

static void test_reclaim_confidence_rejects_weak_solutions(void) {
    assert(!kara_reclaim_score_confident(16, 24));
    assert(!kara_reclaim_score_confident(17, 24));
    assert(kara_reclaim_score_confident(18, 24));
    assert(kara_reclaim_score_confident(24, 24));
    assert(!kara_reclaim_score_confident(15, 24));
    assert(!kara_reclaim_score_confident(16, 23));
    assert(!kara_reclaim_score_confident(25, 24));
}

static void test_ioctl_kernel_pointer_result_validation(void) {
    uint32_t pointer = 0;
    assert(kara_kernel_pointer_result((int)0xc1468ec0u, &pointer));
    assert(pointer == 0xc1468ec0u);
    assert(!kara_kernel_pointer_result(-1, &pointer));
    assert(!kara_kernel_pointer_result(0, &pointer));
    assert(!kara_kernel_pointer_result((int)0xbffffffcu, &pointer));
    assert(!kara_kernel_pointer_result((int)0xf0000000u, &pointer));
    assert(!kara_kernel_pointer_result((int)0xc1468ec1u, &pointer));
}

static void test_consumer_changes_policy_without_changing_priority(void) {
    struct kara_sched_attr attr;

    memset(&attr, 0xa5, sizeof(attr));
    kara_build_nonpreempting_sched_attr(&attr, 0);
    assert(attr.size == sizeof(attr));
    assert(attr.sched_policy == KARA_SCHED_BATCH);
    assert(attr.sched_nice == 0);
    assert(attr.sched_flags == 0);
    assert(attr.sched_priority == 0);
    assert(attr.sched_runtime == 0);
    assert(attr.sched_deadline == 0);
    assert(attr.sched_period == 0);

    kara_build_nonpreempting_sched_attr(&attr, 7);
    assert(attr.sched_policy == KARA_SCHED_BATCH);
    assert(attr.sched_nice == 7);
}

int main(void) {
    test_stamp_maps_waiter_and_ldisc_fields();
    test_fd_plan_matches_hand_derived_bits();
    test_preflight_requires_every_gate();
    test_live_confirmation_and_command_limits();
    test_live_state_machine_rejects_skips_and_rewinds();
    test_tcp_copy_requires_exact_post_copy_error();
    test_reclaim_confidence_rejects_weak_solutions();
    test_ioctl_kernel_pointer_result_validation();
    test_consumer_changes_policy_without_changing_priority();
    puts("kara_ghostlock tests: PASS");
    return 0;
}
