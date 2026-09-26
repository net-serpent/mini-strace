/*
 * Property tests for the pure format_* decoders in decoders.c.
 *
 * These are exactly the functions with no ptrace dependency — they
 * take a raw value and an output buffer and don't touch the traced
 * process's memory at all, which makes them the part of this
 * codebase that's actually testable in isolation without a real
 * ptrace session. (format_sockaddr/format_wait_status/read_child_*
 * all dereference the tracee's memory via ptrace and aren't covered
 * here — see README.md's Testing section.)
 *
 * The property being checked, for every (decoder, value, out_size)
 * combination: never write past out_size bytes (caught by building
 * this with -fsanitize=address — each output buffer is allocated at
 * *exactly* out_size bytes so any overflow trips ASan immediately),
 * and always leave the result NUL-terminated somewhere within
 * [0, out_size) whenever out_size > 0. A single snprintf() call is
 * safe by construction (the C library guarantees both properties by
 * itself), so the interesting targets here are the handful of
 * decoders that build their output by hand across several
 * snprintf() calls with manual `oi`/`out_size` bookkeeping
 * (format_open_flags, format_prot_flags, format_map_flags,
 * format_socket_type, format_access_mode) — exactly the kind of code
 * an off-by-one survives in for a while unnoticed.
 *
 * Deliberately not a coverage-guided fuzzer (no libFuzzer/AFL
 * harness) — just wide, deterministic property sweeps: every
 * decoder against a set of hand-picked edge values (0, all bits set,
 * sign-extended 32-bit patterns, alternating bits, ...) plus a large
 * deterministic pseudo-random stream, each against a spread of
 * output buffer sizes from 0 up to the real STR_ARG_BUF_LEN. Fast
 * enough to run on every `make test` / CI invocation without needing
 * a separate fuzzing corpus or clang toolchain.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>

#include "../src/decoders.h"

typedef void (*decoder_fn)(unsigned long long value, char *out, size_t out_size);

/* format_hex_or_fd_arg takes a pid + an is_fd_arg flag that
 * format_open_flags and friends don't, so it's wrapped to fit the
 * same shape as everything else here. Always exercised with
 * is_fd_arg = 0: that path is pure formatting (the whole point of
 * this harness); is_fd_arg = 1 makes a real readlink() syscall,
 * which is filesystem I/O, not decoder logic, and out of scope. */
static void wrap_hex_or_fd_arg(unsigned long long value, char *out, size_t out_size) {
    format_hex_or_fd_arg(0, value, 0, out, out_size);
}

/* format_sockopt_optname takes a level alongside optname, which
 * format_open_flags and friends don't need, so it's wrapped with
 * level fixed to SOL_SOCKET (sweeping value as optname) to fit the
 * same shape as everything else here. The buffer-safety logic this
 * harness actually checks doesn't depend on which level's table (or
 * neither, falling back to hex) ends up matching, so one fixed
 * level is enough to exercise both code paths. */
static void wrap_sockopt_optname(unsigned long long value, char *out, size_t out_size) {
    format_sockopt_optname(SOL_SOCKET, value, out, out_size);
}

static uint64_t rng_state = 0x9E3779B97F4A7C15ULL;

/* splitmix64 — small, dependency-free, and deterministic (same seed
 * every run), which matters here: a failure needs to be
 * reproducible without saving a corpus file anywhere. */
static uint64_t next_rand(void) {
    uint64_t z = (rng_state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static const unsigned long long fixed_values[] = {
    0ULL, 1ULL, 2ULL, 3ULL, 7ULL, 8ULL, 15ULL, 16ULL,
    0x7fULL, 0x80ULL, 0xffULL, 0x100ULL,
    0x7fffffffULL, 0x80000000ULL, 0xffffffffULL,
    0xffffffff80000000ULL,  /* sign-extended 32-bit negative pattern */
    0x8000000000000000ULL,
    0xfffffffffffffffeULL,
    0xffffffffffffffffULL,  /* UINT64_MAX */
    0x5555555555555555ULL, 0xaaaaaaaaaaaaaaaaULL,  /* alternating bits */
};
#define NUM_FIXED (sizeof(fixed_values) / sizeof(fixed_values[0]))

static const size_t out_sizes[] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 512, 1024,
};
#define NUM_SIZES (sizeof(out_sizes) / sizeof(out_sizes[0]))

/* smaller spread for the random sweep, since it's crossed against
 * many more values — still covers the sizes most likely to catch an
 * off-by-one (the tiny end) plus the real STR_ARG_BUF_LEN. */
static const size_t random_out_sizes[] = { 0, 1, 2, 3, 4, 5, 8, 16, 64, 1024 };
#define NUM_RANDOM_SIZES (sizeof(random_out_sizes) / sizeof(random_out_sizes[0]))

#define NUM_RANDOM_VALUES 2000

static long total_checks = 0;
static long nul_term_failures = 0;

static void check_one(const char *decoder_name, decoder_fn fn,
                       unsigned long long value, size_t out_size) {
    total_checks++;

    /* Allocated at *exactly* out_size — including 0 — so ASan's
     * redzone catches a write even one byte past what the decoder
     * was told it had to work with. */
    char *buf = malloc(out_size);
    if (out_size > 0 && buf == NULL) {
        fprintf(stderr, "malloc(%zu) failed, skipping this combination\n", out_size);
        return;
    }

    fn(value, buf, out_size);

    if (out_size > 0) {
        int found_nul = 0;
        for (size_t i = 0; i < out_size; i++) {
            if (buf[i] == '\0') { found_nul = 1; break; }
        }
        if (!found_nul) {
            nul_term_failures++;
            fprintf(stderr,
                    "NOT NUL-TERMINATED: %s(value=0x%llx, out_size=%zu)\n",
                    decoder_name, value, out_size);
        }
    }

    free(buf);
}

int main(void) {
    /* Built here (not as a file-scope initializer) so every wrapper
     * and format_* symbol is already declared and there's no need
     * for a forward-declaration for each one just to populate a
     * static table. */
    struct { const char *name; decoder_fn fn; } decoders[] = {
        { "format_open_flags",               format_open_flags },
        { "format_prot_flags",               format_prot_flags },
        { "format_map_flags",                format_map_flags },
        { "format_mount_flags",              format_mount_flags },
        { "format_epoll_op",                 format_epoll_op },
        { "format_statx_mask",               format_statx_mask },
        { "format_sockopt_level",             format_sockopt_level },
        { "format_sockopt_optname(level=SOL_SOCKET)", wrap_sockopt_optname },
        { "format_socket_domain",            format_socket_domain },
        { "format_socket_type",              format_socket_type },
        { "format_signal_arg",               format_signal_arg },
        { "format_lseek_whence",             format_lseek_whence },
        { "format_fcntl_cmd",                format_fcntl_cmd },
        { "format_sigprocmask_how",          format_sigprocmask_how },
        { "format_access_mode",              format_access_mode },
        { "format_clockid",                  format_clockid },
        { "format_clone_flags",              format_clone_flags },
        { "format_ioctl_request",            format_ioctl_request },
        { "format_hex_or_fd_arg(is_fd_arg=0)", wrap_hex_or_fd_arg },
    };
    size_t num_decoders = sizeof(decoders) / sizeof(decoders[0]);

    for (size_t d = 0; d < num_decoders; d++) {
        for (size_t v = 0; v < NUM_FIXED; v++) {
            for (size_t s = 0; s < NUM_SIZES; s++) {
                check_one(decoders[d].name, decoders[d].fn, fixed_values[v], out_sizes[s]);
            }
        }
        for (int r = 0; r < NUM_RANDOM_VALUES; r++) {
            unsigned long long value = (unsigned long long)next_rand();
            for (size_t s = 0; s < NUM_RANDOM_SIZES; s++) {
                check_one(decoders[d].name, decoders[d].fn, value, random_out_sizes[s]);
            }
        }
    }

    fprintf(stderr, "%ld checks, %ld NUL-termination failures\n",
            total_checks, nul_term_failures);

    return nul_term_failures > 0 ? 1 : 0;
}
