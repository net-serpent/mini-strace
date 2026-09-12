/*
 * mini-strace v1.0.0 — see CHANGELOG.md for what's changed release
 * to release.
 *
 * Minimal syscall tracer using ptrace(2). Runs a child process,
 * stops it on every syscall entry/exit, prints the syscall name,
 * its arguments, and the return value — with errno resolved to its
 * macro name on failure. Pointer arguments that are known to be
 * C-string paths (open, stat, execve, ...) get dereferenced and
 * printed as quoted strings instead of raw addresses. write()'s
 * output buffer and read()'s input buffer both get dumped the same
 * way, minus the NUL-termination assumption (the data isn't
 * necessarily text) — read()'s dump is deferred to the exit-stop
 * since its buffer is only actually filled after the syscall runs.
 * Optional -e trace=SET filters which syscalls get printed at all
 * (SET is a comma-separated mix of category names — file, network,
 * process — and/or exact syscall names). Optional -f follows
 * fork()/vfork()/clone() into child processes instead of only ever
 * tracing the one process that was launched; output lines get a
 * "[pid N] " prefix so it's clear which process each line belongs
 * to. Signals delivered to a traced process (crashes, external
 * kills, ...) get their own "--- SIGNAME (description) ---" line
 * before being forwarded on, same as real strace. Optional -T times
 * each syscall (wall clock, entry-stop to exit-stop) and appends it
 * as "<seconds.microseconds>" after the return value. Optional -c
 * replaces all of that per-call output with a single summary table
 * at the end — calls/errors/total time grouped by syscall name,
 * sorted slowest-first — reusing the same entry/exit timestamps -T
 * uses. Optional -o FILE sends the trace (and the "[mini-strace] ..."
 * status lines) to a file instead of stdout/stderr, without touching
 * the traced program's own stdin/stdout/stderr. Optional -s SIZE
 * caps how many raw bytes of a string/buffer argument get read and
 * shown before truncating with "..." (default 200). Optional -y
 * resolves file descriptor arguments to whatever they point to via
 * /proc/pid/fd/N, e.g. "read(3</etc/passwd>, ...)" instead of just
 * "read(3, ...)".
 *
 * Supports x86-64 and ARM64 (aarch64) Linux. The two architectures
 * have completely different syscall ABIs — different register
 * names, different way to fetch registers via ptrace, and different
 * syscall numbering — so the register-fetching bits are behind
 * #ifdef __x86_64__ / __aarch64__.
 *
 * Build: make
 * Run:   ./mini-strace /bin/ls -la
 *        ./mini-strace -e trace=file /bin/cat foo.txt
 *        ./mini-strace -e trace=network,openat /bin/curl example.com
 *        ./mini-strace -p 12345
 *        ./mini-strace -f /bin/sh -c 'echo hi'
 *        ./mini-strace -T /bin/sleep 1
 *        ./mini-strace -c /bin/ls
 *        ./mini-strace -o trace.log /bin/ls
 *        ./mini-strace -s 4 /bin/echo hello
 *        ./mini-strace -y /bin/cat /etc/hostname
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <signal.h>

#include "syscall_names.h"
#include "arch.h"
#include "arg_routing.h"
#include "trace_filter.h"
#include "child_mem.h"
#include "decoders.h"

static void run_tracee(char **argv) {
    /* let the parent trace us */
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        perror("ptrace(TRACEME)");
        exit(1);
    }
    /* stop ourselves before exec so the tracer has time to catch up */
    raise(SIGSTOP);

    execvp(argv[0], argv);
    /* only reached if execvp failed */
    perror("execvp");
    exit(1);
}

/* Per-tracee state, needed once -f lets more than one process be
 * traced at a time — each pid has its own independent entry/exit
 * toggle and its own in-flight deferred-print state, so these can no
 * longer live as locals in run_tracer() the way they did when there
 * was only ever one tracee. Fixed-size table instead of anything
 * dynamic, same pragmatic style as MAX_FILTER_TOKENS above; 64
 * concurrent tracees is far more than this is ever meant to handle. */
#define MAX_TRACEES 64

typedef struct {
    pid_t pid;
    int active;
    int in_syscall;
    const char *pending_name;
    unsigned long long pending_args[6];
    const buffer_arg_entry *pending_read_entry;
    const buffer_arg_entry *pending_sockaddr_entry;
    int pending_wait_status_idx;  /* -1 = none; which arg is wait4's wstatus */
    int pending_msghdr_idx;       /* -1 = none; which arg is recvmsg's struct msghdr* */
    int pending_stat_idx;         /* -1 = none; which arg is the stat-family's struct stat* */
    int suppressed;
    struct timespec entry_time;  /* when this syscall's entry-stop fired, for -T/-c */
    const char *current_name;    /* syscall in flight, for -c's per-name accounting */
} tracee_state;

static tracee_state tracees[MAX_TRACEES];

static tracee_state *find_tracee(pid_t pid) {
    for (int i = 0; i < MAX_TRACEES; i++) {
        if (tracees[i].active && tracees[i].pid == pid)
            return &tracees[i];
    }
    return NULL;
}

/* Idempotent: returns the existing entry if pid is already tracked
 * (harmless re-registration happens naturally, e.g. a new child's own
 * first stop can arrive either before or after its PTRACE_EVENT_FORK
 * notification on the parent). */
static tracee_state *add_tracee(pid_t pid) {
    tracee_state *existing = find_tracee(pid);
    if (existing != NULL)
        return existing;
    for (int i = 0; i < MAX_TRACEES; i++) {
        if (!tracees[i].active) {
            memset(&tracees[i], 0, sizeof(tracees[i]));
            tracees[i].pid = pid;
            tracees[i].active = 1;
            return &tracees[i];
        }
    }
    return NULL;  /* table full — extremely fork-heavy tracee, stop tracking new ones */
}

static void remove_tracee(pid_t pid) {
    tracee_state *ts = find_tracee(pid);
    if (ts != NULL)
        ts->active = 0;
}

/* Per-syscall-name aggregates for -c (calls/errors/total time,
 * grouped by name instead of one line per call). Names are static
 * string literals out of syscall_names.h, so storing the pointer
 * as-is (rather than copying) is safe. Linear-scan lookup over a
 * fixed table, same pragmatic style as the rest of this file — a few
 * hundred distinct syscall names in one run is already a lot. */
#define MAX_SUMMARY_ENTRIES 256

typedef struct {
    const char *name;
    long calls;
    long errors;
    double total_time;
} summary_entry;

static summary_entry summary_table[MAX_SUMMARY_ENTRIES];
static int summary_entry_count = 0;

static summary_entry *summary_lookup_or_add(const char *name) {
    for (int i = 0; i < summary_entry_count; i++) {
        if (strcmp(summary_table[i].name, name) == 0)
            return &summary_table[i];
    }
    if (summary_entry_count < MAX_SUMMARY_ENTRIES) {
        summary_entry *se = &summary_table[summary_entry_count++];
        se->name = name;
        se->calls = 0;
        se->errors = 0;
        se->total_time = 0.0;
        return se;
    }
    return NULL;  /* table full — extremely diverse syscall usage, drop the rest */
}

static void print_summary(FILE *out) {
    /* selection sort by total_time descending — table is at most a
     * couple hundred rows, no need for anything fancier */
    for (int i = 0; i < summary_entry_count - 1; i++) {
        int max_idx = i;
        for (int j = i + 1; j < summary_entry_count; j++) {
            if (summary_table[j].total_time > summary_table[max_idx].total_time)
                max_idx = j;
        }
        if (max_idx != i) {
            summary_entry tmp = summary_table[i];
            summary_table[i] = summary_table[max_idx];
            summary_table[max_idx] = tmp;
        }
    }

    double grand_total = 0.0;
    long grand_calls = 0, grand_errors = 0;
    for (int i = 0; i < summary_entry_count; i++) {
        grand_total += summary_table[i].total_time;
        grand_calls += summary_table[i].calls;
        grand_errors += summary_table[i].errors;
    }

    fprintf(out, "%% time     seconds  usecs/call     calls    errors syscall\n");
    fprintf(out, "------ ----------- ----------- --------- --------- ----------------\n");
    for (int i = 0; i < summary_entry_count; i++) {
        double pct = grand_total > 0.0 ? (summary_table[i].total_time / grand_total * 100.0) : 0.0;
        long usecs_per_call = summary_table[i].calls > 0
            ? (long)(summary_table[i].total_time * 1e6 / summary_table[i].calls) : 0;
        fprintf(out, "%6.2f %11.6f %11ld %9ld %9ld %s\n",
                pct, summary_table[i].total_time, usecs_per_call,
                summary_table[i].calls, summary_table[i].errors, summary_table[i].name);
    }
    fprintf(out, "------ ----------- ----------- --------- --------- ----------------\n");
    fprintf(out, "100.00 %11.6f %11s %9ld %9ld total\n",
            grand_total, "", grand_calls, grand_errors);
}

/* Prints "name(arg0, arg1, ...) " with exactly as many arguments as
 * syscall_argc() knows this syscall actually has, instead of always
 * all 6 raw slots — real strace never shows access()'s 4 leftover
 * register values, so neither should this. Falls back to all 6 for
 * anything syscall_argc() doesn't recognize (-1), which is exactly
 * the old fixed behavior. */
static void print_call(FILE *out, const char *pid_prefix, const char *name,
                        char argbuf[6][STR_ARG_BUF_LEN]) {
    int argc = syscall_argc(name);
    int n = (argc < 0 || argc > 6) ? 6 : argc;
    fprintf(out, "%s%s(", pid_prefix, name);
    for (int i = 0; i < n; i++)
        fprintf(out, "%s%s", i ? ", " : "", argbuf[i]);
    fprintf(out, ") ");
}

/* follow_forks (-f) makes the tracer follow fork()/vfork()/clone()
 * into child processes instead of only ever watching the one process
 * it started with. Without it, the loop only has one tracee ever, so
 * this collapses back to the exact same one-child logic as before —
 * the two paths are kept separate below (rather than always running
 * the general multi-pid machinery) so default output/behavior is
 * untouched. */
static void run_tracer(pid_t child, int follow_forks, int show_timing, int summary_mode,
                        int show_fd_paths, FILE *trace_out, FILE *status_out) {
    int status;
    long call_count = 0;

    /* wait for the initial SIGSTOP from raise() above */
    waitpid(child, &status, 0);

    int options = PTRACE_O_TRACESYSGOOD;
    if (follow_forks)
        options |= PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE;
    ptrace(PTRACE_SETOPTIONS, child, NULL, (void *)(long)options);

    add_tracee(child);
    int active_count = 1;

    if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) == -1) {
        perror("ptrace(SYSCALL)");
        return;
    }

    for (;;) {
        pid_t wpid = waitpid(-1, &status, __WALL);
        if (wpid == -1) {
            if (errno == ECHILD)
                break;  /* no tracees left */
            continue;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            remove_tracee(wpid);
            active_count--;
            if (!follow_forks) {
                if (WIFEXITED(status))
                    fprintf(status_out, "\n[mini-strace] process exited, code %d, total syscalls: %ld\n",
                            WEXITSTATUS(status), call_count);
                else
                    fprintf(status_out, "\n[mini-strace] process killed by signal %d\n", WTERMSIG(status));
            } else {
                if (WIFEXITED(status))
                    fprintf(status_out, "\n[mini-strace] pid %d exited, code %d\n", wpid, WEXITSTATUS(status));
                else
                    fprintf(status_out, "\n[mini-strace] pid %d killed by signal %d\n", wpid, WTERMSIG(status));
                if (active_count <= 0)
                    fprintf(status_out, "[mini-strace] all tracees exited, total syscalls: %ld\n", call_count);
            }
            if (active_count <= 0)
                break;
            continue;
        }

        if (!WIFSTOPPED(status))
            continue;

        int stopsig = WSTOPSIG(status);
        int event = status >> 16;

        if (follow_forks && stopsig == SIGTRAP &&
            (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK || event == PTRACE_EVENT_CLONE)) {
            /* New child spawned. PTRACE_O_TRACE{FORK,VFORK,CLONE}
             * auto-attaches it to us with the same options already
             * inherited, so all that's needed here is to start
             * tracking it and let both it and the parent keep going;
             * the new pid's own first stop will surface separately
             * through this same waitpid(-1, ...) loop. */
            unsigned long new_pid = 0;
            if (ptrace(PTRACE_GETEVENTMSG, wpid, NULL, &new_pid) != -1) {
                if (add_tracee((pid_t)new_pid) != NULL) {
                    active_count++;
                    fprintf(status_out, "[mini-strace] new child pid %ld\n", new_pid);
                }
            }
            ptrace(PTRACE_SYSCALL, wpid, NULL, NULL);
            continue;
        }

        /* PTRACE_SYSCALL stops a tracee both on real syscall
         * boundaries *and* whenever a signal is about to be
         * delivered to it. PTRACE_O_TRACESYSGOOD (set above) makes
         * genuine syscall-stops report SIGTRAP with the high bit set
         * (SIGTRAP | 0x80) so we can tell the two apart — without
         * this check, a signal landing mid-trace desyncs the
         * entry/exit toggle and every arg/return value after that
         * point is garbage. */
        if (stopsig != (SIGTRAP | 0x80)) {
            /* Not a syscall-stop: either a genuine signal (redeliver
             * it so it isn't silently eaten) or, under -f, a new
             * child's own first stop arriving as a plain SIGTRAP
             * before/instead of the parent's event notification —
             * either way just track it and let it continue. */
            int deliver = (stopsig != SIGTRAP) ? stopsig : 0;
            if (deliver != 0) {
                /* a real signal is about to be delivered — print it
                 * the way strace does, so a crash (SIGSEGV, SIGABRT,
                 * ...) or an external kill shows up in the trace
                 * instead of only being visible later as an opaque
                 * "killed by signal N" line once the process is
                 * actually gone. */
                char prefix[24] = "";
                if (follow_forks)
                    snprintf(prefix, sizeof(prefix), "[pid %d] ", wpid);
                fprintf(trace_out, "%s--- SIG%s (%s) ---\n", prefix, sigabbrev_np(deliver), sigdescr_np(deliver));
                fflush(trace_out);
            }
            add_tracee(wpid);
            ptrace(PTRACE_SYSCALL, wpid, NULL, (void *)(long)deliver);
            continue;
        }

        tracee_state *ts = add_tracee(wpid);
        if (ts == NULL) {
            ptrace(PTRACE_SYSCALL, wpid, NULL, NULL);
            continue;
        }

        arch_regs_t regs;
        if (get_regs(wpid, &regs) == -1) {
            ptrace(PTRACE_SYSCALL, wpid, NULL, NULL);
            continue;
        }

        char pid_prefix[24] = "";
        if (follow_forks)
            snprintf(pid_prefix, sizeof(pid_prefix), "[pid %d] ", wpid);

        if (!ts->in_syscall) {
            /* syscall entry */
            long syscall_no = syscall_no_of(&regs);
            const char *name = syscall_name(syscall_no);
            ts->current_name = name;
            unsigned long long raw_args[6] = {
                arg0(&regs), arg1(&regs), arg2(&regs),
                arg3(&regs), arg4(&regs), arg5(&regs),
            };

            const buffer_arg_entry *read_entry = read_arg_lookup(name);
            const buffer_arg_entry *accept_entry = accept_arg_lookup(name);
            unsigned char wait_mask = wait_status_arg_mask(name);
            int wait_status_idx = -1;
            for (int i = 0; i < 6; i++) {
                if (wait_mask & (1 << i)) {
                    wait_status_idx = i;
                    break;
                }
            }
            unsigned char msghdr_recv_mask = msghdr_recv_arg_mask(name);
            int msghdr_recv_idx = -1;
            for (int i = 0; i < 6; i++) {
                if (msghdr_recv_mask & (1 << i)) {
                    msghdr_recv_idx = i;
                    break;
                }
            }
            unsigned char stat_buf_mask = stat_buf_arg_mask(name);
            int stat_buf_idx = -1;
            for (int i = 0; i < 6; i++) {
                if (stat_buf_mask & (1 << i)) {
                    stat_buf_idx = i;
                    break;
                }
            }

            if (show_timing || summary_mode)
                clock_gettime(CLOCK_MONOTONIC, &ts->entry_time);

            ts->suppressed = !syscall_allowed(name);

            if (ts->suppressed) {
                /* filtered out by -e trace=SET — don't print anything,
                 * but still track it through entry/exit like normal so
                 * the toggle stays in sync and pending state from a
                 * *previous* (allowed) read()/accept()/wait4() doesn't
                 * leak in. */
                ts->pending_read_entry = NULL;
                ts->pending_sockaddr_entry = NULL;
                ts->pending_wait_status_idx = -1;
                ts->pending_msghdr_idx = -1;
                ts->pending_stat_idx = -1;
            } else if (read_entry != NULL || accept_entry != NULL || wait_status_idx >= 0 ||
                       msghdr_recv_idx >= 0 || stat_buf_idx >= 0) {
                /* read()-family, accept/getsockname/getpeername-family,
                 * wait4, recvmsg, and/or the stat family: their
                 * buffer/sockaddr/wstatus/msghdr/struct stat is
                 * unpopulated until the syscall actually runs, so
                 * there's nothing useful to dereference yet — stash
                 * everything and build the whole line at the exit-stop
                 * instead. More than one can apply to the same call
                 * (recvfrom has a deferred data buffer *and* a deferred
                 * sockaddr); the exit-stop print below handles any
                 * combination, or none, being set. */
                ts->pending_name = name;
                memcpy(ts->pending_args, raw_args, sizeof(raw_args));
                ts->pending_read_entry = read_entry;
                ts->pending_sockaddr_entry = accept_entry;
                ts->pending_wait_status_idx = wait_status_idx;
                ts->pending_msghdr_idx = msghdr_recv_idx;
                ts->pending_stat_idx = stat_buf_idx;
            } else {
                /* everything else prints immediately, same as before:
                 * known path-string args get dereferenced, write()'s
                 * buffer gets dumped, everything unrecognized prints
                 * as a raw hex address/value. */
                ts->pending_read_entry = NULL;
                ts->pending_sockaddr_entry = NULL;
                ts->pending_wait_status_idx = -1;
                ts->pending_msghdr_idx = -1;
                ts->pending_stat_idx = -1;
                if (!summary_mode) {
                    unsigned char str_mask = string_arg_mask(name);
                    unsigned char argv_mask = argv_arg_mask(name);
                    unsigned char open_flags_mask = open_flags_arg_mask(name);
                    unsigned char prot_flags_mask = prot_flags_arg_mask(name);
                    unsigned char map_flags_mask = map_flags_arg_mask(name);
                    unsigned char socket_domain_mask = socket_domain_arg_mask(name);
                    unsigned char socket_type_mask = socket_type_arg_mask(name);
                    unsigned char signal_mask = signal_arg_mask(name);
                    unsigned char lseek_whence_mask = lseek_whence_arg_mask(name);
                    unsigned char fcntl_cmd_mask = fcntl_cmd_arg_mask(name);
                    unsigned char sigprocmask_how_mask = sigprocmask_how_arg_mask(name);
                    unsigned char access_mode_mask = access_mode_arg_mask(name);
                    unsigned char clockid_mask = clockid_arg_mask(name);
                    unsigned char clone_flags_mask = clone_flags_arg_mask(name);
                    unsigned char clone3_args_mask = clone3_args_arg_mask(name);
                    unsigned char ioctl_request_mask = ioctl_request_arg_mask(name);
                    unsigned char msghdr_send_mask = msghdr_send_arg_mask(name);
                    unsigned char fd_mask = show_fd_paths ? fd_arg_mask(name) : 0;
                    const buffer_arg_entry *buf_entry = buffer_arg_lookup(name);
                    const buffer_arg_entry *sockaddr_entry = sockaddr_arg_lookup(name);

                    char argbuf[6][STR_ARG_BUF_LEN];
                    for (int i = 0; i < 6; i++) {
                        if (str_mask & (1 << i))
                            read_child_string(wpid, raw_args[i], argbuf[i], sizeof(argbuf[i]));
                        else if (argv_mask & (1 << i))
                            read_child_argv(wpid, raw_args[i], argbuf[i], sizeof(argbuf[i]));
                        else if (open_flags_mask & (1 << i))
                            format_open_flags(raw_args[i], argbuf[i], sizeof(argbuf[i]));
                        else if (prot_flags_mask & (1 << i))
                            format_prot_flags(raw_args[i], argbuf[i], sizeof(argbuf[i]));
                        else if (map_flags_mask & (1 << i))
                            format_map_flags(raw_args[i], argbuf[i], sizeof(argbuf[i]));
                        else if (socket_domain_mask & (1 << i))
                            format_socket_domain(raw_args[i], argbuf[i], sizeof(argbuf[i]));
                        else if (socket_type_mask & (1 << i))
                            format_socket_type(raw_args[i], argbuf[i], sizeof(argbuf[i]));
                        else if (signal_mask & (1 << i))
                            format_signal_arg(raw_args[i], argbuf[i], sizeof(argbuf[i]));
                        else if (lseek_whence_mask & (1 << i))
                            format_lseek_whence(raw_args[i], argbuf[i], sizeof(argbuf[i]));
                        else if (fcntl_cmd_mask & (1 << i))
                            format_fcntl_cmd(raw_args[i], argbuf[i], sizeof(argbuf[i]));
                        else if (sigprocmask_how_mask & (1 << i))
                            format_sigprocmask_how(raw_args[i], argbuf[i], sizeof(argbuf[i]));
                        else if (access_mode_mask & (1 << i))
                            format_access_mode(raw_args[i], argbuf[i], sizeof(argbuf[i]));
                        else if (clockid_mask & (1 << i))
                            format_clockid(raw_args[i], argbuf[i], sizeof(argbuf[i]));
                        else if (clone_flags_mask & (1 << i))
                            format_clone_flags(raw_args[i], argbuf[i], sizeof(argbuf[i]));
                        else if (clone3_args_mask & (1 << i))
                            format_clone3_flags(wpid, raw_args[i], argbuf[i], sizeof(argbuf[i]));
                        else if (ioctl_request_mask & (1 << i))
                            format_ioctl_request(raw_args[i], argbuf[i], sizeof(argbuf[i]));
                        else if (msghdr_send_mask & (1 << i))
                            format_msghdr(wpid, raw_args[i], -1, argbuf[i], sizeof(argbuf[i]));
                        else if (buf_entry != NULL && i == buf_entry->buf_idx)
                            read_child_buffer(wpid, raw_args[i], raw_args[buf_entry->len_idx],
                                               argbuf[i], sizeof(argbuf[i]));
                        else if (sockaddr_entry != NULL && i == sockaddr_entry->buf_idx)
                            format_sockaddr(wpid, raw_args[i], raw_args[sockaddr_entry->len_idx],
                                             argbuf[i], sizeof(argbuf[i]));
                        else
                            format_hex_or_fd_arg(wpid, raw_args[i], fd_mask & (1 << i),
                                                  argbuf[i], sizeof(argbuf[i]));
                    }

                    print_call(trace_out, pid_prefix, name, argbuf);
                    fflush(trace_out);
                }
            }
            call_count++;
            ts->in_syscall = 1;
        } else {
            /* syscall exit — return value in whichever register the
             * platform uses for it */
            long ret = return_val_of(&regs);

            if (ts->suppressed) {
                /* filtered out — nothing was printed at entry, so
                 * nothing prints here either */
            } else {
                if (ts->pending_read_entry != NULL || ts->pending_sockaddr_entry != NULL ||
                    ts->pending_wait_status_idx >= 0 || ts->pending_msghdr_idx >= 0 ||
                    ts->pending_stat_idx >= 0) {
                    /* deferred print: build the whole "name(args) = ret"
                     * line now that the return value (and anything the
                     * kernel filled in) is available. Any of the five
                     * pending fields can be set alone (read()-family,
                     * accept/getsockname/getpeername-family, wait4,
                     * recvmsg, or the stat family) or combined
                     * (recvfrom: a deferred data buffer *and* a
                     * deferred sockaddr in the same call) — each claims
                     * its own argument slot, so there's no conflict
                     * rendering them into the same line. Skipped
                     * entirely under -c, which never prints per-call
                     * lines. */
                    if (!summary_mode) {
                        unsigned char fd_mask = show_fd_paths ? fd_arg_mask(ts->pending_name) : 0;
                        /* path-string arguments (the stat family's path,
                         * alongside its deferred struct stat) are
                         * populated by the caller before the syscall
                         * runs and don't change while it's in flight, so
                         * this is safe to read here regardless of ret —
                         * same data read_child_string would have used at
                         * the entry-stop, just deferred alongside
                         * whatever else this call needs deferred. */
                        unsigned char str_mask = string_arg_mask(ts->pending_name);

                        /* the socklen_t the kernel wrote the real
                         * sockaddr size into is itself only valid now,
                         * at the exit-stop, so it has to be re-read via
                         * its own ptrace peek rather than trusted from
                         * entry. */
                        unsigned long long addrlen = sizeof(struct sockaddr_storage);
                        if (ts->pending_sockaddr_entry != NULL) {
                            unsigned long long addrlen_ptr = ts->pending_args[ts->pending_sockaddr_entry->len_idx];
                            if (ret >= 0 && addrlen_ptr != 0) {
                                errno = 0;
                                long word = ptrace(PTRACE_PEEKDATA, wpid, (void *)addrlen_ptr, NULL);
                                if (!(word == -1 && errno != 0))
                                    addrlen = (unsigned int)word;  /* socklen_t is 4 bytes */
                            }
                        }

                        char argbuf[6][STR_ARG_BUF_LEN];
                        for (int i = 0; i < 6; i++) {
                            if (str_mask & (1 << i))
                                read_child_string(wpid, ts->pending_args[i], argbuf[i], sizeof(argbuf[i]));
                            else if (ts->pending_read_entry != NULL &&
                                i == ts->pending_read_entry->buf_idx && ret > 0)
                                read_child_buffer(wpid, ts->pending_args[i], (unsigned long long)ret,
                                                   argbuf[i], sizeof(argbuf[i]));
                            else if (ts->pending_sockaddr_entry != NULL &&
                                     i == ts->pending_sockaddr_entry->buf_idx && ret >= 0)
                                format_sockaddr(wpid, ts->pending_args[i], addrlen, argbuf[i], sizeof(argbuf[i]));
                            else if (ts->pending_wait_status_idx == i && ret >= 0)
                                format_wait_status(wpid, ts->pending_args[i], argbuf[i], sizeof(argbuf[i]));
                            else if (ts->pending_msghdr_idx == i && ret >= 0)
                                format_msghdr(wpid, ts->pending_args[i], ret, argbuf[i], sizeof(argbuf[i]));
                            else if (ts->pending_stat_idx == i && ret >= 0)
                                format_stat_buf(wpid, ts->pending_args[i], argbuf[i], sizeof(argbuf[i]));
                            else
                                format_hex_or_fd_arg(wpid, ts->pending_args[i], fd_mask & (1 << i),
                                                      argbuf[i], sizeof(argbuf[i]));
                        }
                        print_call(trace_out, pid_prefix, ts->pending_name, argbuf);
                    }
                    ts->pending_read_entry = NULL;
                    ts->pending_sockaddr_entry = NULL;
                    ts->pending_wait_status_idx = -1;
                    ts->pending_msghdr_idx = -1;
                    ts->pending_stat_idx = -1;
                }

                double elapsed = 0.0;
                char timing_buf[32] = "";
                if (show_timing || summary_mode) {
                    struct timespec now;
                    clock_gettime(CLOCK_MONOTONIC, &now);
                    elapsed = (now.tv_sec - ts->entry_time.tv_sec) +
                              (now.tv_nsec - ts->entry_time.tv_nsec) / 1e9;
                    if (show_timing)
                        snprintf(timing_buf, sizeof(timing_buf), " <%.6f>", elapsed);
                }

                if (summary_mode) {
                    /* -c: no per-call output at all, just fold this
                     * call into its name's running totals — the
                     * table itself prints once, after the loop ends. */
                    summary_entry *se = summary_lookup_or_add(ts->current_name);
                    if (se != NULL) {
                        se->calls++;
                        if (ret < 0)
                            se->errors++;
                        se->total_time += elapsed;
                    }
                } else if (ret < 0) {
                    const char *ename = strerrorname_np((int)(-ret));
                    fprintf(trace_out, "= %ld (%s)%s\n", ret, ename ? ename : "unknown errno", timing_buf);
                } else {
                    fprintf(trace_out, "= %ld%s\n", ret, timing_buf);
                }
            }
            ts->in_syscall = 0;
        }

        ptrace(PTRACE_SYSCALL, wpid, NULL, NULL);
    }

    if (summary_mode)
        print_summary(status_out);
}

int main(int argc, char **argv) {
    int argi = 1;
    pid_t attach_pid = -1;
    int follow_forks = 0;
    int show_timing = 0;
    int summary_mode = 0;
    int show_fd_paths = 0;
    const char *output_file = NULL;

    while (argi < argc && (strcmp(argv[argi], "-e") == 0 ||
                            strcmp(argv[argi], "-p") == 0 ||
                            strcmp(argv[argi], "-f") == 0 ||
                            strcmp(argv[argi], "-T") == 0 ||
                            strcmp(argv[argi], "-c") == 0 ||
                            strcmp(argv[argi], "-o") == 0 ||
                            strcmp(argv[argi], "-s") == 0 ||
                            strcmp(argv[argi], "-y") == 0)) {
        if (strcmp(argv[argi], "-f") == 0) {
            follow_forks = 1;
            argi += 1;
            continue;
        }

        if (strcmp(argv[argi], "-y") == 0) {
            show_fd_paths = 1;
            argi += 1;
            continue;
        }

        if (strcmp(argv[argi], "-T") == 0) {
            show_timing = 1;
            argi += 1;
            continue;
        }

        if (strcmp(argv[argi], "-c") == 0) {
            summary_mode = 1;
            argi += 1;
            continue;
        }

        if (strcmp(argv[argi], "-o") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "error: -o needs a file path\n");
                return 1;
            }
            output_file = argv[argi + 1];
            argi += 2;
            continue;
        }

        if (strcmp(argv[argi], "-s") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "error: -s needs a size argument\n");
                return 1;
            }
            char *endptr;
            long size = strtol(argv[argi + 1], &endptr, 10);
            if (*endptr != '\0' || size < 1) {
                fprintf(stderr, "error: '%s' is not a valid size\n", argv[argi + 1]);
                return 1;
            }
            max_str_len = (size_t)size < (size_t)STR_ARG_BUF_LEN ? (size_t)size : (size_t)STR_ARG_BUF_LEN;
            argi += 2;
            continue;
        }

        if (strcmp(argv[argi], "-p") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "error: -p needs a PID argument\n");
                return 1;
            }
            char *endptr;
            long pid = strtol(argv[argi + 1], &endptr, 10);
            if (*endptr != '\0' || pid <= 0) {
                fprintf(stderr, "error: '%s' is not a valid PID\n", argv[argi + 1]);
                return 1;
            }
            attach_pid = (pid_t)pid;
            argi += 2;
            continue;
        }

        /* -e trace=SET */
        if (argi + 1 >= argc) {
            fprintf(stderr, "error: -e needs an argument, e.g. -e trace=file\n");
            return 1;
        }
        char *opt = argv[argi + 1];
        if (strncmp(opt, "trace=", 6) == 0) {
            parse_trace_filter(opt + 6);  /* modifies opt in place via strtok */
        } else {
            fprintf(stderr, "error: unrecognized -e option '%s' (only trace=SET is supported)\n", opt);
            return 1;
        }
        argi += 2;
    }

    /* -o redirects both the trace lines (normally stdout) and the
     * "[mini-strace] ..." status lines (normally stderr) into one
     * file, same as real strace's -o. The traced program's own
     * stdin/stdout/stderr are untouched — this fd is just an extra
     * one sitting alongside them, not a replacement for fd 1/2, so a
     * fork+exec child inheriting it doesn't change what the child
     * itself reads from or writes to. */
    FILE *trace_out = stdout;
    FILE *status_out = stderr;
    if (output_file != NULL) {
        FILE *f = fopen(output_file, "w");
        if (f == NULL) {
            perror("fopen");
            return 1;
        }
        trace_out = f;
        status_out = f;
    }

    if (attach_pid != -1) {
        /* Attaching skips the fork/TRACEME/exec dance entirely: the
         * target is already running, so PTRACE_ATTACH just sends it
         * a SIGSTOP and starts tracing in place. That stop shows up
         * on the very next waitpid() in run_tracer() the same way
         * the tracee's self-raised SIGSTOP does in the fork+exec
         * path, so the rest of the tracing loop doesn't need to know
         * which way the process was acquired. */
        if (ptrace(PTRACE_ATTACH, attach_pid, NULL, NULL) == -1) {
            perror("ptrace(ATTACH)");
            return 1;
        }
        run_tracer(attach_pid, follow_forks, show_timing, summary_mode, show_fd_paths, trace_out, status_out);
        return 0;
    }

    if (argi >= argc) {
        fprintf(stderr, "usage: %s [-e trace=SET] [-f] [-T] [-c] [-o FILE] [-s SIZE] [-y] <program> [args...]\n", argv[0]);
        fprintf(stderr, "       %s [-e trace=SET] [-f] [-T] [-c] [-o FILE] [-s SIZE] [-y] -p <pid>\n", argv[0]);
        fprintf(stderr, "example: %s /bin/echo hello\n", argv[0]);
        fprintf(stderr, "example: %s -e trace=file /bin/cat foo.txt\n", argv[0]);
        fprintf(stderr, "example: %s -p 12345\n", argv[0]);
        fprintf(stderr, "example: %s -f /bin/sh -c 'echo hi'\n", argv[0]);
        fprintf(stderr, "example: %s -T /bin/sleep 1\n", argv[0]);
        fprintf(stderr, "example: %s -c /bin/ls\n", argv[0]);
        fprintf(stderr, "example: %s -o trace.log /bin/ls\n", argv[0]);
        fprintf(stderr, "example: %s -s 4 /bin/echo hello\n", argv[0]);
        fprintf(stderr, "example: %s -y /bin/cat /etc/hostname\n", argv[0]);
        fprintf(stderr, "  SET is a comma-separated mix of categories (file, network,\n");
        fprintf(stderr, "  process) and/or exact syscall names, e.g. trace=network,openat\n");
        fprintf(stderr, "  -f also traces child processes created via fork/vfork/clone\n");
        fprintf(stderr, "  -T appends the wall-clock time each syscall took, e.g. <0.000123>\n");
        fprintf(stderr, "  -c prints a per-syscall summary table instead of a line per call\n");
        fprintf(stderr, "  -o writes trace output to FILE instead of stdout/stderr\n");
        fprintf(stderr, "  -s caps string/buffer args at SIZE bytes before truncating with"
                        " \"...\" (default 200, max %d)\n", STR_ARG_BUF_LEN);
        fprintf(stderr, "  -y resolves file descriptor args to their path, e.g. 3</etc/hosts>\n");
        return 1;
    }

    pid_t child = fork();
    if (child == -1) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        run_tracee(&argv[argi]);
    } else {
        run_tracer(child, follow_forks, show_timing, summary_mode, show_fd_paths, trace_out, status_out);
    }

    return 0;
}
