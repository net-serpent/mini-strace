/*
 * mini-strace v1.0
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

#if defined(__aarch64__)
#include <sys/uio.h>
#define NT_PRSTATUS_ 1  /* from linux/elf.h — avoids pulling in elf.h just for this */
#endif

#include "syscall_names.h"

/* Which arguments of which syscalls are NUL-terminated C-string
 * paths, as a bitmask over argument slots 0-5 (bit i set = arg i is
 * a char* path). Covers the common filesystem/exec syscalls; not
 * exhaustive — anything not in this table just prints as a raw hex
 * address, same as before. */
typedef struct {
    const char *name;
    unsigned char str_args;  /* bit i => argument i is a path string */
} string_arg_entry;

static const string_arg_entry string_arg_table[] = {
    { "open",        0x01 },
    { "openat",      0x02 },
    { "creat",       0x01 },
    { "access",      0x01 },
    { "faccessat",   0x02 },
    { "faccessat2",  0x02 },
    { "stat",        0x01 },
    { "lstat",       0x01 },
    { "newfstatat",  0x02 },
    { "statx",       0x02 },
    { "execve",      0x01 },
    { "execveat",    0x02 },
    { "unlink",      0x01 },
    { "unlinkat",    0x02 },
    { "mkdir",       0x01 },
    { "mkdirat",     0x02 },
    { "rmdir",       0x01 },
    { "chdir",       0x01 },
    { "rename",      0x03 },  /* args 0 and 1 */
    { "renameat",    0x0a },  /* args 1 and 3 */
    { "renameat2",   0x0a },
    { "readlink",    0x01 },
    { "readlinkat",  0x02 },
    { "chmod",       0x01 },
    { "fchmodat",    0x02 },
    { "chown",       0x01 },
    { "lchown",      0x01 },
    { "fchownat",    0x02 },
    { "truncate",    0x01 },
    { "statfs",      0x01 },
    { "symlink",     0x03 },  /* args 0 and 1 */
    { "symlinkat",   0x05 },  /* args 0 (target) and 2 (linkpath) */
    { "link",        0x03 },  /* args 0 and 1 */
    { "linkat",      0x0a },  /* args 1 and 3 */
    { "mount",       0x07 },  /* args 0 (source), 1 (target), 2 (fstype) */
    { "umount2",     0x01 },
    { "chroot",      0x01 },
    { "pivot_root",  0x03 },  /* args 0 and 1 */
    { "utime",       0x01 },
    { "utimes",      0x01 },
    { "futimesat",   0x02 },
    { NULL,          0x00 },
};

static unsigned char string_arg_mask(const char *syscall) {
    for (int i = 0; string_arg_table[i].name != NULL; i++) {
        if (strcmp(string_arg_table[i].name, syscall) == 0)
            return string_arg_table[i].str_args;
    }
    return 0;
}

/* Which arguments of which syscalls are file descriptors, same
 * bitmask-over-slots-0-5 shape as string_arg_table — used by -y to
 * resolve a raw fd number to what it actually points to. Covers the
 * common fd-taking syscalls; *at() syscalls' dirfd is included too,
 * even though it's very often AT_FDCWD (a negative sentinel, not a
 * real fd) — resolve_fd_path() below just skips negative values. */
static const string_arg_entry fd_arg_table[] = {
    { "read",         0x01 },
    { "write",        0x01 },
    { "pread64",      0x01 },
    { "pwrite64",     0x01 },
    { "close",        0x01 },
    { "fstat",        0x01 },
    { "lseek",        0x01 },
    { "ioctl",        0x01 },
    { "fcntl",        0x01 },
    { "dup",          0x01 },
    { "dup2",         0x03 },  /* args 0 and 1 */
    { "dup3",         0x03 },
    { "fchmod",       0x01 },
    { "fchown",       0x01 },
    { "ftruncate",    0x01 },
    { "fstatfs",      0x01 },
    { "fsync",        0x01 },
    { "fdatasync",    0x01 },
    { "flock",        0x01 },
    { "openat",       0x01 },
    { "faccessat",    0x01 },
    { "faccessat2",   0x01 },
    { "unlinkat",     0x01 },
    { "mkdirat",      0x01 },
    { "renameat",     0x05 },  /* args 0 and 2 */
    { "renameat2",    0x05 },
    { "newfstatat",   0x01 },
    { "readlinkat",   0x01 },
    { "fchmodat",     0x01 },
    { "fchownat",     0x01 },
    { "symlinkat",    0x02 },  /* arg 1 (newdirfd) */
    { "linkat",       0x05 },  /* args 0 (olddirfd) and 2 (newdirfd) */
    { "futimesat",    0x01 },
    { "accept",       0x01 },
    { "accept4",      0x01 },
    { "bind",         0x01 },
    { "listen",       0x01 },
    { "connect",      0x01 },
    { "getsockname",  0x01 },
    { "getpeername",  0x01 },
    { "setsockopt",   0x01 },
    { "getsockopt",   0x01 },
    { "shutdown",     0x01 },
    { "sendto",       0x01 },
    { "recvfrom",     0x01 },
    { "sendmsg",      0x01 },
    { "recvmsg",      0x01 },
    { NULL,           0x00 },
};

static unsigned char fd_arg_mask(const char *syscall) {
    for (int i = 0; fd_arg_table[i].name != NULL; i++) {
        if (strcmp(fd_arg_table[i].name, syscall) == 0)
            return fd_arg_table[i].str_args;
    }
    return 0;
}

/* Which arguments are argv[]/envp[]-style NULL-terminated arrays of
 * C-string pointers — just execve/execveat's argv and envp today.
 * Same bitmask-over-slots-0-5 shape as string_arg_table; read via
 * read_child_argv() below instead of read_child_string() since these
 * are arrays of pointers, not a single string. */
static const string_arg_entry argv_arg_table[] = {
    { "execve",    0x06 },  /* args 1 (argv) and 2 (envp) */
    { "execveat",  0x0c },  /* args 2 (argv) and 3 (envp) */
    { NULL,        0x00 },
};

static unsigned char argv_arg_mask(const char *syscall) {
    for (int i = 0; argv_arg_table[i].name != NULL; i++) {
        if (strcmp(argv_arg_table[i].name, syscall) == 0)
            return argv_arg_table[i].str_args;
    }
    return 0;
}

/* Resolves fd to whatever it points to via /proc/pid/fd/N, which is
 * a symlink to the real path (or "socket:[12345]", "pipe:[12345]",
 * etc. for non-path fds — readlink() returns that text as-is, which
 * is exactly what real strace shows too). Negative fd (AT_FDCWD and
 * friends) and any readlink failure (already closed, fd genuinely
 * invalid, ...) just report "no path", not an error — resolving a
 * fd to a path is inherently best-effort. */
static int resolve_fd_path(pid_t pid, long fd, char *out, size_t out_size) {
    if (fd < 0)
        return 0;
    char linkpath[64];
    snprintf(linkpath, sizeof(linkpath), "/proc/%d/fd/%ld", (int)pid, fd);
    ssize_t n = readlink(linkpath, out, out_size - 1);
    if (n < 0)
        return 0;
    out[n] = '\0';
    return 1;
}

/* Formats an argument that isn't a known string/buffer: plain hex,
 * same as always, unless it's a fd slot under -y and resolve_fd_path
 * finds something — then "<path>" gets appended after the hex value,
 * e.g. "0x3<socket:[12345]>". is_fd_arg is 0 whenever -y isn't
 * active, so this collapses back to the plain-hex-only path by
 * default. */
static void format_hex_or_fd_arg(pid_t pid, unsigned long long raw, int is_fd_arg,
                                  char *out, size_t out_size) {
    if (is_fd_arg) {
        char path[192];
        if (resolve_fd_path(pid, (long)raw, path, sizeof(path))) {
            snprintf(out, out_size, "0x%llx<%s>", raw, path);
            return;
        }
    }
    snprintf(out, out_size, "0x%llx", raw);
}

/* Syscalls whose input is a raw (not NUL-terminated) byte buffer,
 * paired with which argument slot holds the buffer and which slot
 * holds its length. Unlike string_arg_table this only covers
 * "output" syscalls — the buffer is already populated by the caller
 * before the syscall runs, so it can be dereferenced at the same
 * entry-stop as everything else. read()'s buffer is the opposite
 * case (empty until the syscall actually runs) and needs different
 * handling — see read_arg_table below. */
typedef struct {
    const char *name;
    int buf_idx;
    int len_idx;
} buffer_arg_entry;

static const buffer_arg_entry buffer_arg_table[] = {
    { "write",    1, 2 },
    { "pwrite64", 1, 2 },
    { NULL,       0, 0 },
};

static const buffer_arg_entry *buffer_arg_lookup(const char *syscall) {
    for (int i = 0; buffer_arg_table[i].name != NULL; i++) {
        if (strcmp(buffer_arg_table[i].name, syscall) == 0)
            return &buffer_arg_table[i];
    }
    return NULL;
}

/* Syscalls whose output is a raw byte buffer that's only populated
 * *after* the syscall actually runs — read()'s buf is garbage/empty
 * at the entry-stop, so unlike write() this can't be dereferenced
 * there. These get looked up separately and handled by deferring
 * the whole print to the exit-stop, where the return value tells us
 * how many bytes actually landed in the buffer. Reuses
 * buffer_arg_entry since the shape (which arg is the buffer) is the
 * same idea — len_idx is unused here since the real length is the
 * return value, not the requested count. */
static const buffer_arg_entry read_arg_table[] = {
    { "read",    1, 2 },
    { "pread64", 1, 2 },
    { NULL,      0, 0 },
};

static const buffer_arg_entry *read_arg_lookup(const char *syscall) {
    for (int i = 0; read_arg_table[i].name != NULL; i++) {
        if (strcmp(read_arg_table[i].name, syscall) == 0)
            return &read_arg_table[i];
    }
    return NULL;
}

/* -e trace=SET filtering. SET is a comma-separated list where each
 * token is either a category name (file/network/process) or an
 * exact syscall name — same idea as real strace's -e trace, just
 * with three hardcoded categories instead of a full syscall
 * classification. Not exhaustive, covers the common ones. */
static const char *file_syscalls[] = {
    "open", "openat", "close", "read", "write", "pread64", "pwrite64",
    "stat", "lstat", "fstat", "newfstatat", "statx", "access",
    "faccessat", "faccessat2", "unlink", "unlinkat", "rename",
    "renameat", "renameat2", "mkdir", "mkdirat", "rmdir", "chdir",
    "chmod", "fchmodat", "chown", "lchown", "fchownat", "truncate",
    "readlink", "readlinkat", "statfs", "lseek", "getcwd", "creat",
    "symlink", "symlinkat", "link", "linkat", "mount", "umount2",
    "chroot", "pivot_root", "utime", "utimes", "futimesat",
    NULL,
};

static const char *network_syscalls[] = {
    "socket", "connect", "accept", "accept4", "bind", "listen",
    "send", "recv", "sendto", "recvfrom", "sendmsg", "recvmsg",
    "setsockopt", "getsockopt", "shutdown", "socketpair",
    "getsockname", "getpeername",
    NULL,
};

static const char *process_syscalls[] = {
    "fork", "vfork", "clone", "clone3", "execve", "execveat", "exit",
    "exit_group", "wait4", "waitid", "kill", "tgkill", "tkill",
    "ptrace", "prctl",
    NULL,
};

static int name_in_list(const char **list, const char *name) {
    for (int i = 0; list[i] != NULL; i++) {
        if (strcmp(list[i], name) == 0)
            return 1;
    }
    return 0;
}

/* The parsed -e trace=SET tokens, filled in once by parse_trace_filter().
 * A NULL filter_tokens means "no filter — trace everything", which is
 * also the state before -e is ever parsed. */
#define MAX_FILTER_TOKENS 16
static char filter_tokens[MAX_FILTER_TOKENS][64];
static int filter_token_count = 0;

static void parse_trace_filter(char *set) {
    char *tok = strtok(set, ",");
    while (tok != NULL && filter_token_count < MAX_FILTER_TOKENS) {
        snprintf(filter_tokens[filter_token_count], sizeof(filter_tokens[0]), "%s", tok);
        filter_token_count++;
        tok = strtok(NULL, ",");
    }
}

static int syscall_allowed(const char *name) {
    if (filter_token_count == 0)
        return 1;  /* no filter set — trace everything */

    for (int i = 0; i < filter_token_count; i++) {
        const char *tok = filter_tokens[i];
        if (strcmp(tok, "file") == 0 && name_in_list(file_syscalls, name))
            return 1;
        if (strcmp(tok, "network") == 0 && name_in_list(network_syscalls, name))
            return 1;
        if (strcmp(tok, "process") == 0 && name_in_list(process_syscalls, name))
            return 1;
        if (strcmp(tok, name) == 0)  /* exact syscall name */
            return 1;
    }
    return 0;
}

/* Physical capacity of the raw read window and the escaped-output
 * buffer for string/buffer arguments — a hard ceiling, not the
 * actual truncation point a user sees day to day. -s SIZE (below)
 * picks how many raw bytes actually get shown, up to this cap. */
#define STR_ARG_BUF_LEN 1024

/* Default -s value: how many raw bytes of a string/buffer argument
 * get read and shown before truncating with "...". Matches the old
 * hardcoded STR_ARG_BUF_LEN so default output is unchanged; -s can
 * raise or lower it, up to STR_ARG_BUF_LEN. */
static size_t max_str_len = 200;

/* Reads a NUL-terminated string out of the traced process's address
 * space, one machine word at a time, via PTRACE_PEEKDATA — the
 * classic way strace has always done this (predates /proc/pid/mem
 * as a read interface, and doesn't depend on /proc being mounted
 * with the right options). Falls back to printing the raw address
 * if the read fails for any reason (bad pointer, unmapped page,
 * race with the tracee tearing things down, ...) — a failed
 * dereference shouldn't crash the tracer, it should just degrade to
 * what v0.6 already did. */
static void read_child_string(pid_t pid, unsigned long long addr, char *out, size_t out_size) {
    if (addr == 0) {
        snprintf(out, out_size, "NULL");
        return;
    }

    unsigned char raw[STR_ARG_BUF_LEN];
    /* PTRACE_PEEKDATA only ever reads whole words, so the read window
     * has to round max_str_len up to a word boundary — otherwise a
     * -s value smaller than sizeof(long) would make the loop below
     * exit before reading anything at all. The actual *displayed*
     * length still gets clamped to max_str_len afterward. */
    size_t read_cap = ((max_str_len + sizeof(long) - 1) / sizeof(long)) * sizeof(long);
    if (read_cap > sizeof(raw))
        read_cap = sizeof(raw);
    size_t got = 0;

    while (got + sizeof(long) <= read_cap) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + got), NULL);
        if (word == -1 && errno != 0)
            break;  /* unmapped/invalid address — stop, use what we have */

        memcpy(raw + got, &word, sizeof(long));
        got += sizeof(long);

        int has_nul = 0;
        for (size_t i = 0; i < sizeof(long); i++) {
            if (((unsigned char *)&word)[i] == '\0') { has_nul = 1; break; }
        }
        if (has_nul)
            break;
    }

    if (got == 0) {
        snprintf(out, out_size, "0x%llx", addr);
        return;
    }

    size_t len = 0;
    while (len < got && raw[len] != '\0')
        len++;
    int truncated = (len == got);  /* string may continue past our read window */
    if (len > max_str_len) {
        len = max_str_len;  /* -s truncation, even though a NUL exists further in */
        truncated = 1;
    }

    size_t oi = 0;
    if (oi < out_size) out[oi++] = '"';
    for (size_t i = 0; i < len && oi + 5 < out_size; i++) {
        unsigned char c = raw[i];
        if (c == '"' || c == '\\') {
            out[oi++] = '\\';
            out[oi++] = (char)c;
        } else if (c == '\n') {
            out[oi++] = '\\'; out[oi++] = 'n';
        } else if (c >= 0x20 && c < 0x7f) {
            out[oi++] = (char)c;
        } else {
            oi += (size_t)snprintf(out + oi, out_size - oi, "\\x%02x", c);
        }
    }
    if (oi < out_size) out[oi++] = '"';
    if (truncated && oi + 3 < out_size) {
        memcpy(out + oi, "...", 3);
        oi += 3;
    }
    if (oi < out_size) out[oi] = '\0';
    else out[out_size - 1] = '\0';
}

/* Max entries read out of an argv[]/envp[] array before giving up
 * and marking it truncated — bounds both the ptrace call count and
 * the output line length for processes with huge environments. */
#define MAX_ARGV_ITEMS 32

/* Reads a NULL-terminated array of char* (execve's argv/envp) and
 * renders it as "[\"a\", \"b\", ...]", reusing read_child_string()
 * for each element. Each pointer is fetched with its own
 * PTRACE_PEEKDATA the same way read_child_string reads string bytes
 * — a word at a time, since that's the only unit ptrace deals in. */
static void read_child_argv(pid_t pid, unsigned long long addr, char *out, size_t out_size) {
    if (addr == 0) {
        snprintf(out, out_size, "NULL");
        return;
    }

    size_t oi = 0;
    if (oi < out_size) out[oi++] = '[';

    int count = 0;
    int truncated = 0;
    for (; count < MAX_ARGV_ITEMS; count++) {
        errno = 0;
        long ptr = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + (unsigned long long)count * sizeof(long)), NULL);
        if (ptr == -1 && errno != 0)
            break;  /* unmapped/invalid address — stop, use what we have */
        if (ptr == 0)
            break;  /* NULL terminator — normal end of the array */

        char item[STR_ARG_BUF_LEN];
        read_child_string(pid, (unsigned long long)ptr, item, sizeof(item));

        if (count > 0 && oi + 2 < out_size) {
            out[oi++] = ',';
            out[oi++] = ' ';
        }
        size_t item_len = strlen(item);
        if (oi + item_len < out_size) {
            memcpy(out + oi, item, item_len);
            oi += item_len;
        }

        if (count == MAX_ARGV_ITEMS - 1)
            truncated = 1;  /* hit our cap with a real (non-NULL) entry — array may continue past it */
    }

    if (truncated && oi + 5 < out_size) {
        memcpy(out + oi, ", ...", 5);
        oi += 5;
    }

    if (oi < out_size) out[oi++] = ']';
    if (oi < out_size) out[oi] = '\0';
    else out[out_size - 1] = '\0';
}

/* Same idea as read_child_string but for a buffer whose length is
 * known up front (from the syscall's own length argument) instead
 * of being NUL-terminated — write()'s data isn't necessarily text,
 * so this doesn't stop early at a zero byte, it just reads min(len,
 * our cap) bytes and escapes all of them. */
static void read_child_buffer(pid_t pid, unsigned long long addr, unsigned long long len,
                               char *out, size_t out_size) {
    if (addr == 0) {
        snprintf(out, out_size, "NULL");
        return;
    }

    size_t cap = (max_str_len < STR_ARG_BUF_LEN) ? max_str_len : STR_ARG_BUF_LEN;
    size_t want = (len < cap) ? (size_t)len : cap;
    unsigned char raw[STR_ARG_BUF_LEN];
    size_t got = 0;

    while (got < want) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + got), NULL);
        if (word == -1 && errno != 0)
            break;  /* unmapped/invalid address — stop, use what we have */

        size_t chunk = (want - got < sizeof(long)) ? (want - got) : sizeof(long);
        memcpy(raw + got, &word, chunk);
        got += chunk;
    }

    if (got == 0) {
        snprintf(out, out_size, "0x%llx", addr);
        return;
    }

    size_t oi = 0;
    if (oi < out_size) out[oi++] = '"';
    for (size_t i = 0; i < got && oi + 5 < out_size; i++) {
        unsigned char c = raw[i];
        if (c == '"' || c == '\\') {
            out[oi++] = '\\';
            out[oi++] = (char)c;
        } else if (c == '\n') {
            out[oi++] = '\\'; out[oi++] = 'n';
        } else if (c >= 0x20 && c < 0x7f) {
            out[oi++] = (char)c;
        } else {
            oi += (size_t)snprintf(out + oi, out_size - oi, "\\x%02x", c);
        }
    }
    if (oi < out_size) out[oi++] = '"';
    if (len > got && oi + 3 < out_size) {  /* real buffer is longer than what we dumped */
        memcpy(out + oi, "...", 3);
        oi += 3;
    }
    if (oi < out_size) out[oi] = '\0';
    else out[out_size - 1] = '\0';
}

#if defined(__x86_64__)

typedef struct user_regs_struct arch_regs_t;

static int get_regs(pid_t child, arch_regs_t *regs) {
    return ptrace(PTRACE_GETREGS, child, NULL, regs);
}

static long syscall_no_of(const arch_regs_t *r)  { return r->orig_rax; }
static long return_val_of(const arch_regs_t *r)  { return r->rax; }
static unsigned long long arg0(const arch_regs_t *r) { return r->rdi; }
static unsigned long long arg1(const arch_regs_t *r) { return r->rsi; }
static unsigned long long arg2(const arch_regs_t *r) { return r->rdx; }
static unsigned long long arg3(const arch_regs_t *r) { return r->r10; }
static unsigned long long arg4(const arch_regs_t *r) { return r->r8; }
static unsigned long long arg5(const arch_regs_t *r) { return r->r9; }

#elif defined(__aarch64__)

typedef struct user_regs_struct arch_regs_t;

static int get_regs(pid_t child, arch_regs_t *regs) {
    struct iovec iov = { .iov_base = regs, .iov_len = sizeof(*regs) };
    return ptrace(PTRACE_GETREGSET, child, (void *)(long)NT_PRSTATUS_, &iov);
}

/* aarch64 keeps the syscall number in x8 for both entry and exit
 * stops (unlike x86-64's separate orig_rax vs rax), and the return
 * value comes back in x0 — which doubles as the first argument slot
 * on entry, so we only read it as a return value after the call. */
static long syscall_no_of(const arch_regs_t *r)  { return r->regs[8]; }
static long return_val_of(const arch_regs_t *r)  { return r->regs[0]; }
static unsigned long long arg0(const arch_regs_t *r) { return r->regs[0]; }
static unsigned long long arg1(const arch_regs_t *r) { return r->regs[1]; }
static unsigned long long arg2(const arch_regs_t *r) { return r->regs[2]; }
static unsigned long long arg3(const arch_regs_t *r) { return r->regs[3]; }
static unsigned long long arg4(const arch_regs_t *r) { return r->regs[4]; }
static unsigned long long arg5(const arch_regs_t *r) { return r->regs[5]; }

#else
#error "mini-strace only supports x86-64 and ARM64 (aarch64) Linux"
#endif

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

            if (show_timing || summary_mode)
                clock_gettime(CLOCK_MONOTONIC, &ts->entry_time);

            ts->suppressed = !syscall_allowed(name);

            if (ts->suppressed) {
                /* filtered out by -e trace=SET — don't print anything,
                 * but still track it through entry/exit like normal so
                 * the toggle stays in sync and pending state from a
                 * *previous* (allowed) read() doesn't leak in. */
                ts->pending_read_entry = NULL;
            } else if (read_entry != NULL) {
                /* read()-family: its buffer is unpopulated until the
                 * syscall actually runs, so there's nothing useful
                 * to dereference yet — stash everything and print
                 * the whole line at the exit-stop instead, once we
                 * know the real byte count from the return value. */
                ts->pending_name = name;
                memcpy(ts->pending_args, raw_args, sizeof(raw_args));
                ts->pending_read_entry = read_entry;
            } else {
                /* everything else prints immediately, same as before:
                 * known path-string args get dereferenced, write()'s
                 * buffer gets dumped, everything unrecognized prints
                 * as a raw hex address/value. */
                ts->pending_read_entry = NULL;
                if (!summary_mode) {
                    unsigned char str_mask = string_arg_mask(name);
                    unsigned char argv_mask = argv_arg_mask(name);
                    unsigned char fd_mask = show_fd_paths ? fd_arg_mask(name) : 0;
                    const buffer_arg_entry *buf_entry = buffer_arg_lookup(name);

                    char argbuf[6][STR_ARG_BUF_LEN];
                    for (int i = 0; i < 6; i++) {
                        if (str_mask & (1 << i))
                            read_child_string(wpid, raw_args[i], argbuf[i], sizeof(argbuf[i]));
                        else if (argv_mask & (1 << i))
                            read_child_argv(wpid, raw_args[i], argbuf[i], sizeof(argbuf[i]));
                        else if (buf_entry != NULL && i == buf_entry->buf_idx)
                            read_child_buffer(wpid, raw_args[i], raw_args[buf_entry->len_idx],
                                               argbuf[i], sizeof(argbuf[i]));
                        else
                            format_hex_or_fd_arg(wpid, raw_args[i], fd_mask & (1 << i),
                                                  argbuf[i], sizeof(argbuf[i]));
                    }

                    fprintf(trace_out, "%s%s(%s, %s, %s, %s, %s, %s) ",
                            pid_prefix, name, argbuf[0], argbuf[1], argbuf[2],
                            argbuf[3], argbuf[4], argbuf[5]);
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
                if (ts->pending_read_entry != NULL) {
                    /* this is the deferred read()-family print: build
                     * the whole "name(args) = ret" line now, using ret
                     * itself as the buffer length — that's the actual
                     * number of bytes the kernel put there, which is
                     * usually less than the requested count and is the
                     * only length we can trust at this point. Skipped
                     * entirely under -c, which never prints per-call
                     * lines. */
                    if (!summary_mode) {
                        unsigned char fd_mask = show_fd_paths ? fd_arg_mask(ts->pending_name) : 0;
                        char argbuf[6][STR_ARG_BUF_LEN];
                        for (int i = 0; i < 6; i++) {
                            if (i == ts->pending_read_entry->buf_idx && ret > 0)
                                read_child_buffer(wpid, ts->pending_args[i], (unsigned long long)ret,
                                                   argbuf[i], sizeof(argbuf[i]));
                            else
                                format_hex_or_fd_arg(wpid, ts->pending_args[i], fd_mask & (1 << i),
                                                      argbuf[i], sizeof(argbuf[i]));
                        }
                        fprintf(trace_out, "%s%s(%s, %s, %s, %s, %s, %s) ",
                                pid_prefix, ts->pending_name, argbuf[0], argbuf[1], argbuf[2],
                                argbuf[3], argbuf[4], argbuf[5]);
                    }
                    ts->pending_read_entry = NULL;
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
