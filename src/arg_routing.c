#define _GNU_SOURCE
#include <string.h>

#include "arg_routing.h"

/* Which arguments of which syscalls are NUL-terminated C-string
 * paths, as a bitmask over argument slots 0-5 (bit i set = arg i is
 * a char* path). Covers the common filesystem/exec syscalls; not
 * exhaustive — anything not in this table just prints as a raw hex
 * address, same as before. */
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

unsigned char string_arg_mask(const char *syscall) {
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
 * real fd) — resolve_fd_path() in decoders.c just skips negative
 * values. */
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
    { "mmap",         0x10 },  /* arg 4 (usually -1 for MAP_ANONYMOUS) */
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

unsigned char fd_arg_mask(const char *syscall) {
    for (int i = 0; fd_arg_table[i].name != NULL; i++) {
        if (strcmp(fd_arg_table[i].name, syscall) == 0)
            return fd_arg_table[i].str_args;
    }
    return 0;
}

/* Which arguments are argv[]/envp[]-style NULL-terminated arrays of
 * C-string pointers — just execve/execveat's argv and envp today.
 * Same bitmask-over-slots-0-5 shape as string_arg_table; read via
 * read_child_argv() (child_mem.c) instead of read_child_string()
 * since these are arrays of pointers, not a single string. */
static const string_arg_entry argv_arg_table[] = {
    { "execve",    0x06 },  /* args 1 (argv) and 2 (envp) */
    { "execveat",  0x0c },  /* args 2 (argv) and 3 (envp) */
    { NULL,        0x00 },
};

unsigned char argv_arg_mask(const char *syscall) {
    for (int i = 0; argv_arg_table[i].name != NULL; i++) {
        if (strcmp(argv_arg_table[i].name, syscall) == 0)
            return argv_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds open()/openat()'s flags — decoded via
 * format_open_flags() (decoders.c) instead of the generic hex
 * fallback. creat() isn't here: it has no flags argument, only a
 * mode. */
static const string_arg_entry open_flags_arg_table[] = {
    { "open",    0x02 },  /* arg 1 */
    { "openat",  0x04 },  /* arg 2 */
    { NULL,      0x00 },
};

unsigned char open_flags_arg_mask(const char *syscall) {
    for (int i = 0; open_flags_arg_table[i].name != NULL; i++) {
        if (strcmp(open_flags_arg_table[i].name, syscall) == 0)
            return open_flags_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds a PROT_ or MAP_ value — mmap has both (prot
 * and flags are separate arguments), mprotect only has prot. */
static const string_arg_entry prot_flags_arg_table[] = {
    { "mmap",      0x04 },  /* arg 2 */
    { "mprotect",  0x04 },  /* arg 2 */
    { NULL,        0x00 },
};

unsigned char prot_flags_arg_mask(const char *syscall) {
    for (int i = 0; prot_flags_arg_table[i].name != NULL; i++) {
        if (strcmp(prot_flags_arg_table[i].name, syscall) == 0)
            return prot_flags_arg_table[i].str_args;
    }
    return 0;
}

static const string_arg_entry map_flags_arg_table[] = {
    { "mmap",  0x08 },  /* arg 3 */
    { NULL,    0x00 },
};

unsigned char map_flags_arg_mask(const char *syscall) {
    for (int i = 0; map_flags_arg_table[i].name != NULL; i++) {
        if (strcmp(map_flags_arg_table[i].name, syscall) == 0)
            return map_flags_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds mount()'s flags, decoded via
 * format_mount_flags() in decoders.c. Populated by the caller
 * before the syscall runs, so this is dereferenced at the
 * entry-stop like every other plain-value flag argument in this
 * file, not deferred. */
static const string_arg_entry mount_flags_arg_table[] = {
    { "mount",  0x08 },  /* arg 3 */
    { NULL,     0x00 },
};

unsigned char mount_flags_arg_mask(const char *syscall) {
    for (int i = 0; mount_flags_arg_table[i].name != NULL; i++) {
        if (strcmp(mount_flags_arg_table[i].name, syscall) == 0)
            return mount_flags_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds socket()/socketpair()'s domain (arg 0) and
 * type (arg 1) — both syscalls share the same argument layout for
 * these two. */
static const string_arg_entry socket_domain_arg_table[] = {
    { "socket",      0x01 },  /* arg 0 */
    { "socketpair",  0x01 },  /* arg 0 */
    { NULL,          0x00 },
};

unsigned char socket_domain_arg_mask(const char *syscall) {
    for (int i = 0; socket_domain_arg_table[i].name != NULL; i++) {
        if (strcmp(socket_domain_arg_table[i].name, syscall) == 0)
            return socket_domain_arg_table[i].str_args;
    }
    return 0;
}

static const string_arg_entry socket_type_arg_table[] = {
    { "socket",      0x02 },  /* arg 1 */
    { "socketpair",  0x02 },  /* arg 1 */
    { NULL,          0x00 },
};

unsigned char socket_type_arg_mask(const char *syscall) {
    for (int i = 0; socket_type_arg_table[i].name != NULL; i++) {
        if (strcmp(socket_type_arg_table[i].name, syscall) == 0)
            return socket_type_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds kill()/tkill()/tgkill()'s target signal
 * number, or rt_sigaction()'s signal being configured, decoded via
 * format_signal_arg() (decoders.c). rt_sigaction's sig is never the
 * null signal in practice, but there's no need for a special case:
 * format_signal_arg() already treats 0 as its own real value. */
static const string_arg_entry signal_arg_table[] = {
    { "kill",          0x02 },  /* arg 1 */
    { "tkill",         0x02 },  /* arg 1 */
    { "tgkill",        0x04 },  /* arg 2 */
    { "rt_sigaction",  0x01 },  /* arg 0 */
    { NULL,            0x00 },
};

unsigned char signal_arg_mask(const char *syscall) {
    for (int i = 0; signal_arg_table[i].name != NULL; i++) {
        if (strcmp(signal_arg_table[i].name, syscall) == 0)
            return signal_arg_table[i].str_args;
    }
    return 0;
}

static const string_arg_entry lseek_whence_arg_table[] = {
    { "lseek",  0x04 },  /* arg 2 */
    { NULL,     0x00 },
};

unsigned char lseek_whence_arg_mask(const char *syscall) {
    for (int i = 0; lseek_whence_arg_table[i].name != NULL; i++) {
        if (strcmp(lseek_whence_arg_table[i].name, syscall) == 0)
            return lseek_whence_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds fcntl()'s cmd, decoded via
 * format_fcntl_cmd() (decoders.c). */
static const string_arg_entry fcntl_cmd_arg_table[] = {
    { "fcntl",  0x02 },  /* arg 1 */
    { NULL,     0x00 },
};

unsigned char fcntl_cmd_arg_mask(const char *syscall) {
    for (int i = 0; fcntl_cmd_arg_table[i].name != NULL; i++) {
        if (strcmp(fcntl_cmd_arg_table[i].name, syscall) == 0)
            return fcntl_cmd_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds rt_sigprocmask()'s how, decoded via
 * format_sigprocmask_how() (decoders.c). */
static const string_arg_entry sigprocmask_how_arg_table[] = {
    { "rt_sigprocmask",  0x01 },  /* arg 0 */
    { NULL,              0x00 },
};

unsigned char sigprocmask_how_arg_mask(const char *syscall) {
    for (int i = 0; sigprocmask_how_arg_table[i].name != NULL; i++) {
        if (strcmp(sigprocmask_how_arg_table[i].name, syscall) == 0)
            return sigprocmask_how_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds access()/faccessat()/faccessat2()'s mode,
 * decoded via format_access_mode() (decoders.c). */
static const string_arg_entry access_mode_arg_table[] = {
    { "access",      0x02 },  /* arg 1 */
    { "faccessat",   0x04 },  /* arg 2 */
    { "faccessat2",  0x04 },  /* arg 2 */
    { NULL,          0x00 },
};

unsigned char access_mode_arg_mask(const char *syscall) {
    for (int i = 0; access_mode_arg_table[i].name != NULL; i++) {
        if (strcmp(access_mode_arg_table[i].name, syscall) == 0)
            return access_mode_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds clock_gettime()/clock_settime()/
 * clock_getres()/clock_nanosleep()'s clockid, decoded via
 * format_clockid() (decoders.c) — all four take it as arg 0. */
static const string_arg_entry clockid_arg_table[] = {
    { "clock_gettime",     0x01 },
    { "clock_settime",     0x01 },
    { "clock_getres",      0x01 },
    { "clock_nanosleep",   0x01 },
    { NULL,                0x00 },
};

unsigned char clockid_arg_mask(const char *syscall) {
    for (int i = 0; clockid_arg_table[i].name != NULL; i++) {
        if (strcmp(clockid_arg_table[i].name, syscall) == 0)
            return clockid_arg_table[i].str_args;
    }
    return 0;
}

/* Syscalls whose input is a raw (not NUL-terminated) byte buffer,
 * paired with which argument slot holds the buffer and which slot
 * holds its length. Unlike string_arg_table this only covers
 * "output" syscalls — the buffer is already populated by the caller
 * before the syscall runs, so it can be dereferenced at the same
 * entry-stop as everything else. read()'s buffer is the opposite
 * case (empty until the syscall actually runs) and needs different
 * handling — see read_arg_table below. */
static const buffer_arg_entry buffer_arg_table[] = {
    { "write",    1, 2 },
    { "pwrite64", 1, 2 },
    { NULL,       0, 0 },
};

const buffer_arg_entry *buffer_arg_lookup(const char *syscall) {
    for (int i = 0; buffer_arg_table[i].name != NULL; i++) {
        if (strcmp(buffer_arg_table[i].name, syscall) == 0)
            return &buffer_arg_table[i];
    }
    return NULL;
}

/* Syscalls whose input is a struct sockaddr, paired with which
 * argument slot holds it and which holds its length — same shape as
 * buffer_arg_table, reused as-is since it's the same idea (a slot
 * that's already populated by the caller at entry, plus a length
 * slot). accept/getsockname/getpeername's sockaddr is the opposite
 * case (only filled in *after* the syscall runs, like read()'s
 * buffer) — see accept_arg_table below for those. */
static const buffer_arg_entry sockaddr_arg_table[] = {
    { "connect", 1, 2 },
    { "bind",    1, 2 },
    { "sendto",  4, 5 },
    { NULL,      0, 0 },
};

const buffer_arg_entry *sockaddr_arg_lookup(const char *syscall) {
    for (int i = 0; sockaddr_arg_table[i].name != NULL; i++) {
        if (strcmp(sockaddr_arg_table[i].name, syscall) == 0)
            return &sockaddr_arg_table[i];
    }
    return NULL;
}

/* Syscalls whose sockaddr argument is only populated *after* the
 * syscall runs — like read_arg_table below, but for a struct
 * sockaddr instead of a plain byte buffer. len_idx here points at a
 * socklen_t* (not a length value): the kernel writes the actual
 * struct size it produced through that pointer, which has to be
 * read back at the exit-stop to know how many bytes of the sockaddr
 * are real. recvfrom is also in read_arg_table below for its data
 * buffer — the exit-stop print in mini_strace.c combines both when a
 * syscall (only recvfrom, today) appears in both tables. */
static const buffer_arg_entry accept_arg_table[] = {
    { "accept",       1, 2 },
    { "accept4",      1, 2 },
    { "getsockname",  1, 2 },
    { "getpeername",  1, 2 },
    { "recvfrom",     4, 5 },
    { NULL,           0, 0 },
};

const buffer_arg_entry *accept_arg_lookup(const char *syscall) {
    for (int i = 0; accept_arg_table[i].name != NULL; i++) {
        if (strcmp(accept_arg_table[i].name, syscall) == 0)
            return &accept_arg_table[i];
    }
    return NULL;
}

/* wait4's wstatus is a third kind of exit-only-populated argument —
 * a plain int this time, not a buffer or a struct — so it gets its
 * own bitmask table (string_arg_entry's shape fits fine) rather than
 * reusing buffer_arg_entry, which carries a len_idx this doesn't
 * need. waitid() isn't covered: its equivalent is a siginfo_t, a
 * different and more involved decode. */
static const string_arg_entry wait_status_arg_table[] = {
    { "wait4", 0x02 },  /* arg 1 */
    { NULL,    0x00 },
};

unsigned char wait_status_arg_mask(const char *syscall) {
    for (int i = 0; wait_status_arg_table[i].name != NULL; i++) {
        if (strcmp(wait_status_arg_table[i].name, syscall) == 0)
            return wait_status_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds wait4's output struct rusage, decoded via
 * format_rusage() in decoders.c. Only populated once the syscall
 * actually returns, so like wait_status_arg_mask this is deferred
 * to the exit-stop, not dereferenced here. */
static const string_arg_entry rusage_arg_table[] = {
    { "wait4", 0x08 },  /* arg 3 */
    { NULL,    0x00 },
};

unsigned char rusage_arg_mask(const char *syscall) {
    for (int i = 0; rusage_arg_table[i].name != NULL; i++) {
        if (strcmp(rusage_arg_table[i].name, syscall) == 0)
            return rusage_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds stat/lstat/fstat/newfstatat's output struct
 * stat, decoded via format_stat_buf() in decoders.c. Like wait4's
 * wstatus, this is only populated once the syscall actually returns,
 * so it's deferred to the exit-stop the same way, not dereferenced
 * at entry. */
static const string_arg_entry stat_buf_arg_table[] = {
    { "stat",        0x02 },  /* arg 1 */
    { "lstat",       0x02 },  /* arg 1 */
    { "fstat",       0x02 },  /* arg 1 */
    { "newfstatat",  0x04 },  /* arg 2 */
    { NULL,          0x00 },
};

unsigned char stat_buf_arg_mask(const char *syscall) {
    for (int i = 0; stat_buf_arg_table[i].name != NULL; i++) {
        if (strcmp(stat_buf_arg_table[i].name, syscall) == 0)
            return stat_buf_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds getdents64()'s output buffer, decoded via
 * format_getdents_buf() in decoders.c. Like read()'s buffer, this
 * is only populated once the syscall actually runs, so it's
 * deferred to the exit-stop rather than dereferenced at entry. */
static const string_arg_entry getdents_buf_arg_table[] = {
    { "getdents64",  0x02 },  /* arg 1 */
    { NULL,          0x00 },
};

unsigned char getdents_buf_arg_mask(const char *syscall) {
    for (int i = 0; getdents_buf_arg_table[i].name != NULL; i++) {
        if (strcmp(getdents_buf_arg_table[i].name, syscall) == 0)
            return getdents_buf_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds clone()'s flags, decoded via
 * format_clone_flags() in decoders.c. Both x86-64 and aarch64 use
 * the same raw syscall argument order for clone (flags, stack,
 * parent_tid, child_tid, tls); a few older architectures reorder
 * these but neither of this project's two supported architectures
 * does. */
static const string_arg_entry clone_flags_arg_table[] = {
    { "clone",  0x01 },  /* arg 0 */
    { NULL,     0x00 },
};

unsigned char clone_flags_arg_mask(const char *syscall) {
    for (int i = 0; clone_flags_arg_table[i].name != NULL; i++) {
        if (strcmp(clone_flags_arg_table[i].name, syscall) == 0)
            return clone_flags_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds clone3()'s struct clone_args pointer,
 * decoded via format_clone3_flags() in decoders.c. Unlike
 * clone_flags_arg_table this is a pointer, not a plain value, but
 * it is populated by the caller before the syscall runs, so it can
 * be dereferenced at the entry-stop like the sockaddr arguments in
 * sockaddr_arg_table, not deferred to the exit-stop. */
static const string_arg_entry clone3_args_arg_table[] = {
    { "clone3",  0x01 },  /* arg 0 */
    { NULL,      0x00 },
};

unsigned char clone3_args_arg_mask(const char *syscall) {
    for (int i = 0; clone3_args_arg_table[i].name != NULL; i++) {
        if (strcmp(clone3_args_arg_table[i].name, syscall) == 0)
            return clone3_args_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds ioctl()'s request code, decoded via
 * format_ioctl_request() in decoders.c. ioctl's third argument
 * (the request-specific data, a struct pointer for most requests
 * covered by that table) is left as plain hex/fd — decoding it
 * would mean a separate struct layout per request, which is well
 * beyond what the request-code table above covers. */
static const string_arg_entry ioctl_request_arg_table[] = {
    { "ioctl",  0x02 },  /* arg 1 */
    { NULL,     0x00 },
};

unsigned char ioctl_request_arg_mask(const char *syscall) {
    for (int i = 0; ioctl_request_arg_table[i].name != NULL; i++) {
        if (strcmp(ioctl_request_arg_table[i].name, syscall) == 0)
            return ioctl_request_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds sendmsg()'s struct msghdr*, decoded via
 * format_msghdr() in decoders.c. sendmsg's msghdr is fully
 * populated by the caller before the syscall runs, so like
 * clone3_args_arg_table this is dereferenced at the entry-stop, not
 * deferred. */
static const string_arg_entry msghdr_send_arg_table[] = {
    { "sendmsg",  0x02 },  /* arg 1 */
    { NULL,       0x00 },
};

unsigned char msghdr_send_arg_mask(const char *syscall) {
    for (int i = 0; msghdr_send_arg_table[i].name != NULL; i++) {
        if (strcmp(msghdr_send_arg_table[i].name, syscall) == 0)
            return msghdr_send_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds recvmsg()'s struct msghdr*. Unlike sendmsg,
 * recvmsg's msghdr is only meaningful after the kernel has filled
 * it in, so this is looked up the same way wait_status_arg_mask is
 * and deferred to the exit-stop in mini_strace.c, not dereferenced
 * here. */
static const string_arg_entry msghdr_recv_arg_table[] = {
    { "recvmsg",  0x02 },  /* arg 1 */
    { NULL,       0x00 },
};

unsigned char msghdr_recv_arg_mask(const char *syscall) {
    for (int i = 0; msghdr_recv_arg_table[i].name != NULL; i++) {
        if (strcmp(msghdr_recv_arg_table[i].name, syscall) == 0)
            return msghdr_recv_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds rt_sigaction()'s new struct sigaction (act),
 * decoded via format_sigaction() in decoders.c. Populated by the
 * caller before the syscall runs, so this is dereferenced at the
 * entry-stop like clone3's clone_args, not deferred. */
static const string_arg_entry sigaction_new_arg_table[] = {
    { "rt_sigaction",  0x02 },  /* arg 1 */
    { NULL,            0x00 },
};

unsigned char sigaction_new_arg_mask(const char *syscall) {
    for (int i = 0; sigaction_new_arg_table[i].name != NULL; i++) {
        if (strcmp(sigaction_new_arg_table[i].name, syscall) == 0)
            return sigaction_new_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds rt_sigaction()'s old struct sigaction
 * (oldact). Unlike act, this is only filled in by the kernel once
 * the syscall returns, so it's deferred to the exit-stop the same
 * way stat_buf_arg_mask/getdents_buf_arg_mask are, not dereferenced
 * here. */
static const string_arg_entry sigaction_old_arg_table[] = {
    { "rt_sigaction",  0x04 },  /* arg 2 */
    { NULL,            0x00 },
};

unsigned char sigaction_old_arg_mask(const char *syscall) {
    for (int i = 0; sigaction_old_arg_table[i].name != NULL; i++) {
        if (strcmp(sigaction_old_arg_table[i].name, syscall) == 0)
            return sigaction_old_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds a struct timespec* that's already populated
 * by the caller before the syscall runs (clock_settime's new time,
 * nanosleep/clock_nanosleep's requested duration), decoded via
 * format_timespec() in decoders.c. */
static const string_arg_entry timespec_in_arg_table[] = {
    { "clock_settime",    0x02 },  /* arg 1 */
    { "nanosleep",        0x01 },  /* arg 0 (request) */
    { "clock_nanosleep",  0x04 },  /* arg 2 (request) */
    { NULL,               0x00 },
};

unsigned char timespec_in_arg_mask(const char *syscall) {
    for (int i = 0; timespec_in_arg_table[i].name != NULL; i++) {
        if (strcmp(timespec_in_arg_table[i].name, syscall) == 0)
            return timespec_in_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds a struct timespec* only populated by the
 * kernel once the syscall returns (clock_gettime's result;
 * nanosleep/clock_nanosleep's remaining time, meaningful only if
 * the sleep was interrupted). Deferred to the exit-stop like
 * stat_buf_arg_mask, not dereferenced here. */
static const string_arg_entry timespec_out_arg_table[] = {
    { "clock_gettime",    0x02 },  /* arg 1 */
    { "nanosleep",        0x02 },  /* arg 1 (remaining) */
    { "clock_nanosleep",  0x08 },  /* arg 3 (remaining) */
    { NULL,               0x00 },
};

unsigned char timespec_out_arg_mask(const char *syscall) {
    for (int i = 0; timespec_out_arg_table[i].name != NULL; i++) {
        if (strcmp(timespec_out_arg_table[i].name, syscall) == 0)
            return timespec_out_arg_table[i].str_args;
    }
    return 0;
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
    { "read",     1, 2 },
    { "pread64",  1, 2 },
    { "recvfrom", 1, 2 },  /* also in accept_arg_table above for its sockaddr */
    { NULL,       0, 0 },
};

const buffer_arg_entry *read_arg_lookup(const char *syscall) {
    for (int i = 0; read_arg_table[i].name != NULL; i++) {
        if (strcmp(read_arg_table[i].name, syscall) == 0)
            return &read_arg_table[i];
    }
    return NULL;
}

/* How many of the 6 raw argument slots a syscall actually has, so
 * mini_strace.c can print exactly that many instead of always all
 * 6 (most of which would otherwise be leftover register garbage —
 * access(path, mode) has never had more than 2 real arguments).
 * Counts are the *raw kernel syscall*'s arity, not the glibc
 * wrapper's — those occasionally differ (fchmodat's libc wrapper
 * takes a 4th "flags" argument that isn't part of the actual
 * fchmodat syscall and is silently dropped, or emulated by libc
 * without a flags-capable fchmodat kernel syscall at all; the raw
 * syscall this project actually traces only ever sees 3).
 *
 * Deliberately not exhaustive over every Linux syscall — that
 * would mean a table with hundreds of entries this project has no
 * way to verify against real behavior for the ones nobody's
 * traced. It covers every syscall this file already has dedicated
 * argument decoding for (their real signatures had to be known
 * anyway to write that decoding) plus a short list of syscalls
 * that show up in essentially every trace regardless of what's
 * being run (process startup bookkeeping, basic process/thread
 * info). Anything not listed here falls back to the old
 * behavior — all 6 slots shown — rather than guessing. */
static const syscall_argc_entry syscall_argc_table[] = {
    /* already-decoded syscalls, grouped the same way arg_routing's
     * other tables are: file/path operations first, then sockets,
     * then everything else. */
    { "access",         2 },
    { "faccessat",      3 },
    { "faccessat2",     4 },
    { "chdir",          1 },
    { "chmod",          2 },
    { "fchmod",         2 },
    { "fchmodat",       3 },
    { "chown",          3 },
    { "fchown",         3 },
    { "fchownat",       5 },
    { "lchown",         3 },
    { "chroot",         1 },
    { "creat",          2 },
    { "open",           3 },
    { "openat",         4 },
    { "close",          1 },
    { "read",           3 },
    { "write",          3 },
    { "pread64",        4 },
    { "pwrite64",       4 },
    { "lseek",          3 },
    { "fcntl",          3 },
    { "flock",          2 },
    { "fsync",          1 },
    { "fdatasync",      1 },
    { "ftruncate",      2 },
    { "truncate",       2 },
    { "stat",           2 },
    { "lstat",          2 },
    { "fstat",          2 },
    { "newfstatat",     4 },
    { "statx",          5 },
    { "statfs",         2 },
    { "fstatfs",        2 },
    { "readlink",       3 },
    { "readlinkat",     4 },
    { "symlink",        2 },
    { "symlinkat",      3 },
    { "link",           2 },
    { "linkat",         5 },
    { "rename",         2 },
    { "renameat",       4 },
    { "renameat2",      5 },
    { "unlink",         1 },
    { "unlinkat",       3 },
    { "mkdir",          2 },
    { "mkdirat",        3 },
    { "rmdir",          1 },
    { "utime",          2 },
    { "utimes",         2 },
    { "futimesat",      3 },
    { "mount",          5 },
    { "umount2",        2 },
    { "pivot_root",     2 },
    { "execve",         3 },
    { "execveat",       5 },
    { "dup",            1 },
    { "dup2",           2 },
    { "dup3",           3 },
    { "mmap",           6 },
    { "mprotect",       3 },
    { "kill",           2 },
    { "tkill",          2 },
    { "tgkill",         3 },
    { "wait4",          4 },
    { "clock_gettime",  2 },
    { "clock_settime",  2 },
    { "clock_getres",   2 },
    { "clock_nanosleep", 4 },
    { "rt_sigprocmask", 4 },
    { "clone",          5 },
    { "clone3",         2 },
    { "ioctl",          3 },
    /* socket family */
    { "socket",         3 },
    { "socketpair",     4 },
    { "bind",           3 },
    { "listen",         2 },
    { "accept",         3 },
    { "accept4",        4 },
    { "connect",        3 },
    { "getsockname",    3 },
    { "getpeername",    3 },
    { "setsockopt",     5 },
    { "getsockopt",     5 },
    { "shutdown",       2 },
    { "sendto",         6 },
    { "recvfrom",       6 },
    { "sendmsg",        3 },
    { "recvmsg",        3 },

    /* not otherwise decoded, but common enough (process startup,
     * basic process/thread info) to be worth the same treatment. */
    { "brk",            1 },
    { "munmap",         2 },
    { "arch_prctl",     2 },
    { "set_tid_address", 1 },
    { "set_robust_list", 2 },
    { "rseq",           4 },
    { "prlimit64",      4 },
    { "getrandom",      3 },
    { "rt_sigaction",   4 },
    { "rt_sigreturn",   0 },
    { "sched_yield",    0 },
    { "madvise",        3 },
    { "poll",           3 },
    { "pipe",           1 },
    { "pipe2",          2 },
    { "getcwd",         2 },
    { "getdents64",     3 },
    { "prctl",          5 },
    { "alarm",          1 },
    { "pause",          0 },
    { "nanosleep",      2 },
    { "sync",           0 },
    { "exit",           1 },
    { "exit_group",     1 },
    { "fork",           0 },
    { "vfork",          0 },
    { "getuid",         0 },
    { "getgid",         0 },
    { "geteuid",        0 },
    { "getegid",        0 },
    { "getpid",         0 },
    { "getppid",        0 },
    { "gettid",         0 },

    { NULL,             0 },
};

int syscall_argc(const char *syscall) {
    for (int i = 0; syscall_argc_table[i].name != NULL; i++) {
        if (strcmp(syscall_argc_table[i].name, syscall) == 0)
            return syscall_argc_table[i].argc;
    }
    return -1;
}
