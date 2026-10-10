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
    { "memfd_create", 0x01 },
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

/* Which arguments are the directory fd of an *at() syscall, decoded
 * via format_dirfd() (AT_FDCWD by name). Independent of fd_arg_table
 * above: that one only applies under -y, while AT_FDCWD is shown
 * unconditionally. Some syscalls have two (renameat's olddirfd and
 * newdirfd). */
static const string_arg_entry dirfd_arg_table[] = {
    { "openat",            0x01 },
    { "openat2",           0x01 },
    { "faccessat",         0x01 },
    { "faccessat2",        0x01 },
    { "unlinkat",          0x01 },
    { "mkdirat",           0x01 },
    { "mknodat",           0x01 },
    { "renameat",          0x05 },  /* args 0 and 2 */
    { "renameat2",         0x05 },
    { "newfstatat",        0x01 },
    { "statx",             0x01 },
    { "readlinkat",        0x01 },
    { "fchmodat",          0x01 },
    { "fchmodat2",         0x01 },
    { "fchownat",          0x01 },
    { "symlinkat",         0x02 },  /* arg 1 (newdirfd) */
    { "linkat",            0x05 },  /* args 0 and 2 */
    { "futimesat",         0x01 },
    { "utimensat",         0x01 },
    { "execveat",          0x01 },
    { "name_to_handle_at", 0x01 },
    { NULL,                0x00 },
};

unsigned char dirfd_arg_mask(const char *syscall) {
    for (int i = 0; dirfd_arg_table[i].name != NULL; i++) {
        if (strcmp(dirfd_arg_table[i].name, syscall) == 0)
            return dirfd_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds the AT_* flags of an *at() syscall, decoded
 * via format_at_flags() (decoders.c). unlinkat and faccessat2 are in
 * their own tables because bit 0x200 means AT_REMOVEDIR for one and
 * AT_EACCESS for the other. faccessat and fchmodat have no flags
 * argument at the syscall level (glibc emulates theirs in userspace),
 * so they aren't listed. */
static const string_arg_entry at_flags_arg_table[] = {
    { "newfstatat",  0x08 },  /* arg 3 */
    { "statx",       0x04 },  /* arg 2 */
    { "linkat",      0x10 },  /* arg 4 */
    { "utimensat",   0x08 },  /* arg 3 */
    { "fchmodat2",   0x08 },  /* arg 3 */
    { "fchownat",    0x10 },  /* arg 4 */
    { "execveat",    0x10 },  /* arg 4 */
    { NULL,          0x00 },
};

unsigned char at_flags_arg_mask(const char *syscall) {
    for (int i = 0; at_flags_arg_table[i].name != NULL; i++) {
        if (strcmp(at_flags_arg_table[i].name, syscall) == 0)
            return at_flags_arg_table[i].str_args;
    }
    return 0;
}

static const string_arg_entry unlinkat_flags_arg_table[] = {
    { "unlinkat", 0x04 },  /* arg 2 */
    { NULL,       0x00 },
};

unsigned char unlinkat_flags_arg_mask(const char *syscall) {
    for (int i = 0; unlinkat_flags_arg_table[i].name != NULL; i++) {
        if (strcmp(unlinkat_flags_arg_table[i].name, syscall) == 0)
            return unlinkat_flags_arg_table[i].str_args;
    }
    return 0;
}

static const string_arg_entry faccessat_flags_arg_table[] = {
    { "faccessat2", 0x08 },  /* arg 3 */
    { NULL,         0x00 },
};

unsigned char faccessat_flags_arg_mask(const char *syscall) {
    for (int i = 0; faccessat_flags_arg_table[i].name != NULL; i++) {
        if (strcmp(faccessat_flags_arg_table[i].name, syscall) == 0)
            return faccessat_flags_arg_table[i].str_args;
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

/* Which argument holds setsockopt()/getsockopt()'s level, decoded
 * via format_sockopt_level() in decoders.c. Populated by the caller
 * before the syscall runs, dereferenced at the entry-stop like
 * every other plain-value lookup in this file. */
static const string_arg_entry sockopt_level_arg_table[] = {
    { "setsockopt",  0x02 },  /* arg 1 */
    { "getsockopt",  0x02 },  /* arg 1 */
    { NULL,          0x00 },
};

unsigned char sockopt_level_arg_mask(const char *syscall) {
    for (int i = 0; sockopt_level_arg_table[i].name != NULL; i++) {
        if (strcmp(sockopt_level_arg_table[i].name, syscall) == 0)
            return sockopt_level_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds setsockopt()/getsockopt()'s optname, decoded
 * via format_sockopt_optname() in decoders.c. Always immediately
 * follows level for both syscalls (level, optname, ...), so
 * mini_strace.c reads raw_args[i-1] for the level value rather than
 * needing a separate len_idx-style lookup. */
static const string_arg_entry sockopt_optname_arg_table[] = {
    { "setsockopt",  0x04 },  /* arg 2 */
    { "getsockopt",  0x04 },  /* arg 2 */
    { NULL,          0x00 },
};

unsigned char sockopt_optname_arg_mask(const char *syscall) {
    for (int i = 0; sockopt_optname_arg_table[i].name != NULL; i++) {
        if (strcmp(sockopt_optname_arg_table[i].name, syscall) == 0)
            return sockopt_optname_arg_table[i].str_args;
    }
    return 0;
}

/* Which arguments hold select()'s/pselect6()'s readfds/writefds/
 * exceptfds, decoded via format_fdset_buf() in decoders.c. nfds is
 * arg 0 in both syscalls, so mini_strace.c reads raw_args[0]
 * directly rather than needing a separate lookup for it. */
static const string_arg_entry fdset_arg_table[] = {
    { "select",   0x0e },  /* args 1, 2, 3 */
    { "pselect6", 0x0e },  /* args 1, 2, 3 */
    { NULL,       0x00 },
};

unsigned char fdset_arg_mask(const char *syscall) {
    for (int i = 0; fdset_arg_table[i].name != NULL; i++) {
        if (strcmp(fdset_arg_table[i].name, syscall) == 0)
            return fdset_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds sendto()'s/recvfrom()'s/sendmsg()'s/
 * recvmsg()'s own flags argument, decoded via format_msg_flags() in
 * decoders.c. sendto/recvfrom carry it at index 3 (after fd, buf,
 * len); sendmsg/recvmsg at index 2 (after fd, msg) — the same
 * MSG_* namespace either way. */
static const string_arg_entry msg_flags_arg_table[] = {
    { "sendto",    0x08 },  /* arg 3 */
    { "recvfrom",  0x08 },  /* arg 3 */
    { "sendmsg",   0x04 },  /* arg 2 */
    { "recvmsg",   0x04 },  /* arg 2 */
    { NULL,        0x00 },
};

unsigned char msg_flags_arg_mask(const char *syscall) {
    for (int i = 0; msg_flags_arg_table[i].name != NULL; i++) {
        if (strcmp(msg_flags_arg_table[i].name, syscall) == 0)
            return msg_flags_arg_table[i].str_args;
    }
    return 0;
}

/* Single-argument decode masks for five more syscalls, each a
 * one-entry-per-name table with the same linear scan: pipe2's flags
 * (arg 1), getrandom's flags (arg 2), flock's operation (arg 1),
 * madvise's advice (arg 2) and futex's op (arg 1). All immediate:
 * none of these syscalls has a kernel-populated argument this
 * project decodes, so none of them takes the deferred path. */
static unsigned char mask_lookup(const string_arg_entry *table, const char *syscall) {
    for (int i = 0; table[i].name != NULL; i++) {
        if (strcmp(table[i].name, syscall) == 0)
            return table[i].str_args;
    }
    return 0;
}

/* Which argument is a plain permission mode (octal), decoded via
 * format_file_mode(): chmod/fchmod/fchmodat/fchmodat2/mkdir/mkdirat/
 * mknod/mknodat/creat/umask. */
static const string_arg_entry file_mode_arg_table[] = {
    { "chmod",     0x02 },  /* arg 1 */
    { "fchmod",    0x02 },  /* arg 1 */
    { "fchmodat",  0x04 },  /* arg 2 */
    { "fchmodat2", 0x04 },  /* arg 2 */
    { "mkdir",     0x02 },  /* arg 1 */
    { "mkdirat",   0x04 },  /* arg 2 */
    { "mknod",     0x02 },  /* arg 1 */
    { "mknodat",   0x04 },  /* arg 2 */
    { "creat",     0x02 },  /* arg 1 */
    { "umask",     0x01 },  /* arg 0 */
    { NULL,        0x00 },
};
unsigned char file_mode_arg_mask(const char *syscall) {
    return mask_lookup(file_mode_arg_table, syscall);
}

/* open()'s arg 2 / openat()'s arg 3: the mode that only means
 * something when the flags (the argument right before it) create a
 * file, decoded via format_open_mode(), which looks at that sibling. */
static const string_arg_entry open_mode_arg_table[] = {
    { "open",   0x04 },  /* arg 2 */
    { "openat", 0x08 },  /* arg 3 */
    { NULL,     0x00 },
};
unsigned char open_mode_arg_mask(const char *syscall) {
    return mask_lookup(open_mode_arg_table, syscall);
}

/* renameat2's flags (arg 4), mremap's flags (arg 3), memfd_create's
 * flags (arg 1), eventfd2's flags (arg 1), and the resource argument
 * of getrlimit/setrlimit (arg 0) and prlimit64 (arg 1). All
 * immediate. */
static const string_arg_entry renameat2_flags_arg_table[] = {
    { "renameat2", 0x10 },  /* arg 4 */
    { NULL,        0x00 },
};
unsigned char renameat2_flags_arg_mask(const char *syscall) {
    return mask_lookup(renameat2_flags_arg_table, syscall);
}

static const string_arg_entry mremap_flags_arg_table[] = {
    { "mremap", 0x08 },  /* arg 3 */
    { NULL,     0x00 },
};
unsigned char mremap_flags_arg_mask(const char *syscall) {
    return mask_lookup(mremap_flags_arg_table, syscall);
}

static const string_arg_entry memfd_flags_arg_table[] = {
    { "memfd_create", 0x02 },  /* arg 1 */
    { NULL,           0x00 },
};
unsigned char memfd_flags_arg_mask(const char *syscall) {
    return mask_lookup(memfd_flags_arg_table, syscall);
}

static const string_arg_entry eventfd_flags_arg_table[] = {
    { "eventfd2", 0x02 },  /* arg 1 */
    { NULL,       0x00 },
};
unsigned char eventfd_flags_arg_mask(const char *syscall) {
    return mask_lookup(eventfd_flags_arg_table, syscall);
}

/* wait4's options (arg 2), waitid's idtype (arg 0) and options
 * (arg 3), sched_setscheduler's policy (arg 1). wait4 is always
 * deferred (its wstatus and rusage are kernel-populated), so its
 * options are only ever dispatched from the exit-stop loop in
 * mini_strace.c; the other three are immediate. */
static const string_arg_entry wait4_options_arg_table[] = {
    { "wait4", 0x04 },  /* arg 2 */
    { NULL,    0x00 },
};
unsigned char wait4_options_arg_mask(const char *syscall) {
    return mask_lookup(wait4_options_arg_table, syscall);
}

static const string_arg_entry waitid_idtype_arg_table[] = {
    { "waitid", 0x01 },  /* arg 0 */
    { NULL,     0x00 },
};
unsigned char waitid_idtype_arg_mask(const char *syscall) {
    return mask_lookup(waitid_idtype_arg_table, syscall);
}

static const string_arg_entry waitid_options_arg_table[] = {
    { "waitid", 0x08 },  /* arg 3 */
    { NULL,     0x00 },
};
unsigned char waitid_options_arg_mask(const char *syscall) {
    return mask_lookup(waitid_options_arg_table, syscall);
}

static const string_arg_entry sched_policy_arg_table[] = {
    { "sched_setscheduler", 0x02 },  /* arg 1 */
    { NULL,                 0x00 },
};
unsigned char sched_policy_arg_mask(const char *syscall) {
    return mask_lookup(sched_policy_arg_table, syscall);
}

/* getrusage's who (arg 0). getrusage is always deferred (its rusage
 * is kernel-populated), so this is only dispatched from the exit-stop
 * loop. */
static const string_arg_entry rusage_who_arg_table[] = {
    { "getrusage", 0x01 },  /* arg 0 */
    { NULL,        0x00 },
};
unsigned char rusage_who_arg_mask(const char *syscall) {
    return mask_lookup(rusage_who_arg_table, syscall);
}

/* struct rlimit arguments, decoded via format_rlimit(). Two tables
 * because of direction: _in is caller-populated (setrlimit's rlim,
 * prlimit64's new_limit), _out is written by the kernel and deferred
 * to the exit-stop (getrlimit's rlim, prlimit64's old_limit).
 * prlimit64 appears in both, which also means it is always deferred:
 * its _in struct is then decoded from the exit-stop loop too, the
 * same always-deferred situation as nanosleep's requested time. */
static const string_arg_entry rlimit_in_arg_table[] = {
    { "setrlimit", 0x02 },  /* arg 1 */
    { "prlimit64", 0x04 },  /* arg 2 */
    { NULL,        0x00 },
};
unsigned char rlimit_in_arg_mask(const char *syscall) {
    return mask_lookup(rlimit_in_arg_table, syscall);
}

static const string_arg_entry rlimit_out_arg_table[] = {
    { "getrlimit", 0x02 },  /* arg 1 */
    { "prlimit64", 0x08 },  /* arg 3 */
    { NULL,        0x00 },
};
unsigned char rlimit_out_arg_mask(const char *syscall) {
    return mask_lookup(rlimit_out_arg_table, syscall);
}

static const string_arg_entry rlimit_resource_arg_table[] = {
    { "getrlimit", 0x01 },  /* arg 0 */
    { "setrlimit", 0x01 },  /* arg 0 */
    { "prlimit64", 0x02 },  /* arg 1 */
    { NULL,        0x00 },
};
unsigned char rlimit_resource_arg_mask(const char *syscall) {
    return mask_lookup(rlimit_resource_arg_table, syscall);
}

static const string_arg_entry pipe2_flags_arg_table[] = {
    { "pipe2", 0x02 },  /* arg 1 */
    { NULL,    0x00 },
};
unsigned char pipe2_flags_arg_mask(const char *syscall) {
    return mask_lookup(pipe2_flags_arg_table, syscall);
}

static const string_arg_entry getrandom_flags_arg_table[] = {
    { "getrandom", 0x04 },  /* arg 2 */
    { NULL,        0x00 },
};
unsigned char getrandom_flags_arg_mask(const char *syscall) {
    return mask_lookup(getrandom_flags_arg_table, syscall);
}

static const string_arg_entry flock_op_arg_table[] = {
    { "flock", 0x02 },  /* arg 1 */
    { NULL,    0x00 },
};
unsigned char flock_op_arg_mask(const char *syscall) {
    return mask_lookup(flock_op_arg_table, syscall);
}

static const string_arg_entry madvise_advice_arg_table[] = {
    { "madvise", 0x04 },  /* arg 2 */
    { NULL,      0x00 },
};
unsigned char madvise_advice_arg_mask(const char *syscall) {
    return mask_lookup(madvise_advice_arg_table, syscall);
}

static const string_arg_entry futex_op_arg_table[] = {
    { "futex", 0x02 },  /* arg 1 */
    { NULL,    0x00 },
};
unsigned char futex_op_arg_mask(const char *syscall) {
    return mask_lookup(futex_op_arg_table, syscall);
}

/* Which argument holds prctl()'s option, decoded via
 * format_prctl_option() in decoders.c. */
static const string_arg_entry prctl_option_arg_table[] = {
    { "prctl", 0x01 },  /* arg 0 */
    { NULL,    0x00 },
};

unsigned char prctl_option_arg_mask(const char *syscall) {
    for (int i = 0; prctl_option_arg_table[i].name != NULL; i++) {
        if (strcmp(prctl_option_arg_table[i].name, syscall) == 0)
            return prctl_option_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds prctl()'s arg2, decoded via
 * format_prctl_name_arg() in decoders.c. Always immediately follows
 * option for prctl, so mini_strace.c reads raw_args[i - 1] for the
 * option value rather than needing a separate lookup for it — same
 * shape as sockopt_optname_arg_table above. */
static const string_arg_entry prctl_name_arg_table[] = {
    { "prctl", 0x02 },  /* arg 1 */
    { NULL,    0x00 },
};

unsigned char prctl_name_arg_mask(const char *syscall) {
    for (int i = 0; prctl_name_arg_table[i].name != NULL; i++) {
        if (strcmp(prctl_name_arg_table[i].name, syscall) == 0)
            return prctl_name_arg_table[i].str_args;
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

/* writev's iov argument (buf_idx) and its sibling iovcnt (reusing
 * len_idx for a count, not a byte length — the same repurposing
 * pollfds_arg_table below does for nfds), decoded via
 * format_iovec_buf(). writev's data is the caller's own outgoing
 * buffers, already fully populated before the syscall runs, so —
 * like write()'s own single buffer above — it's looked up from the
 * entry-stop's immediate dispatch. readv's is only meaningful after
 * the syscall returns and gets its own lookup below instead, the
 * same split read()/write() already have. */
static const buffer_arg_entry iovec_write_arg_table[] = {
    { "writev", 1, 2 },
    { NULL,     0, 0 },
};

const buffer_arg_entry *iovec_write_arg_lookup(const char *syscall) {
    for (int i = 0; iovec_write_arg_table[i].name != NULL; i++) {
        if (strcmp(iovec_write_arg_table[i].name, syscall) == 0)
            return &iovec_write_arg_table[i];
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
    { "wait4",     0x08 },  /* arg 3 */
    { "getrusage", 0x02 },  /* arg 1 */
    { NULL,        0x00 },
};

unsigned char rusage_arg_mask(const char *syscall) {
    for (int i = 0; rusage_arg_table[i].name != NULL; i++) {
        if (strcmp(rusage_arg_table[i].name, syscall) == 0)
            return rusage_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds epoll_ctl()'s op, decoded via
 * format_epoll_op() in decoders.c. */
static const string_arg_entry epoll_op_arg_table[] = {
    { "epoll_ctl", 0x02 },  /* arg 1 */
    { NULL,        0x00 },
};

unsigned char epoll_op_arg_mask(const char *syscall) {
    for (int i = 0; epoll_op_arg_table[i].name != NULL; i++) {
        if (strcmp(epoll_op_arg_table[i].name, syscall) == 0)
            return epoll_op_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds epoll_ctl()'s struct epoll_event*, decoded
 * via format_epoll_event() in decoders.c. Populated by the caller
 * before the syscall runs, so this is dereferenced at the
 * entry-stop like clone3's clone_args, not deferred. */
static const string_arg_entry epoll_event_arg_table[] = {
    { "epoll_ctl", 0x08 },  /* arg 3 */
    { NULL,        0x00 },
};

unsigned char epoll_event_arg_mask(const char *syscall) {
    for (int i = 0; epoll_event_arg_table[i].name != NULL; i++) {
        if (strcmp(epoll_event_arg_table[i].name, syscall) == 0)
            return epoll_event_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds epoll_wait()'s output array of struct
 * epoll_event, decoded via format_epoll_events_buf() in
 * decoders.c. Only populated once the syscall actually returns, so
 * like stat_buf_arg_mask this is deferred to the exit-stop, not
 * dereferenced here. epoll_pwait is included at the same argument
 * index: glibc's epoll_wait() compiles down to a call to the
 * epoll_pwait syscall (with a NULL sigmask) rather than the
 * epoll_wait syscall, the same kind of libc-wrapper-picks-a-
 * different-syscall situation access()/faccessat() and
 * nanosleep()/clock_nanosleep() are already in. */
static const string_arg_entry epoll_events_arg_table[] = {
    { "epoll_wait",  0x02 },  /* arg 1 */
    { "epoll_pwait", 0x02 },  /* arg 1 */
    { NULL,          0x00 },
};

unsigned char epoll_events_arg_mask(const char *syscall) {
    for (int i = 0; epoll_events_arg_table[i].name != NULL; i++) {
        if (strcmp(epoll_events_arg_table[i].name, syscall) == 0)
            return epoll_events_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds poll()'s fds array and which holds nfds (the
 * array's length), decoded via format_pollfds_buf() in decoders.c.
 * Reuses buffer_arg_entry's "one arg is a buffer, another holds its
 * length" shape even though nfds isn't itself deferred — it's a
 * plain caller-supplied count, but the array it describes still
 * needs deferring to the exit-stop for revents, so this is looked
 * up the same way accept_arg_table's deferred buf+length pairs are,
 * not sockaddr_arg_table's entry-populated ones. ppoll is included
 * at the same argument indices: glibc's poll() compiles down to a
 * call to the ppoll syscall (with a NULL timeout/sigmask), the same
 * libc-wrapper-picks-a-different-syscall situation already seen
 * with access()/faccessat(), nanosleep()/clock_nanosleep(), and
 * epoll_wait()/epoll_pwait(). */
static const buffer_arg_entry pollfds_arg_table[] = {
    { "poll",  0, 1 },
    { "ppoll", 0, 1 },
    { NULL,    0, 0 },
};

const buffer_arg_entry *pollfds_arg_lookup(const char *syscall) {
    for (int i = 0; pollfds_arg_table[i].name != NULL; i++) {
        if (strcmp(pollfds_arg_table[i].name, syscall) == 0)
            return &pollfds_arg_table[i];
    }
    return NULL;
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

/* Which argument holds statx()'s mask, decoded via
 * format_statx_mask() in decoders.c. Populated by the caller before
 * the syscall runs, but statx's other argument (statxbuf) always
 * routes the whole call through the deferred path — routing is
 * keyed on syscall name, and statx always has a struct statx*
 * argument — so unlike a true entry-only mask this is only ever
 * dispatched from the exit-stop's loop, the same situation
 * clock_gettime/clock_nanosleep's clockid ended up in. */
static const string_arg_entry statx_mask_arg_table[] = {
    { "statx", 0x08 },  /* arg 3 */
    { NULL,    0x00 },
};

unsigned char statx_mask_arg_mask(const char *syscall) {
    for (int i = 0; statx_mask_arg_table[i].name != NULL; i++) {
        if (strcmp(statx_mask_arg_table[i].name, syscall) == 0)
            return statx_mask_arg_table[i].str_args;
    }
    return 0;
}

/* Which argument holds statx()'s output struct statx, decoded via
 * format_statx_buf() in decoders.c. Only populated once the syscall
 * actually returns, so like stat_buf_arg_mask this is deferred to
 * the exit-stop, not dereferenced here. */
static const string_arg_entry statx_buf_arg_table[] = {
    { "statx", 0x10 },  /* arg 4 */
    { NULL,    0x00 },
};

unsigned char statx_buf_arg_mask(const char *syscall) {
    for (int i = 0; statx_buf_arg_table[i].name != NULL; i++) {
        if (strcmp(statx_buf_arg_table[i].name, syscall) == 0)
            return statx_buf_arg_table[i].str_args;
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

/* readv's iov argument and its sibling iovcnt — the deferred
 * counterpart of iovec_write_arg_table above. Unlike read_arg_table,
 * len_idx here is genuinely used (it's iovcnt, the array length the
 * caller declared, the same way pollfds_arg_table's nfds is used —
 * not a byte count the return value would replace). */
static const buffer_arg_entry iovec_read_arg_table[] = {
    { "readv", 1, 2 },
    { NULL,    0, 0 },
};

const buffer_arg_entry *iovec_read_arg_lookup(const char *syscall) {
    for (int i = 0; iovec_read_arg_table[i].name != NULL; i++) {
        if (strcmp(iovec_read_arg_table[i].name, syscall) == 0)
            return &iovec_read_arg_table[i];
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
    { "umask",          1 },
    { "mremap",         5 },
    { "memfd_create",   2 },
    { "eventfd2",       2 },
    { "getrlimit",      2 },
    { "setrlimit",      2 },
    { "readv",          3 },
    { "writev",         3 },
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
    { "ppoll",          5 },  /* fds, nfds, tmo_p, sigmask, sigsetsize */
    { "select",         5 },  /* nfds, readfds, writefds, exceptfds, timeout */
    { "pselect6",       6 },  /* nfds, readfds, writefds, exceptfds, timeout, sigmask */
    { "epoll_ctl",      4 },
    { "epoll_wait",     4 },
    { "epoll_pwait",    6 },  /* epfd, events, maxevents, timeout, sigmask, sigsetsize */
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

    /* Arity-only entries: syscalls with no dedicated argument
     * decoding, listed so they print their real argument count
     * instead of all six slots. Counts are the kernel's
     * SYSCALL_DEFINEn arities. Deliberately left out: the newest
     * syscalls whose signatures this project has not verified
     * (lsm_*, statmount, listmount, the futex_wait family,
     * map_shadow_stack), the removed nfsservctl, and the
     * arch_specific_syscall placeholder. Those still fall back to
     * six slots. */
    { "io_setup",       2 }, { "io_destroy",      1 }, { "io_submit",      3 },
    { "io_cancel",      3 }, { "io_getevents",    5 }, { "io_pgetevents",  6 },
    { "setxattr",       5 }, { "lsetxattr",       5 }, { "fsetxattr",      5 },
    { "getxattr",       4 }, { "lgetxattr",       4 }, { "fgetxattr",      4 },
    { "listxattr",      3 }, { "llistxattr",      3 }, { "flistxattr",     3 },
    { "removexattr",    2 }, { "lremovexattr",    2 }, { "fremovexattr",   2 },
    { "lookup_dcookie", 3 }, { "epoll_create",    1 }, { "epoll_create1",  1 },
    { "inotify_init",   0 }, { "inotify_init1",   1 }, { "inotify_add_watch", 3 },
    { "inotify_rm_watch", 2 }, { "ioprio_set",    3 }, { "ioprio_get",     2 },
    { "mknod",          3 }, { "mknodat",         4 }, { "fallocate",      4 },
    { "fchdir",         1 }, { "vhangup",         0 }, { "quotactl",       4 },
    { "preadv",         5 }, { "pwritev",         5 }, { "preadv2",        6 },
    { "pwritev2",       6 }, { "sendfile",        4 }, { "signalfd",       3 },
    { "signalfd4",      4 }, { "eventfd",         2 }, { "vmsplice",       4 },
    { "splice",         6 }, { "tee",             4 }, { "sync_file_range", 4 },
    { "timerfd_create", 2 }, { "timerfd_settime", 4 }, { "timerfd_gettime", 2 },
    { "utimensat",      4 }, { "acct",            1 }, { "capget",         2 },
    { "capset",         2 }, { "personality",     1 }, { "waitid",         5 },
    { "unshare",        1 }, { "futex",           6 }, { "get_robust_list", 3 },
    { "getitimer",      2 }, { "setitimer",       3 }, { "kexec_load",     4 },
    { "init_module",    3 }, { "finit_module",    3 }, { "delete_module",  2 },
    { "timer_create",   3 }, { "timer_gettime",   2 }, { "timer_getoverrun", 1 },
    { "timer_settime",  4 }, { "timer_delete",    1 }, { "syslog",         3 },
    { "ptrace",         4 }, { "sched_setparam",  2 }, { "sched_setscheduler", 3 },
    { "sched_getscheduler", 1 }, { "sched_getparam", 2 }, { "sched_setaffinity", 3 },
    { "sched_getaffinity", 3 }, { "sched_get_priority_max", 1 },
    { "sched_get_priority_min", 1 }, { "sched_rr_get_interval", 2 },
    { "restart_syscall", 0 }, { "sigaltstack",    2 }, { "rt_sigsuspend",  2 },
    { "rt_sigpending",  2 }, { "rt_sigtimedwait", 4 }, { "rt_sigqueueinfo", 3 },
    { "rt_tgsigqueueinfo", 4 }, { "setpriority",  3 }, { "getpriority",    2 },
    { "reboot",         4 }, { "setregid",        2 }, { "setgid",         1 },
    { "setreuid",       2 }, { "setuid",          1 }, { "setresuid",      3 },
    { "getresuid",      3 }, { "setresgid",       3 }, { "getresgid",      3 },
    { "setfsuid",       1 }, { "setfsgid",        1 }, { "times",          1 },
    { "setpgid",        2 }, { "getpgid",         1 }, { "getpgrp",        0 },
    { "getsid",         1 }, { "setsid",          0 }, { "getgroups",      2 },
    { "setgroups",      2 }, { "uname",           1 }, { "sethostname",    2 },
    { "setdomainname",  2 }, { "getrusage",       2 }, { "getcpu",         3 },
    { "gettimeofday",   2 }, { "settimeofday",    2 }, { "time",           1 },
    { "adjtimex",       1 }, { "clock_adjtime",   2 }, { "sysinfo",        1 },
    { "mq_open",        4 }, { "mq_unlink",       1 }, { "mq_timedsend",   5 },
    { "mq_timedreceive", 5 }, { "mq_notify",      2 }, { "mq_getsetattr",  3 },
    { "msgget",         2 }, { "msgctl",          3 }, { "msgrcv",         5 },
    { "msgsnd",         4 }, { "semget",          3 }, { "semctl",         4 },
    { "semtimedop",     4 }, { "semop",           3 }, { "shmget",         3 },
    { "shmctl",         3 }, { "shmat",           3 }, { "shmdt",          1 },
    { "readahead",      3 }, { "add_key",         5 }, { "request_key",    4 },
    { "keyctl",         5 }, { "fadvise64",       4 }, { "swapon",         2 },
    { "swapoff",        1 }, { "msync",           3 }, { "mlock",          2 },
    { "munlock",        2 }, { "mlockall",        1 }, { "munlockall",     0 },
    { "mlock2",         3 }, { "mincore",         3 }, { "remap_file_pages", 5 },
    { "mbind",          6 }, { "get_mempolicy",   5 }, { "set_mempolicy",  3 },
    { "set_mempolicy_home_node", 4 }, { "migrate_pages", 4 }, { "move_pages", 6 },
    { "perf_event_open", 5 }, { "recvmmsg",       5 }, { "sendmmsg",       4 },
    { "fanotify_init",  2 }, { "fanotify_mark",   5 }, { "name_to_handle_at", 5 },
    { "open_by_handle_at", 3 }, { "syncfs",       1 }, { "setns",          2 },
    { "process_vm_readv", 6 }, { "process_vm_writev", 6 }, { "kcmp",       5 },
    { "sched_setattr",  3 }, { "sched_getattr",   4 }, { "seccomp",        3 },
    { "bpf",            3 }, { "userfaultfd",     1 }, { "membarrier",     3 },
    { "copy_file_range", 6 }, { "pkey_mprotect",  4 }, { "pkey_alloc",     2 },
    { "pkey_free",      1 }, { "kexec_file_load", 5 }, { "pidfd_send_signal", 4 },
    { "io_uring_setup", 2 }, { "io_uring_enter",  6 }, { "io_uring_register", 4 },
    { "open_tree",      3 }, { "move_mount",      5 }, { "fsopen",         2 },
    { "fsconfig",       5 }, { "fsmount",         3 }, { "fspick",         3 },
    { "pidfd_open",     2 }, { "close_range",     3 }, { "openat2",        4 },
    { "pidfd_getfd",    3 }, { "process_madvise", 5 }, { "epoll_pwait2",   6 },
    { "mount_setattr",  5 }, { "quotactl_fd",     4 }, { "landlock_create_ruleset", 3 },
    { "landlock_add_rule", 4 }, { "landlock_restrict_self", 2 },
    { "memfd_secret",   1 }, { "process_mrelease", 2 }, { "futex_waitv",   5 },
    { "cachestat",      4 }, { "fchmodat2",       4 }, { "getdents",       3 },
    { "ustat",          2 }, { "uselib",          1 }, { "sysfs",          3 },
    { "modify_ldt",     3 }, { "iopl",            1 }, { "ioperm",         3 },

    { NULL,             0 },
};

int syscall_argc(const char *syscall) {
    for (int i = 0; syscall_argc_table[i].name != NULL; i++) {
        if (strcmp(syscall_argc_table[i].name, syscall) == 0)
            return syscall_argc_table[i].argc;
    }
    return -1;
}
