/*
 * "Which argument slot(s) of this syscall hold a value of kind X" —
 * routing tables that just say WHERE to look, not how to read or
 * format what's there. Everything here is keyed by syscall name
 * (a linear scan over a small static table — see mini_strace.c's
 * header comment for why that's the deliberate choice throughout
 * this codebase) and returns either a bitmask over argument slots
 * 0-5, or a small struct pointer for the two-slot (value + length)
 * cases.
 */
#ifndef MINI_STRACE_ARG_ROUTING_H
#define MINI_STRACE_ARG_ROUTING_H

/* Bitmask-over-argument-slots shape, shared by every "which arg(s)
 * hold a single value of this kind" table below. */
typedef struct {
    const char *name;
    unsigned char str_args;  /* bit i => argument i matches */
} string_arg_entry;

/* "One arg holds a value, another holds its length/size" shape,
 * shared by the buffer/sockaddr tables below. */
typedef struct {
    const char *name;
    int buf_idx;
    int len_idx;
} buffer_arg_entry;

/* "This syscall has exactly N of the 6 raw argument slots" shape,
 * used by syscall_argc_table. */
typedef struct {
    const char *name;
    int argc;
} syscall_argc_entry;

/* Path-string arguments (open, stat, execve, symlink, mount, ...). */
unsigned char string_arg_mask(const char *syscall);

/* File descriptor arguments, used by -y to resolve a raw fd number
 * to what it points to. */
unsigned char fd_arg_mask(const char *syscall);

/* execve/execveat's argv/envp arrays. */
unsigned char argv_arg_mask(const char *syscall);

/* open/openat's flags. */
unsigned char open_flags_arg_mask(const char *syscall);

/* mmap/mprotect's prot. */
unsigned char prot_flags_arg_mask(const char *syscall);

/* mmap's flags. */
unsigned char map_flags_arg_mask(const char *syscall);

/* socket/socketpair's domain. */
unsigned char socket_domain_arg_mask(const char *syscall);

/* socket/socketpair's type. */
unsigned char socket_type_arg_mask(const char *syscall);

/* kill/tkill/tgkill's target signal number. */
unsigned char signal_arg_mask(const char *syscall);

/* lseek's whence. */
unsigned char lseek_whence_arg_mask(const char *syscall);

/* fcntl's cmd. */
unsigned char fcntl_cmd_arg_mask(const char *syscall);

/* rt_sigprocmask's how. */
unsigned char sigprocmask_how_arg_mask(const char *syscall);

/* access/faccessat/faccessat2's mode. */
unsigned char access_mode_arg_mask(const char *syscall);

/* clock_gettime/clock_settime/clock_getres/clock_nanosleep's clockid. */
unsigned char clockid_arg_mask(const char *syscall);

/* wait4's wstatus (deferred to the exit-stop — see mini_strace.c). */
unsigned char wait_status_arg_mask(const char *syscall);

/* clone's flags. */
unsigned char clone_flags_arg_mask(const char *syscall);

/* clone3's struct clone_args pointer. */
unsigned char clone3_args_arg_mask(const char *syscall);

/* ioctl's request code. */
unsigned char ioctl_request_arg_mask(const char *syscall);

/* sendmsg's struct msghdr* — already populated at the entry-stop. */
unsigned char msghdr_send_arg_mask(const char *syscall);

/* recvmsg's struct msghdr* (deferred to the exit-stop — see
 * mini_strace.c). */
unsigned char msghdr_recv_arg_mask(const char *syscall);

/* write's buffer + length — already populated at the entry-stop. */
const buffer_arg_entry *buffer_arg_lookup(const char *syscall);

/* connect/bind/sendto's sockaddr + length — already populated at
 * the entry-stop. */
const buffer_arg_entry *sockaddr_arg_lookup(const char *syscall);

/* accept/getsockname/getpeername/recvfrom's sockaddr + socklen_t*,
 * only populated *after* the syscall runs (deferred to the
 * exit-stop — see mini_strace.c). */
const buffer_arg_entry *accept_arg_lookup(const char *syscall);

/* read/pread64/recvfrom's buffer + length, only populated *after*
 * the syscall runs (deferred to the exit-stop — see mini_strace.c). */
const buffer_arg_entry *read_arg_lookup(const char *syscall);

/* How many of the 6 raw argument slots this syscall actually has.
 * -1 means unknown — mini_strace.c falls back to showing all 6. */
int syscall_argc(const char *syscall);

#endif /* MINI_STRACE_ARG_ROUTING_H */
