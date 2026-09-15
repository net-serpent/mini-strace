/*
 * Turning a raw argument value into something readable, once
 * arg_routing.h has already said *which* argument this is. Each
 * function here takes the raw value (or, for the two that need to
 * dereference the tracee's memory, a pid + address) and writes a
 * formatted string into the caller's buffer.
 */
#ifndef MINI_STRACE_DECODERS_H
#define MINI_STRACE_DECODERS_H

#include <sys/types.h>
#include <stddef.h>

/* Formats an argument that isn't a known string/buffer: plain hex,
 * same as always, unless it's a fd slot under -y and it can be
 * resolved to a path — then "<path>" gets appended after the hex
 * value, e.g. "0x3<socket:[12345]>". is_fd_arg is 0 whenever -y
 * isn't active, so this collapses back to the plain-hex-only path
 * by default. */
void format_hex_or_fd_arg(pid_t pid, unsigned long long raw, int is_fd_arg,
                           char *out, size_t out_size);

/* Decodes a struct sockaddr argument (connect/bind/sendto/accept/
 * getsockname/getpeername/recvfrom) into something readable instead
 * of a raw pointer — AF_INET/AF_INET6/AF_UNIX are decoded, anything
 * else just shows the numeric family. */
void format_sockaddr(pid_t pid, unsigned long long addr, unsigned long long addrlen,
                      char *out, size_t out_size);

/* Decodes wait4's wstatus into the WIFEXITED/WIFSIGNALED/WIFSTOPPED
 * form real strace uses, instead of a raw hex encoded status word. */
void format_wait_status(pid_t pid, unsigned long long addr, char *out, size_t out_size);

/* open/openat's flags — "O_WRONLY|O_CREAT|O_TRUNC" instead of a raw
 * hex number. */
void format_open_flags(unsigned long long flags, char *out, size_t out_size);

/* mmap/mprotect's prot argument. */
void format_prot_flags(unsigned long long value, char *out, size_t out_size);

/* mmap's flags argument. */
void format_map_flags(unsigned long long value, char *out, size_t out_size);

/* mount's flags argument. */
void format_mount_flags(unsigned long long value, char *out, size_t out_size);

/* socket/socketpair's domain argument. */
void format_socket_domain(unsigned long long value, char *out, size_t out_size);

/* socket/socketpair's type argument. */
void format_socket_type(unsigned long long value, char *out, size_t out_size);

/* kill/tkill/tgkill's target signal number. */
void format_signal_arg(unsigned long long value, char *out, size_t out_size);

/* lseek's whence argument. */
void format_lseek_whence(unsigned long long value, char *out, size_t out_size);

/* fcntl's cmd argument. */
void format_fcntl_cmd(unsigned long long value, char *out, size_t out_size);

/* rt_sigprocmask's how argument. */
void format_sigprocmask_how(unsigned long long value, char *out, size_t out_size);

/* access/faccessat/faccessat2's mode argument. */
void format_access_mode(unsigned long long value, char *out, size_t out_size);

/* clock_gettime/clock_settime/clock_getres/clock_nanosleep's
 * clockid argument. */
void format_clockid(unsigned long long value, char *out, size_t out_size);

/* clone's flags argument. The low byte (CSIGNAL) is the exit signal
 * sent to the parent, not a flag bit, and is decoded separately. */
void format_clone_flags(unsigned long long value, char *out, size_t out_size);

/* clone3's single argument: a pointer to struct clone_args. Reads
 * the tracee's memory to get the flags and exit_signal fields. */
void format_clone3_flags(pid_t pid, unsigned long long addr, char *out, size_t out_size);

/* ioctl's request argument. Known terminal (tty) ioctls decode by
 * name; anything else falls back to decoding the request's
 * direction/type/number/size bit layout instead of a bare hex
 * number. */
void format_ioctl_request(unsigned long long value, char *out, size_t out_size);

/* sendmsg/recvmsg's struct msghdr argument. total_bytes is -1 for
 * sendmsg (trust each iovec's declared iov_len) or the syscall's
 * return value for recvmsg (only that many bytes were actually
 * received, spread across the iovecs in order). */
void format_msghdr(pid_t pid, unsigned long long addr, long total_bytes,
                    char *out, size_t out_size);

/* stat/lstat/fstat/newfstatat's output struct stat — st_mode (file
 * type + permissions), st_size, st_nlink, st_uid, st_gid. Only
 * meaningful after the syscall returns. */
void format_stat_buf(pid_t pid, unsigned long long addr, char *out, size_t out_size);

/* getdents64's output buffer of directory entries. Only meaningful
 * after the syscall returns; ret is the actual byte count returned
 * (the buffer's declared capacity is not how much of it is real). */
void format_getdents_buf(pid_t pid, unsigned long long addr, long ret, char *out, size_t out_size);

/* rt_sigaction's act/oldact struct sigaction — sa_handler (or
 * SIG_DFL/SIG_IGN), sa_flags, sa_mask. Note this is the kernel's
 * raw-syscall layout, not glibc's userspace struct sigaction —
 * see decoders.c for why those differ. */
void format_sigaction(pid_t pid, unsigned long long addr, char *out, size_t out_size);

#endif /* MINI_STRACE_DECODERS_H */
