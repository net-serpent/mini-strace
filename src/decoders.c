#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <sched.h>

#include "decoders.h"
#include "child_mem.h"

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

void format_hex_or_fd_arg(pid_t pid, unsigned long long raw, int is_fd_arg,
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

/* Decodes a struct sockaddr argument (connect/bind/sendto) into
 * something readable instead of a raw pointer. sa_family is always
 * host-endian; sin_port/sin_addr inside sockaddr_in (and sin6_port
 * inside sockaddr_in6) are always network byte order regardless of
 * host endianness, so they're unpacked byte-by-byte here rather than
 * assuming any particular host layout — inet_ntop() takes the raw
 * 16-byte address as-is (it's defined byte-order-agnostic, not a
 * host-endian integer) so that part doesn't need manual unpacking.
 * Only AF_INET, AF_INET6, and AF_UNIX are decoded — anything else
 * (AF_NETLINK, ...) just shows the numeric family, which is still
 * more useful than a bare address and keeps this from turning into a
 * decoder for every address family Linux has. */
void format_sockaddr(pid_t pid, unsigned long long addr, unsigned long long addrlen,
                      char *out, size_t out_size) {
    if (addr == 0) {
        snprintf(out, out_size, "NULL");
        return;
    }

    unsigned char raw[128];
    size_t want = (addrlen < sizeof(raw)) ? (size_t)addrlen : sizeof(raw);
    if (want < 2)
        want = 2;  /* always try to get at least sa_family */
    size_t got = read_child_raw(pid, addr, raw, want);

    if (got < 2) {
        snprintf(out, out_size, "0x%llx", addr);
        return;
    }

    unsigned short family = (unsigned short)(raw[0] | (raw[1] << 8));

    if (family == AF_INET && got >= 8) {
        unsigned int port = ((unsigned int)raw[2] << 8) | raw[3];
        snprintf(out, out_size,
                 "{sa_family=AF_INET, sin_port=htons(%u), sin_addr=inet_addr(\"%u.%u.%u.%u\")}",
                 port, raw[4], raw[5], raw[6], raw[7]);
    } else if (family == AF_INET6 && got >= 8 + sizeof(struct in6_addr)) {
        unsigned int port = ((unsigned int)raw[2] << 8) | raw[3];
        char ipstr[INET6_ADDRSTRLEN];
        /* sockaddr_in6 layout: family(2), port(2), flowinfo(4), addr(16), scope_id(4) */
        if (inet_ntop(AF_INET6, raw + 8, ipstr, sizeof(ipstr)) != NULL) {
            snprintf(out, out_size,
                     "{sa_family=AF_INET6, sin6_port=htons(%u), sin6_addr=inet_pton(AF_INET6, \"%s\")}",
                     port, ipstr);
        } else {
            snprintf(out, out_size, "{sa_family=AF_INET6, ...}");
        }
    } else if (family == AF_UNIX) {
        size_t path_len = got > 2 ? got - 2 : 0;
        if (path_len > sizeof(raw) - 2)
            path_len = sizeof(raw) - 2;
        /* an abstract socket's path starts with a NUL byte instead
         * of being a normal filesystem path — real strace (and the
         * kernel's own convention) marks that with a leading '@'. */
        if (path_len > 0 && raw[2] == '\0') {
            snprintf(out, out_size, "{sa_family=AF_UNIX, sun_path=\"@%.*s\"}",
                     (int)path_len - 1, (const char *)raw + 3);
        } else {
            snprintf(out, out_size, "{sa_family=AF_UNIX, sun_path=\"%.*s\"}",
                     (int)path_len, (const char *)raw + 2);
        }
    } else {
        snprintf(out, out_size, "{sa_family=%u, ...}", family);
    }
}

/* Decodes wait4's wstatus into the WIFEXITED/WIFSIGNALED/WIFSTOPPED
 * form real strace uses, instead of a raw hex encoded status word.
 * A single PTRACE_PEEKDATA is enough since wstatus is only 4 bytes
 * (an int) — no need for the multi-word read loop the string/buffer
 * readers use. */
void format_wait_status(pid_t pid, unsigned long long addr, char *out, size_t out_size) {
    if (addr == 0) {
        snprintf(out, out_size, "NULL");
        return;
    }

    errno = 0;
    long word = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL);
    if (word == -1 && errno != 0) {
        snprintf(out, out_size, "0x%llx", addr);
        return;
    }

    int wstatus = (int)(word & 0xffffffff);

    if (WIFEXITED(wstatus)) {
        snprintf(out, out_size, "[{WIFEXITED(s) && WEXITSTATUS(s) == %d}]", WEXITSTATUS(wstatus));
    } else if (WIFSIGNALED(wstatus)) {
        snprintf(out, out_size, "[{WIFSIGNALED(s) && WTERMSIG(s) == SIG%s}]",
                 sigabbrev_np(WTERMSIG(wstatus)));
    } else if (WIFSTOPPED(wstatus)) {
        snprintf(out, out_size, "[{WIFSTOPPED(s) && WSTOPSIG(s) == SIG%s}]",
                 sigabbrev_np(WSTOPSIG(wstatus)));
    } else {
        snprintf(out, out_size, "[0x%x]", (unsigned int)wstatus);
    }
}

typedef struct {
    unsigned long long value;
    const char *name;
} flag_entry;

/* open()/openat()'s flags, decoded as real strace shows them —
 * "O_WRONLY|O_CREAT|O_TRUNC" instead of an opaque hex number. Real
 * macros from <fcntl.h> rather than hardcoded numbers, since a few
 * of these (notably O_LARGEFILE) have historically differed across
 * architectures — the libc headers already get that right for
 * whatever platform this is built on.
 *
 * O_SYNC and O_TMPFILE are each defined as an existing flag bit
 * *plus* an extra bit (O_SYNC = O_DSYNC | extra; O_TMPFILE =
 * O_DIRECTORY | extra), not independent bits of their own, so they
 * have to be checked — and their bits consumed — before their
 * "subset" flag gets a chance to match on what's left over. That's
 * why they're listed first: format_open_flags() below matches
 * top-to-bottom and only claims a table entry when *all* of its bits
 * are still present in what's left to explain. */
static const flag_entry open_flag_table[] = {
    { O_TMPFILE,   "O_TMPFILE" },
    { O_SYNC,      "O_SYNC" },
    { O_CREAT,     "O_CREAT" },
    { O_EXCL,      "O_EXCL" },
    { O_NOCTTY,    "O_NOCTTY" },
    { O_TRUNC,     "O_TRUNC" },
    { O_APPEND,    "O_APPEND" },
    { O_NONBLOCK,  "O_NONBLOCK" },
    { O_DSYNC,     "O_DSYNC" },
    { O_DIRECT,    "O_DIRECT" },
    { O_LARGEFILE, "O_LARGEFILE" },
    { O_DIRECTORY, "O_DIRECTORY" },
    { O_NOFOLLOW,  "O_NOFOLLOW" },
    { O_NOATIME,   "O_NOATIME" },
    { O_CLOEXEC,   "O_CLOEXEC" },
    { O_PATH,      "O_PATH" },
    { 0,           NULL },
};

void format_open_flags(unsigned long long flags, char *out, size_t out_size) {
    unsigned long long remaining = flags;
    size_t oi = 0;

    /* the low bits aren't independent flags — O_RDONLY/O_WRONLY/
     * O_RDWR are a 2-bit access-mode value, not bits to OR against —
     * so it's handled separately from the flag_entry table. */
    const char *accmode_name = "O_RDONLY";
    if ((remaining & O_ACCMODE) == O_WRONLY)
        accmode_name = "O_WRONLY";
    else if ((remaining & O_ACCMODE) == O_RDWR)
        accmode_name = "O_RDWR";
    remaining &= ~(unsigned long long)O_ACCMODE;

    oi += (size_t)snprintf(out + oi, out_size - oi, "%s", accmode_name);

    for (int i = 0; open_flag_table[i].name != NULL && oi < out_size; i++) {
        if (open_flag_table[i].value != 0 &&
            (remaining & open_flag_table[i].value) == open_flag_table[i].value) {
            oi += (size_t)snprintf(out + oi, out_size - oi, "|%s", open_flag_table[i].name);
            remaining &= ~open_flag_table[i].value;
        }
    }
    if (remaining != 0 && oi < out_size)
        snprintf(out + oi, out_size - oi, "|0x%llx", remaining);
}

/* mmap()/mprotect()'s prot argument — PROT_READ/PROT_WRITE/PROT_EXEC
 * are true independent bits (unlike open()'s access mode), so this
 * is a plain OR-of-matched-names walk with no special first entry.
 * value == 0 is its own real, named case (PROT_NONE) rather than
 * "no flags matched", so it's handled up front. */
static const flag_entry prot_flag_table[] = {
    { PROT_READ,  "PROT_READ" },
    { PROT_WRITE, "PROT_WRITE" },
    { PROT_EXEC,  "PROT_EXEC" },
    { 0,          NULL },
};

void format_prot_flags(unsigned long long value, char *out, size_t out_size) {
    if (value == 0) {
        snprintf(out, out_size, "PROT_NONE");
        return;
    }
    unsigned long long remaining = value;
    size_t oi = 0;
    for (int i = 0; prot_flag_table[i].name != NULL && oi < out_size; i++) {
        if ((remaining & prot_flag_table[i].value) == prot_flag_table[i].value) {
            oi += (size_t)snprintf(out + oi, out_size - oi, "%s%s", oi ? "|" : "", prot_flag_table[i].name);
            remaining &= ~prot_flag_table[i].value;
        }
    }
    if (remaining != 0 && oi < out_size)
        snprintf(out + oi, out_size - oi, "%s0x%llx", oi ? "|" : "", remaining);
}

/* mmap()'s flags argument. MAP_SHARED/MAP_PRIVATE are usually
 * mutually exclusive in practice but aren't a 2-bit enum the way
 * open()'s access mode is — they're independent bits like everything
 * else here, so no special first-entry handling is needed. */
static const flag_entry map_flag_table[] = {
    { MAP_SHARED,     "MAP_SHARED" },
    { MAP_PRIVATE,    "MAP_PRIVATE" },
    { MAP_FIXED,      "MAP_FIXED" },
    { MAP_ANONYMOUS,  "MAP_ANONYMOUS" },
    { MAP_GROWSDOWN,  "MAP_GROWSDOWN" },
    { MAP_DENYWRITE,  "MAP_DENYWRITE" },
    { MAP_EXECUTABLE, "MAP_EXECUTABLE" },
    { MAP_LOCKED,     "MAP_LOCKED" },
    { MAP_NORESERVE,  "MAP_NORESERVE" },
    { MAP_POPULATE,   "MAP_POPULATE" },
    { MAP_NONBLOCK,   "MAP_NONBLOCK" },
    { MAP_STACK,      "MAP_STACK" },
    { MAP_HUGETLB,    "MAP_HUGETLB" },
    { 0,              NULL },
};

void format_map_flags(unsigned long long value, char *out, size_t out_size) {
    unsigned long long remaining = value;
    size_t oi = 0;
    for (int i = 0; map_flag_table[i].name != NULL && oi < out_size; i++) {
        if (map_flag_table[i].value != 0 &&
            (remaining & map_flag_table[i].value) == map_flag_table[i].value) {
            oi += (size_t)snprintf(out + oi, out_size - oi, "%s%s", oi ? "|" : "", map_flag_table[i].name);
            remaining &= ~map_flag_table[i].value;
        }
    }
    if ((oi == 0 || remaining != 0) && oi < out_size)
        snprintf(out + oi, out_size - oi, "%s0x%llx", oi ? "|" : "", remaining);
}

/* socket()/socketpair()'s domain argument. This is a plain enum
 * value, not independent bits to OR together — exactly one of these
 * is ever set — so it's a lookup, not a flag walk. Covers the
 * families this file's own sockaddr decoding already understands
 * plus the two most common ones it doesn't (netlink and packet
 * sockets), so a bare number here is rare in practice. */
static const flag_entry socket_domain_table[] = {
    { AF_UNIX,    "AF_UNIX" },
    { AF_INET,    "AF_INET" },
    { AF_INET6,   "AF_INET6" },
    { AF_NETLINK, "AF_NETLINK" },
    { AF_PACKET,  "AF_PACKET" },
    { AF_UNSPEC,  "AF_UNSPEC" },
    { 0,          NULL },
};

void format_socket_domain(unsigned long long value, char *out, size_t out_size) {
    for (int i = 0; socket_domain_table[i].name != NULL; i++) {
        if (socket_domain_table[i].value == value) {
            snprintf(out, out_size, "%s", socket_domain_table[i].name);
            return;
        }
    }
    snprintf(out, out_size, "0x%llx", value);
}

/* socket()/socketpair()'s type argument. Also an enum value, not
 * independent bits — but Linux additionally lets SOCK_CLOEXEC and
 * SOCK_NONBLOCK ride along OR'd into the same int (they're just
 * O_CLOEXEC/O_NONBLOCK reused as socket-type bits, picked because
 * they don't collide with any real socket type's low bits), so those
 * two get peeled off and appended the way open()'s flags append
 * separate names, while the base type underneath is still a lookup
 * rather than a walk. */
static const flag_entry socket_type_table[] = {
    { SOCK_STREAM,    "SOCK_STREAM" },
    { SOCK_DGRAM,     "SOCK_DGRAM" },
    { SOCK_RAW,       "SOCK_RAW" },
    { SOCK_RDM,       "SOCK_RDM" },
    { SOCK_SEQPACKET, "SOCK_SEQPACKET" },
    { SOCK_PACKET,    "SOCK_PACKET" },
    { 0,              NULL },
};

void format_socket_type(unsigned long long value, char *out, size_t out_size) {
    unsigned long long base = value & ~(unsigned long long)(SOCK_CLOEXEC | SOCK_NONBLOCK);
    const char *base_name = NULL;

    for (int i = 0; socket_type_table[i].name != NULL; i++) {
        if (socket_type_table[i].value == base) {
            base_name = socket_type_table[i].name;
            break;
        }
    }

    size_t oi;
    if (base_name != NULL)
        oi = (size_t)snprintf(out, out_size, "%s", base_name);
    else
        oi = (size_t)snprintf(out, out_size, "0x%llx", base);

    if ((value & (unsigned long long)SOCK_CLOEXEC) && oi < out_size)
        oi += (size_t)snprintf(out + oi, out_size - oi, "|SOCK_CLOEXEC");
    if ((value & (unsigned long long)SOCK_NONBLOCK) && oi < out_size)
        snprintf(out + oi, out_size - oi, "|SOCK_NONBLOCK");
}

/* kill()/tkill()/tgkill()'s target signal number, via the same
 * sigabbrev_np() already used to name a signal actually being
 * delivered to the tracee. Signal 0 is its own real, meaningful
 * value (the "null signal" used purely to test whether a pid exists
 * and is killable, without sending anything) rather than a signal
 * name, so it's printed as a plain "0" instead of going through the
 * lookup. */
void format_signal_arg(unsigned long long value, char *out, size_t out_size) {
    int sig = (int)value;
    if (sig == 0) {
        snprintf(out, out_size, "0");
        return;
    }
    const char *abbrev = sigabbrev_np(sig);
    if (abbrev != NULL)
        snprintf(out, out_size, "SIG%s", abbrev);
    else
        snprintf(out, out_size, "%d", sig);
}

/* lseek()'s whence argument — a plain enum value like socket()'s
 * domain, not bits to OR. SEEK_SET happens to be 0, but that's not
 * special-cased the way PROT_NONE/O_RDONLY are: those needed to
 * distinguish "the value was legitimately zero" from "no flag bits
 * matched" in an OR-of-bits walk, but a lookup like this one just
 * compares against each entry regardless of which one happens to be
 * zero. */
static const flag_entry lseek_whence_table[] = {
    { SEEK_SET,  "SEEK_SET" },
    { SEEK_CUR,  "SEEK_CUR" },
    { SEEK_END,  "SEEK_END" },
    { SEEK_DATA, "SEEK_DATA" },
    { SEEK_HOLE, "SEEK_HOLE" },
    { 0,         NULL },
};

void format_lseek_whence(unsigned long long value, char *out, size_t out_size) {
    for (int i = 0; lseek_whence_table[i].name != NULL; i++) {
        if (lseek_whence_table[i].value == value) {
            snprintf(out, out_size, "%s", lseek_whence_table[i].name);
            return;
        }
    }
    snprintf(out, out_size, "0x%llx", value);
}

/* fcntl()'s cmd argument — another plain enum lookup, like
 * lseek()'s whence. F_DUPFD is 0 here for the same non-reason
 * SEEK_SET being 0 wasn't a problem there: this is a value lookup,
 * not an OR-of-bits walk, so which entry happens to be zero doesn't
 * matter. Real macros from <fcntl.h> rather than hardcoded numbers —
 * F_GETLK/F_SETLK/F_SETLKW in particular have differed across
 * architectures and 32-vs-64-bit off_t builds historically, so
 * trusting the libc header sidesteps that entirely. Only the cmd
 * itself is decoded; the meaning of fcntl's third argument depends
 * on which cmd this is (a flags value, a struct flock*, ignored,
 * ...) and is left as plain hex, same as before this change. */
static const flag_entry fcntl_cmd_table[] = {
    { F_DUPFD,         "F_DUPFD" },
    { F_DUPFD_CLOEXEC, "F_DUPFD_CLOEXEC" },
    { F_GETFD,         "F_GETFD" },
    { F_SETFD,         "F_SETFD" },
    { F_GETFL,         "F_GETFL" },
    { F_SETFL,         "F_SETFL" },
    { F_GETLK,         "F_GETLK" },
    { F_SETLK,         "F_SETLK" },
    { F_SETLKW,        "F_SETLKW" },
    { F_GETOWN,        "F_GETOWN" },
    { F_SETOWN,        "F_SETOWN" },
    { F_GETSIG,        "F_GETSIG" },
    { F_SETSIG,        "F_SETSIG" },
    { F_SETLEASE,      "F_SETLEASE" },
    { F_GETLEASE,      "F_GETLEASE" },
    { F_SETPIPE_SZ,    "F_SETPIPE_SZ" },
    { F_GETPIPE_SZ,    "F_GETPIPE_SZ" },
    { 0,               NULL },
};

void format_fcntl_cmd(unsigned long long value, char *out, size_t out_size) {
    for (int i = 0; fcntl_cmd_table[i].name != NULL; i++) {
        if (fcntl_cmd_table[i].value == value) {
            snprintf(out, out_size, "%s", fcntl_cmd_table[i].name);
            return;
        }
    }
    snprintf(out, out_size, "0x%llx", value);
}

/* rt_sigprocmask()'s how argument — same plain-enum-lookup shape as
 * lseek()'s whence and fcntl()'s cmd. SIG_BLOCK is 0 here for the
 * same non-reason SEEK_SET/F_DUPFD being 0 wasn't a problem for
 * those: a value lookup doesn't care which entry happens to be
 * zero. Only x86-64 and aarch64 are supported by this file (see the
 * header comment), and neither has a legacy sigprocmask(2) syscall
 * of its own — signal mask changes go through rt_sigprocmask on
 * both — so that's the only name this needs to match. */
static const flag_entry sigprocmask_how_table[] = {
    { SIG_BLOCK,   "SIG_BLOCK" },
    { SIG_UNBLOCK, "SIG_UNBLOCK" },
    { SIG_SETMASK, "SIG_SETMASK" },
    { 0,           NULL },
};

void format_sigprocmask_how(unsigned long long value, char *out, size_t out_size) {
    for (int i = 0; sigprocmask_how_table[i].name != NULL; i++) {
        if (sigprocmask_how_table[i].value == value) {
            snprintf(out, out_size, "%s", sigprocmask_how_table[i].name);
            return;
        }
    }
    snprintf(out, out_size, "0x%llx", value);
}

/* access()/faccessat()/faccessat2()'s mode argument — back to an
 * OR-of-bits walk like the PROT_ or MAP_ flags, not a plain lookup like
 * whence/cmd/how, since R_OK/W_OK/X_OK are genuinely independent and
 * combinable (checking "can I read and write this" is one call with
 * both bits set). F_OK (value 0, "does this path exist at all") is
 * its own named case up front, same reasoning as PROT_NONE. */
static const flag_entry access_mode_table[] = {
    { R_OK, "R_OK" },
    { W_OK, "W_OK" },
    { X_OK, "X_OK" },
    { 0,    NULL },
};

void format_access_mode(unsigned long long value, char *out, size_t out_size) {
    if (value == 0) {
        snprintf(out, out_size, "F_OK");
        return;
    }
    unsigned long long remaining = value;
    size_t oi = 0;
    for (int i = 0; access_mode_table[i].name != NULL && oi < out_size; i++) {
        if ((remaining & access_mode_table[i].value) == access_mode_table[i].value) {
            oi += (size_t)snprintf(out + oi, out_size - oi, "%s%s", oi ? "|" : "", access_mode_table[i].name);
            remaining &= ~access_mode_table[i].value;
        }
    }
    if (remaining != 0 && oi < out_size)
        snprintf(out + oi, out_size - oi, "%s0x%llx", oi ? "|" : "", remaining);
}

/* clock_gettime()/clock_settime()/clock_getres()/clock_nanosleep()'s
 * clockid argument — another plain enum lookup, like whence/cmd/how.
 * CLOCK_REALTIME being 0 isn't special-cased for the usual reason: a
 * value lookup doesn't care which entry happens to be zero. */
static const flag_entry clockid_table[] = {
    { CLOCK_REALTIME,           "CLOCK_REALTIME" },
    { CLOCK_MONOTONIC,          "CLOCK_MONOTONIC" },
    { CLOCK_PROCESS_CPUTIME_ID, "CLOCK_PROCESS_CPUTIME_ID" },
    { CLOCK_THREAD_CPUTIME_ID,  "CLOCK_THREAD_CPUTIME_ID" },
    { CLOCK_MONOTONIC_RAW,      "CLOCK_MONOTONIC_RAW" },
    { CLOCK_REALTIME_COARSE,    "CLOCK_REALTIME_COARSE" },
    { CLOCK_MONOTONIC_COARSE,   "CLOCK_MONOTONIC_COARSE" },
    { CLOCK_BOOTTIME,           "CLOCK_BOOTTIME" },
    { 0,                        NULL },
};

void format_clockid(unsigned long long value, char *out, size_t out_size) {
    for (int i = 0; clockid_table[i].name != NULL; i++) {
        if (clockid_table[i].value == value) {
            snprintf(out, out_size, "%s", clockid_table[i].name);
            return;
        }
    }
    snprintf(out, out_size, "0x%llx", value);
}

/* clone()/clone3()'s flags. Real macros from <sched.h>, same
 * reasoning as everywhere else in this file: numbers are fixed by
 * the kernel ABI and the libc header already has them right for
 * this platform. CLONE_PIDFD and CLONE_CLEAR_SIGHAND are newer
 * additions to the kernel/glibc pair and are guarded, since a build
 * against an older libc may not define them.
 *
 * The low byte of clone()'s flags argument is not a flag at all: it
 * is the signal number to send the parent on exit (CSIGNAL, 0xff),
 * a historical encoding predating clone3()'s separate exit_signal
 * field. format_clone_flags_value() below splits that byte out and
 * decodes it with sigabbrev_np(), the same function used elsewhere
 * to name a signal being delivered to the tracee. */
static const flag_entry clone_flag_table[] = {
    { CLONE_VM,             "CLONE_VM" },
    { CLONE_FS,             "CLONE_FS" },
    { CLONE_FILES,          "CLONE_FILES" },
    { CLONE_SIGHAND,        "CLONE_SIGHAND" },
#ifdef CLONE_PIDFD
    { CLONE_PIDFD,          "CLONE_PIDFD" },
#endif
    { CLONE_PTRACE,         "CLONE_PTRACE" },
    { CLONE_VFORK,          "CLONE_VFORK" },
    { CLONE_PARENT,         "CLONE_PARENT" },
    { CLONE_THREAD,         "CLONE_THREAD" },
    { CLONE_NEWNS,          "CLONE_NEWNS" },
    { CLONE_SYSVSEM,        "CLONE_SYSVSEM" },
    { CLONE_SETTLS,         "CLONE_SETTLS" },
    { CLONE_PARENT_SETTID,  "CLONE_PARENT_SETTID" },
    { CLONE_CHILD_CLEARTID, "CLONE_CHILD_CLEARTID" },
    { CLONE_UNTRACED,       "CLONE_UNTRACED" },
    { CLONE_CHILD_SETTID,   "CLONE_CHILD_SETTID" },
    { CLONE_NEWCGROUP,      "CLONE_NEWCGROUP" },
    { CLONE_NEWUTS,         "CLONE_NEWUTS" },
    { CLONE_NEWIPC,         "CLONE_NEWIPC" },
    { CLONE_NEWUSER,        "CLONE_NEWUSER" },
    { CLONE_NEWPID,         "CLONE_NEWPID" },
    { CLONE_NEWNET,         "CLONE_NEWNET" },
    { CLONE_IO,             "CLONE_IO" },
#ifdef CLONE_CLEAR_SIGHAND
    { CLONE_CLEAR_SIGHAND,  "CLONE_CLEAR_SIGHAND" },
#endif
    { 0,                    NULL },
};

/* Low byte of clone()'s flags argument: the exit signal sent to the
 * parent, encoded there instead of as its own argument (that is
 * clone3()'s exit_signal field, a separate struct member). Not a
 * kernel macro name available from a header; the value is fixed by
 * the ABI. */
#define CLONE_CSIGNAL_MASK 0xffULL

/* Shared by format_clone_flags() (clone()'s flags argument, flags
 * and exit signal packed into one value) and format_clone3_flags()
 * (clone3()'s struct clone_args, which keeps them as separate
 * fields). exit_signal of 0 means none and is not printed. */
static void format_clone_flags_value(unsigned long long flags, unsigned long long exit_signal,
                                      char *out, size_t out_size) {
    unsigned long long remaining = flags;
    size_t oi = 0;

    for (int i = 0; clone_flag_table[i].name != NULL && oi < out_size; i++) {
        if ((remaining & clone_flag_table[i].value) == clone_flag_table[i].value) {
            oi += (size_t)snprintf(out + oi, out_size - oi, "%s%s", oi ? "|" : "", clone_flag_table[i].name);
            remaining &= ~clone_flag_table[i].value;
        }
    }

    if (exit_signal != 0 && oi < out_size) {
        const char *abbrev = sigabbrev_np((int)exit_signal);
        if (abbrev != NULL)
            oi += (size_t)snprintf(out + oi, out_size - oi, "%sSIG%s", oi ? "|" : "", abbrev);
        else
            oi += (size_t)snprintf(out + oi, out_size - oi, "%s%llu", oi ? "|" : "", exit_signal);
    }

    if (oi == 0) {
        snprintf(out, out_size, "0");
        return;
    }
    if (remaining != 0 && oi < out_size)
        snprintf(out + oi, out_size - oi, "|0x%llx", remaining);
}

void format_clone_flags(unsigned long long value, char *out, size_t out_size) {
    format_clone_flags_value(value & ~CLONE_CSIGNAL_MASK, value & CLONE_CSIGNAL_MASK, out, out_size);
}

/* clone3()'s single argument is a pointer to struct clone_args, not
 * a plain integer, so this reads the tracee's memory instead of
 * just formatting a value already in hand. struct clone_args (Linux
 * uapi <linux/sched.h>) has a fixed field layout regardless of the
 * size argument, which only tells the kernel how many trailing
 * fields are present:
 *
 *   u64 flags;        offset 0
 *   u64 pidfd;        offset 8
 *   u64 child_tid;    offset 16
 *   u64 parent_tid;   offset 24
 *   u64 exit_signal;  offset 32
 *   ...
 *
 * Only flags and exit_signal are read here. Fields are read as
 * plain host-endian integers (unlike sockaddr's network-order
 * fields in format_sockaddr): ptrace(2) only ever traces a process
 * on the same machine, so the tracee's native integers are already
 * in the tracer's own byte order. */
#define CLONE_ARGS_MIN_SIZE 40

void format_clone3_flags(pid_t pid, unsigned long long addr, char *out, size_t out_size) {
    if (addr == 0) {
        snprintf(out, out_size, "NULL");
        return;
    }

    unsigned char raw[CLONE_ARGS_MIN_SIZE];
    size_t got = read_child_raw(pid, addr, raw, sizeof(raw));
    if (got < 8) {
        snprintf(out, out_size, "0x%llx", addr);
        return;
    }

    unsigned long long flags = 0;
    memcpy(&flags, raw, 8);

    unsigned long long exit_signal = 0;
    if (got >= CLONE_ARGS_MIN_SIZE)
        memcpy(&exit_signal, raw + 32, 8);

    format_clone_flags_value(flags, exit_signal, out, out_size);
}
