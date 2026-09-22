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
#include <sys/ioctl.h>
#include <linux/ioctl.h>
#include <sys/uio.h>
#include <stdint.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/epoll.h>
#include <poll.h>

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

/* mount()'s flags argument — an OR-of-bits walk like mmap's flags
 * above. MS_REMOUNT/MS_BIND/MS_MOVE/MS_SHARED/etc. are independent
 * bits, not a mutually-exclusive enum, so a bind mount combined with
 * read-only (MS_BIND|MS_RDONLY, a common pattern for exposing a
 * directory read-only) decodes as both names together, same as any
 * other flag combination in this file. Newer flags not in every
 * glibc's <sys/mount.h> (MS_LAZYTIME) are guarded with #ifdef, same
 * pattern as CLONE_PIDFD in clone_flag_table. */
static const flag_entry mount_flag_table[] = {
    { MS_RDONLY,      "MS_RDONLY" },
    { MS_NOSUID,      "MS_NOSUID" },
    { MS_NODEV,       "MS_NODEV" },
    { MS_NOEXEC,      "MS_NOEXEC" },
    { MS_SYNCHRONOUS, "MS_SYNCHRONOUS" },
    { MS_REMOUNT,     "MS_REMOUNT" },
    { MS_MANDLOCK,    "MS_MANDLOCK" },
    { MS_DIRSYNC,     "MS_DIRSYNC" },
    { MS_NOATIME,     "MS_NOATIME" },
    { MS_NODIRATIME,  "MS_NODIRATIME" },
    { MS_BIND,        "MS_BIND" },
    { MS_MOVE,        "MS_MOVE" },
    { MS_REC,         "MS_REC" },
    { MS_SILENT,      "MS_SILENT" },
    { MS_POSIXACL,    "MS_POSIXACL" },
    { MS_UNBINDABLE,  "MS_UNBINDABLE" },
    { MS_PRIVATE,     "MS_PRIVATE" },
    { MS_SLAVE,       "MS_SLAVE" },
    { MS_SHARED,      "MS_SHARED" },
    { MS_RELATIME,    "MS_RELATIME" },
    { MS_KERNMOUNT,   "MS_KERNMOUNT" },
    { MS_I_VERSION,   "MS_I_VERSION" },
    { MS_STRICTATIME, "MS_STRICTATIME" },
#ifdef MS_LAZYTIME
    { MS_LAZYTIME,    "MS_LAZYTIME" },
#endif
    { 0,              NULL },
};

void format_mount_flags(unsigned long long value, char *out, size_t out_size) {
    unsigned long long remaining = value;
    size_t oi = 0;
    for (int i = 0; mount_flag_table[i].name != NULL && oi < out_size; i++) {
        if (mount_flag_table[i].value != 0 &&
            (remaining & mount_flag_table[i].value) == mount_flag_table[i].value) {
            oi += (size_t)snprintf(out + oi, out_size - oi, "%s%s", oi ? "|" : "", mount_flag_table[i].name);
            remaining &= ~mount_flag_table[i].value;
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

/* ioctl()'s request argument. Unlike the lookups above, this isn't
 * a small fixed enum — Linux has thousands of request codes spread
 * across every driver and subsystem, encoded via <linux/ioctl.h>'s
 * bit layout (direction, type, number, size packed into one 32-bit
 * value) rather than assigned arbitrary numbers. This table covers
 * the terminal (tty) ioctls, which dominate real-world traces (any
 * program checking whether stdin/stdout is a terminal, getting its
 * size, or fiddling with line discipline hits these); an unlisted
 * request falls back to decoding that bit layout directly instead
 * of a bare hex number, the same fallback real strace uses. */
static const flag_entry ioctl_request_table[] = {
    { TCGETS,       "TCGETS" },
    { TCSETS,       "TCSETS" },
    { TCSETSW,      "TCSETSW" },
    { TCSETSF,      "TCSETSF" },
    { TCGETA,       "TCGETA" },
    { TCSETA,       "TCSETA" },
    { TCSETAW,      "TCSETAW" },
    { TCSETAF,      "TCSETAF" },
    { TCSBRK,       "TCSBRK" },
    { TCXONC,       "TCXONC" },
    { TCFLSH,       "TCFLSH" },
    { TIOCEXCL,     "TIOCEXCL" },
    { TIOCNXCL,     "TIOCNXCL" },
    { TIOCSCTTY,    "TIOCSCTTY" },
    { TIOCGPGRP,    "TIOCGPGRP" },
    { TIOCSPGRP,    "TIOCSPGRP" },
    { TIOCOUTQ,     "TIOCOUTQ" },
    { TIOCSTI,      "TIOCSTI" },
    { TIOCGWINSZ,   "TIOCGWINSZ" },
    { TIOCSWINSZ,   "TIOCSWINSZ" },
    { TIOCMGET,     "TIOCMGET" },
    { TIOCMBIS,     "TIOCMBIS" },
    { TIOCMBIC,     "TIOCMBIC" },
    { TIOCMSET,     "TIOCMSET" },
    { TIOCGSOFTCAR, "TIOCGSOFTCAR" },
    { TIOCSSOFTCAR, "TIOCSSOFTCAR" },
    { FIONREAD,     "FIONREAD" },
    { TIOCLINUX,    "TIOCLINUX" },
    { TIOCCONS,     "TIOCCONS" },
    { TIOCGSERIAL,  "TIOCGSERIAL" },
    { TIOCSSERIAL,  "TIOCSSERIAL" },
    { TIOCPKT,      "TIOCPKT" },
    { FIONBIO,      "FIONBIO" },
    { TIOCNOTTY,    "TIOCNOTTY" },
    { TIOCSETD,     "TIOCSETD" },
    { TIOCGETD,     "TIOCGETD" },
    { TIOCGSID,     "TIOCGSID" },
    { TIOCGPTN,     "TIOCGPTN" },
    { TIOCSPTLCK,   "TIOCSPTLCK" },
#ifdef TIOCGPTPEER
    { TIOCGPTPEER,  "TIOCGPTPEER" },
#endif
    { FIONCLEX,     "FIONCLEX" },
    { FIOCLEX,      "FIOCLEX" },
    { FIOASYNC,     "FIOASYNC" },
    { 0,            NULL },
};

void format_ioctl_request(unsigned long long value, char *out, size_t out_size) {
    for (int i = 0; ioctl_request_table[i].name != NULL; i++) {
        if (ioctl_request_table[i].value == value) {
            snprintf(out, out_size, "%s", ioctl_request_table[i].name);
            return;
        }
    }

    unsigned int req = (unsigned int)value;
    unsigned int dir = _IOC_DIR(req);
    const char *dir_name;
    switch (dir) {
        case _IOC_NONE:            dir_name = "_IOC_NONE"; break;
        case _IOC_READ:            dir_name = "_IOC_READ"; break;
        case _IOC_WRITE:           dir_name = "_IOC_WRITE"; break;
        case _IOC_READ|_IOC_WRITE: dir_name = "_IOC_READ|_IOC_WRITE"; break;
        default:                   dir_name = "0"; break;
    }
    snprintf(out, out_size, "_IOC(%s, 0x%x, 0x%x, %u)",
             dir_name, _IOC_TYPE(req), _IOC_NR(req), _IOC_SIZE(req));
}

/* sendmsg/recvmsg's msg_flags argument (real, kernel-recognized
 * MSG_* bits) — a plain OR-of-bits walk like open()'s flags, used
 * only inside format_msghdr() below. 0 is itself a meaningful value
 * (no flags), not "nothing matched", so it's printed directly
 * rather than going through the walk. */
static const flag_entry msg_flag_table[] = {
    { MSG_OOB,          "MSG_OOB" },
    { MSG_PEEK,         "MSG_PEEK" },
    { MSG_DONTROUTE,    "MSG_DONTROUTE" },
    { MSG_CTRUNC,       "MSG_CTRUNC" },
    { MSG_TRUNC,        "MSG_TRUNC" },
    { MSG_DONTWAIT,     "MSG_DONTWAIT" },
    { MSG_EOR,          "MSG_EOR" },
    { MSG_WAITALL,      "MSG_WAITALL" },
    { MSG_CONFIRM,      "MSG_CONFIRM" },
    { MSG_ERRQUEUE,     "MSG_ERRQUEUE" },
    { MSG_NOSIGNAL,     "MSG_NOSIGNAL" },
    { MSG_MORE,         "MSG_MORE" },
    { MSG_CMSG_CLOEXEC, "MSG_CMSG_CLOEXEC" },
    { 0,                NULL },
};

static void format_msg_flags_value(int flags, char *out, size_t out_size) {
    if (flags == 0) {
        snprintf(out, out_size, "0");
        return;
    }
    unsigned long long remaining = (unsigned int)flags;
    size_t oi = 0;
    for (int i = 0; msg_flag_table[i].name != NULL && oi < out_size; i++) {
        if ((remaining & msg_flag_table[i].value) == msg_flag_table[i].value) {
            oi += (size_t)snprintf(out + oi, out_size - oi, "%s%s", oi ? "|" : "", msg_flag_table[i].name);
            remaining &= ~msg_flag_table[i].value;
        }
    }
    if (remaining != 0 && oi < out_size)
        snprintf(out + oi, out_size - oi, "%s0x%llx", oi ? "|" : "", remaining);
}

/* sendmsg/recvmsg's ancillary-data (cmsg) list, msg_control /
 * msg_controllen in struct msghdr. This is a sequence of struct
 * cmsghdr headers each followed by its own payload, with kernel-
 * defined alignment/padding between entries (CMSG_ALIGN) that isn't
 * worth reimplementing by hand — instead the tracee's control
 * buffer is copied into a local one, wrapped in a throwaway struct
 * msghdr that actually points at *this* process's memory, and
 * walked with the real CMSG_FIRSTHDR/CMSG_NXTHDR/CMSG_DATA macros,
 * the same ones a real sender/receiver would use.
 *
 * Only SOL_SOCKET's SCM_RIGHTS (passed file descriptors — the
 * reason cmsg exists in most real-world traces, e.g. systemd/Docker
 * socket-activation and D-Bus fd passing) and SCM_CREDENTIALS
 * (sender pid/uid/gid) are decoded into their actual meaning;
 * anything else shows its level/type/length without trying to
 * interpret payload this table doesn't know the shape of. */
#define MSGHDR_MAX_CONTROL 512

static void format_cmsg(pid_t pid, unsigned long long addr, size_t controllen,
                         char *out, size_t out_size) {
    size_t want = controllen < MSGHDR_MAX_CONTROL ? controllen : MSGHDR_MAX_CONTROL;
    unsigned char cbuf[MSGHDR_MAX_CONTROL];
    size_t got = read_child_raw(pid, addr, cbuf, want);
    if (got == 0) {
        snprintf(out, out_size, "[]");
        return;
    }

    struct msghdr local_hdr;
    memset(&local_hdr, 0, sizeof(local_hdr));
    local_hdr.msg_control = cbuf;
    local_hdr.msg_controllen = got;

    size_t oi = (size_t)snprintf(out, out_size, "[");
    int first = 1;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&local_hdr); c != NULL && oi < out_size;
         c = CMSG_NXTHDR(&local_hdr, c)) {
        oi += (size_t)snprintf(out + oi, out_size - oi, "%s{cmsg_level=", first ? "" : ", ");
        if (c->cmsg_level == SOL_SOCKET)
            oi += (size_t)snprintf(out + oi, out_size - oi, "SOL_SOCKET");
        else
            oi += (size_t)snprintf(out + oi, out_size - oi, "0x%x", (unsigned int)c->cmsg_level);

        if (oi >= out_size)
            break;

        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) {
            size_t data_len = c->cmsg_len > CMSG_LEN(0) ? c->cmsg_len - CMSG_LEN(0) : 0;
            size_t num_fds = data_len / sizeof(int);
            oi += (size_t)snprintf(out + oi, out_size - oi, ", cmsg_type=SCM_RIGHTS, cmsg_data=[");
            unsigned char *data = CMSG_DATA(c);
            for (size_t i = 0; i < num_fds && oi < out_size; i++) {
                int fd;
                memcpy(&fd, data + i * sizeof(int), sizeof(int));
                oi += (size_t)snprintf(out + oi, out_size - oi, "%s%d", i ? ", " : "", fd);
            }
            if (oi < out_size)
                oi += (size_t)snprintf(out + oi, out_size - oi, "]}");
        } else if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_CREDENTIALS &&
                   c->cmsg_len >= CMSG_LEN(sizeof(struct ucred))) {
            struct ucred cred;
            memcpy(&cred, CMSG_DATA(c), sizeof(cred));
            oi += (size_t)snprintf(out + oi, out_size - oi,
                                    ", cmsg_type=SCM_CREDENTIALS, cmsg_data={pid=%d, uid=%u, gid=%u}}",
                                    (int)cred.pid, (unsigned int)cred.uid, (unsigned int)cred.gid);
        } else {
            oi += (size_t)snprintf(out + oi, out_size - oi, ", cmsg_type=0x%x, cmsg_len=%zu}",
                                    (unsigned int)c->cmsg_type, (size_t)c->cmsg_len);
        }
        first = 0;
    }
    if (oi < out_size)
        snprintf(out + oi, out_size - oi, "]");
}

/* sendmsg/recvmsg's struct msghdr argument. sendmsg's msghdr is
 * fully populated by the caller before the syscall runs (outgoing
 * address, data, and ancillary data are all already in place), so
 * it's decoded at the entry-stop like connect/bind/sendto's
 * sockaddr; recvmsg's is only meaningful *after* the syscall
 * returns (the kernel fills in the sender's address, the actual
 * received bytes, ancillary data, and msg_flags), so it's decoded
 * at the exit-stop like accept/getsockname's sockaddr — same
 * function either way, called from two different points in
 * mini_strace.c.
 *
 * total_bytes distinguishes the two cases for msg_iov: -1 means
 * "trust each iovec's iov_len as given" (sendmsg — that's the
 * caller's own outgoing data). A value >= 0 (recvmsg's return
 * value) means the kernel only reports the *total* bytes received
 * across every iovec, not per-iovec, so this walks the iovecs in
 * order consuming that budget the same way the kernel itself filled
 * them, the same convention real strace uses for recvmsg/readv. */
#define MSGHDR_MAX_IOV 8

void format_msghdr(pid_t pid, unsigned long long addr, long total_bytes,
                    char *out, size_t out_size) {
    if (addr == 0) {
        snprintf(out, out_size, "NULL");
        return;
    }

    struct msghdr hdr;
    if (read_child_raw(pid, addr, (unsigned char *)&hdr, sizeof(hdr)) < sizeof(hdr)) {
        snprintf(out, out_size, "0x%llx", addr);
        return;
    }

    size_t oi = (size_t)snprintf(out, out_size, "{msg_name=");

    if (hdr.msg_name != NULL && oi < out_size) {
        char namebuf[STR_ARG_BUF_LEN];
        format_sockaddr(pid, (unsigned long long)(uintptr_t)hdr.msg_name,
                         hdr.msg_namelen, namebuf, sizeof(namebuf));
        oi += (size_t)snprintf(out + oi, out_size - oi, "%s", namebuf);
    } else if (oi < out_size) {
        oi += (size_t)snprintf(out + oi, out_size - oi, "NULL");
    }

    if (oi < out_size)
        oi += (size_t)snprintf(out + oi, out_size - oi, ", msg_iov=[");

    size_t iov_count = (size_t)hdr.msg_iovlen;
    int truncated_iov = iov_count > MSGHDR_MAX_IOV;
    if (truncated_iov)
        iov_count = MSGHDR_MAX_IOV;

    long remaining_bytes = total_bytes;
    for (size_t i = 0; i < iov_count && oi < out_size; i++) {
        struct iovec iov;
        unsigned long long iov_addr = (unsigned long long)(uintptr_t)hdr.msg_iov + i * sizeof(struct iovec);
        if (read_child_raw(pid, iov_addr, (unsigned char *)&iov, sizeof(iov)) < sizeof(iov))
            break;

        unsigned long long show_len = (unsigned long long)iov.iov_len;
        if (total_bytes >= 0) {
            unsigned long long avail = remaining_bytes > 0 ? (unsigned long long)remaining_bytes : 0;
            if (show_len > avail)
                show_len = avail;
            remaining_bytes -= (long)show_len;
        }

        char iovbuf[STR_ARG_BUF_LEN];
        read_child_buffer(pid, (unsigned long long)(uintptr_t)iov.iov_base, show_len,
                           iovbuf, sizeof(iovbuf));
        oi += (size_t)snprintf(out + oi, out_size - oi, "%s{iov_base=%s, iov_len=%zu}",
                                i ? ", " : "", iovbuf, (size_t)iov.iov_len);
    }
    if (truncated_iov && oi < out_size)
        oi += (size_t)snprintf(out + oi, out_size - oi, ", ...");
    if (oi < out_size)
        oi += (size_t)snprintf(out + oi, out_size - oi, "]");

    if (oi < out_size)
        oi += (size_t)snprintf(out + oi, out_size - oi, ", msg_control=");
    if (hdr.msg_control != NULL && hdr.msg_controllen > 0 && oi < out_size) {
        char cbuf[STR_ARG_BUF_LEN];
        format_cmsg(pid, (unsigned long long)(uintptr_t)hdr.msg_control,
                     (size_t)hdr.msg_controllen, cbuf, sizeof(cbuf));
        oi += (size_t)snprintf(out + oi, out_size - oi, "%s", cbuf);
    } else if (oi < out_size) {
        oi += (size_t)snprintf(out + oi, out_size - oi, "NULL");
    }

    if (oi < out_size) {
        char flagbuf[128];
        format_msg_flags_value(hdr.msg_flags, flagbuf, sizeof(flagbuf));
        snprintf(out + oi, out_size - oi, ", msg_flags=%s}", flagbuf);
    }
}

/* stat/lstat/fstat/newfstatat's output struct stat, only meaningful
 * *after* the syscall returns (deferred to the exit-stop, like
 * accept's sockaddr or recvmsg's msghdr) — struct stat is read
 * directly into a local struct the same way struct msghdr is in
 * format_msghdr(), rather than hand-decoding field offsets: it's an
 * ordinary type this file already includes via <sys/stat.h>, and
 * ptrace only ever traces a process on the same machine and
 * architecture, so the tracee's layout matches the tracer's own
 * exactly — including the parts of the layout (field widths,
 * padding) that actually differ between x86-64 and aarch64, since
 * whichever one this is built for is the one whose <sys/stat.h> got
 * compiled in.
 *
 * Only st_mode (file type + permission bits), st_size, st_nlink,
 * st_uid, and st_gid are decoded — the fields most worth seeing at
 * a glance. Timestamps aren't: converting st_atime/st_mtime/
 * st_ctime into anything more readable than a raw epoch integer
 * would need real time formatting, which is more machinery than
 * this project's other decoders take on for one struct's fields. */
static const char *stat_file_type_name(mode_t mode) {
    switch (mode & S_IFMT) {
        case S_IFREG:  return "S_IFREG";
        case S_IFDIR:  return "S_IFDIR";
        case S_IFCHR:  return "S_IFCHR";
        case S_IFBLK:  return "S_IFBLK";
        case S_IFIFO:  return "S_IFIFO";
        case S_IFLNK:  return "S_IFLNK";
        case S_IFSOCK: return "S_IFSOCK";
        default:       return NULL;
    }
}

void format_stat_buf(pid_t pid, unsigned long long addr, char *out, size_t out_size) {
    if (addr == 0) {
        snprintf(out, out_size, "NULL");
        return;
    }

    struct stat st;
    if (read_child_raw(pid, addr, (unsigned char *)&st, sizeof(st)) < sizeof(st)) {
        snprintf(out, out_size, "0x%llx", addr);
        return;
    }

    const char *type_name = stat_file_type_name(st.st_mode);
    size_t oi;
    if (type_name != NULL)
        oi = (size_t)snprintf(out, out_size, "{st_mode=%s|0%o", type_name,
                               (unsigned int)(st.st_mode & ~(mode_t)S_IFMT));
    else
        oi = (size_t)snprintf(out, out_size, "{st_mode=0%o", (unsigned int)st.st_mode);

    if (oi < out_size)
        oi += (size_t)snprintf(out + oi, out_size - oi, ", st_size=%lld", (long long)st.st_size);
    if (oi < out_size)
        oi += (size_t)snprintf(out + oi, out_size - oi, ", st_nlink=%llu",
                                (unsigned long long)st.st_nlink);
    if (oi < out_size)
        oi += (size_t)snprintf(out + oi, out_size - oi, ", st_uid=%u", (unsigned int)st.st_uid);
    if (oi < out_size)
        snprintf(out + oi, out_size - oi, ", st_gid=%u}", (unsigned int)st.st_gid);
}

/* getdents64()'s output buffer, only meaningful *after* the syscall
 * returns (deferred to the exit-stop, like read()'s buffer) —
 * unlike read(), the returned bytes aren't raw data to dump, they're
 * a packed sequence of directory entries to parse.
 *
 * The kernel's wire format (struct linux_dirent64, from getdents64(2))
 * isn't exposed by any glibc header — glibc only exposes the higher-
 * level opendir()/readdir() API built on top of it — so unlike
 * struct stat/msghdr above, there's no real local type to overlay
 * onto a read_child_raw() copy. Fields are read at their fixed
 * byte offsets instead, the same approach format_clone3_flags() uses
 * for struct clone_args, another kernel-only type with no glibc
 * declaration. This wire format has no architecture-specific
 * variants (unlike struct stat/clone_args) — getdents64 has used one
 * fixed 64-bit layout across every architecture since it was added:
 *
 *   u64            d_ino;     offset 0
 *   s64            d_off;     offset 8
 *   unsigned short d_reclen;  offset 16
 *   unsigned char  d_type;    offset 18
 *   char           d_name[];  offset 19, NUL-terminated, padded to
 *                             fill out d_reclen bytes
 *
 * Entries are packed back-to-back with no separator; d_reclen (each
 * entry's own size, header included) is how far to advance to reach
 * the next one, so malformed data (a d_reclen too small to hold a
 * header, or one that would read past the bytes actually returned)
 * just stops parsing rather than reading garbage. */
#define GETDENTS_HEADER_SIZE 19
#define GETDENTS_MAX_BYTES 4096
#define GETDENTS_MAX_ENTRIES 8

static const char *dirent_type_name(unsigned char d_type) {
    switch (d_type) {
        case DT_REG:  return "DT_REG";
        case DT_DIR:  return "DT_DIR";
        case DT_LNK:  return "DT_LNK";
        case DT_CHR:  return "DT_CHR";
        case DT_BLK:  return "DT_BLK";
        case DT_FIFO: return "DT_FIFO";
        case DT_SOCK: return "DT_SOCK";
        default:      return "DT_UNKNOWN";
    }
}

void format_getdents_buf(pid_t pid, unsigned long long addr, long ret, char *out, size_t out_size) {
    if (ret <= 0) {
        snprintf(out, out_size, "0x%llx", addr);
        return;
    }

    size_t want = (size_t)ret < GETDENTS_MAX_BYTES ? (size_t)ret : GETDENTS_MAX_BYTES;
    unsigned char buf[GETDENTS_MAX_BYTES];
    size_t got = read_child_raw(pid, addr, buf, want);
    if (got < GETDENTS_HEADER_SIZE) {
        snprintf(out, out_size, "0x%llx", addr);
        return;
    }

    size_t oi = (size_t)snprintf(out, out_size, "[");
    size_t pos = 0;
    int count = 0;
    int more = 0;

    while (pos + GETDENTS_HEADER_SIZE <= got) {
        unsigned long long d_ino;
        long long d_off;
        unsigned short d_reclen;
        memcpy(&d_ino, buf + pos, 8);
        memcpy(&d_off, buf + pos + 8, 8);
        memcpy(&d_reclen, buf + pos + 16, 2);
        unsigned char d_type = buf[pos + 18];

        if (d_reclen < GETDENTS_HEADER_SIZE || pos + d_reclen > got) {
            more = 1;
            break;
        }
        if (count >= GETDENTS_MAX_ENTRIES) {
            more = 1;
            break;
        }

        size_t name_cap = d_reclen - GETDENTS_HEADER_SIZE;
        size_t name_len = strnlen((const char *)(buf + pos + GETDENTS_HEADER_SIZE), name_cap);

        if (oi < out_size)
            oi += (size_t)snprintf(out + oi, out_size - oi,
                    "%s{d_ino=%llu, d_off=%lld, d_reclen=%u, d_name=\"%.*s\", d_type=%s}",
                    count ? ", " : "", d_ino, d_off, (unsigned int)d_reclen,
                    (int)name_len, (const char *)(buf + pos + GETDENTS_HEADER_SIZE),
                    dirent_type_name(d_type));

        pos += d_reclen;
        count++;
    }

    if (pos < got)
        more = 1;
    if (more && oi < out_size)
        oi += (size_t)snprintf(out + oi, out_size - oi, "%s...", count ? ", " : "");
    if (oi < out_size)
        snprintf(out + oi, out_size - oi, "]");
}

/* rt_sigaction()'s act/oldact struct sigaction arguments. glibc's
 * userspace struct sigaction (from <signal.h>) is NOT what the raw
 * syscall actually reads or writes: glibc's sigaction() wrapper
 * translates between its own struct — sa_handler, then a 128-byte
 * sa_mask (16 unsigned longs, room for 1024 signals), then sa_flags,
 * then sa_restorer — and the kernel's actual on-the-wire layout,
 * which is smaller and in a different field order. Overlaying
 * glibc's type onto a read_child_raw() copy the way format_stat_buf()
 * safely does for struct stat would silently read the wrong bytes
 * into the wrong fields here — struct stat has no such translation
 * layer, struct sigaction does.
 *
 * The kernel's real layout (verified empirically for this project:
 * a raw syscall(SYS_rt_sigaction, ...) call using exactly this
 * struct, followed immediately by a second call reading it back via
 * oldact, round-trips every field correctly on both x86-64 and
 * aarch64 — not taken from documentation alone) is four consecutive
 * word-sized fields:
 *
 *   unsigned long sa_handler;   offset 0
 *   unsigned long sa_flags;     offset 8
 *   unsigned long sa_restorer;  offset 16
 *   unsigned long sa_mask;      offset 24  (one word: sigsetsize is
 *                                           8 on every real call this
 *                                           project's syscalls see)
 *
 * This is a plain C struct this project defines itself (no glibc or
 * kernel header exposes it under this shape), safe to overlay onto
 * a read_child_raw() copy the same way struct stat/msghdr are:
 * every field is an 8-byte-aligned unsigned long, so there's no
 * compiler-inserted padding to worry about regardless of
 * architecture.
 *
 * Field names deliberately avoid sa_handler/sa_flags/sa_mask:
 * glibc's own <bits/sigaction.h> #defines those exact names as
 * macros (sa_handler expands to a union member access, part of how
 * glibc's *userspace* struct sigaction supports both a plain
 * handler and a sa_sigaction callback through the same field), and
 * with _GNU_SOURCE already pulling that header in, those macros are
 * active here too — naming a field sa_handler would silently rewrite
 * it to something that doesn't exist in this struct at all. */
struct kernel_sigaction {
    unsigned long handler;
    unsigned long flags;
    unsigned long restorer;
    unsigned long mask;
};

/* sa_flags — a plain OR-of-bits walk like every other flags argument
 * in this file. SA_RESTORER is glibc's own bookkeeping (it always
 * sets this and supplies a real restorer trampoline) rather than
 * something a caller chooses, but it's a real bit the kernel
 * actually stores, so it's included rather than filtered out. */
static const flag_entry sigaction_flag_table[] = {
    { SA_NOCLDSTOP, "SA_NOCLDSTOP" },
    { SA_NOCLDWAIT, "SA_NOCLDWAIT" },
    { SA_SIGINFO,   "SA_SIGINFO" },
    { SA_ONSTACK,   "SA_ONSTACK" },
    { SA_RESTART,   "SA_RESTART" },
    { SA_NODEFER,   "SA_NODEFER" },
    { SA_RESETHAND, "SA_RESETHAND" },
#ifdef SA_RESTORER
    { SA_RESTORER,  "SA_RESTORER" },
#endif
    { 0,            NULL },
};

static void format_sigaction_flags_value(unsigned long flags, char *out, size_t out_size) {
    if (flags == 0) {
        snprintf(out, out_size, "0");
        return;
    }
    unsigned long long remaining = flags;
    size_t oi = 0;
    for (int i = 0; sigaction_flag_table[i].name != NULL && oi < out_size; i++) {
        if ((remaining & sigaction_flag_table[i].value) == sigaction_flag_table[i].value) {
            oi += (size_t)snprintf(out + oi, out_size - oi, "%s%s", oi ? "|" : "", sigaction_flag_table[i].name);
            remaining &= ~sigaction_flag_table[i].value;
        }
    }
    if (remaining != 0 && oi < out_size)
        snprintf(out + oi, out_size - oi, "%s0x%llx", oi ? "|" : "", remaining);
}

/* sa_mask — which signals are blocked while the handler runs, shown
 * as a bracketed list of names the way real strace shows a sigset,
 * e.g. "[SIGINT SIGTERM]", "[]" when empty. One word (64 signals) is
 * all this project ever reads, matching the fixed sigsetsize every
 * real call here uses. */
static void format_sigset_value(unsigned long mask, char *out, size_t out_size) {
    size_t oi = (size_t)snprintf(out, out_size, "[");
    int first = 1;
    for (int sig = 1; sig <= 64 && oi < out_size; sig++) {
        if (!(mask & (1ULL << (sig - 1))))
            continue;
        const char *abbrev = sigabbrev_np(sig);
        if (abbrev != NULL)
            oi += (size_t)snprintf(out + oi, out_size - oi, "%sSIG%s", first ? "" : " ", abbrev);
        else
            oi += (size_t)snprintf(out + oi, out_size - oi, "%s%d", first ? "" : " ", sig);
        first = 0;
    }
    if (oi < out_size)
        snprintf(out + oi, out_size - oi, "]");
}

void format_sigaction(pid_t pid, unsigned long long addr, char *out, size_t out_size) {
    if (addr == 0) {
        snprintf(out, out_size, "NULL");
        return;
    }

    struct kernel_sigaction sa;
    if (read_child_raw(pid, addr, (unsigned char *)&sa, sizeof(sa)) < sizeof(sa)) {
        snprintf(out, out_size, "0x%llx", addr);
        return;
    }

    size_t oi = (size_t)snprintf(out, out_size, "{sa_handler=");
    if (sa.handler == (unsigned long)SIG_DFL)
        oi += (size_t)snprintf(out + oi, out_size - oi, "SIG_DFL");
    else if (sa.handler == (unsigned long)SIG_IGN)
        oi += (size_t)snprintf(out + oi, out_size - oi, "SIG_IGN");
    else
        oi += (size_t)snprintf(out + oi, out_size - oi, "0x%lx", sa.handler);

    if (oi < out_size) {
        char flagbuf[256];
        format_sigaction_flags_value(sa.flags, flagbuf, sizeof(flagbuf));
        oi += (size_t)snprintf(out + oi, out_size - oi, ", sa_flags=%s", flagbuf);
    }

    if (oi < out_size) {
        char maskbuf[512];
        format_sigset_value(sa.mask, maskbuf, sizeof(maskbuf));
        snprintf(out + oi, out_size - oi, ", sa_mask=%s}", maskbuf);
    }
}

/* clock_gettime/clock_settime/nanosleep/clock_nanosleep's struct
 * timespec arguments. Unlike struct sigaction above, there's no
 * glibc-vs-kernel translation layer to worry about here: glibc's
 * userspace struct timespec (<time.h>) is passed straight through
 * to these syscalls unchanged, the same situation struct stat and
 * struct msghdr are in, so overlaying it onto a read_child_raw()
 * copy is safe without needing the kind of empirical ABI
 * verification struct sigaction required. */
void format_timespec(pid_t pid, unsigned long long addr, char *out, size_t out_size) {
    if (addr == 0) {
        snprintf(out, out_size, "NULL");
        return;
    }

    struct timespec ts;
    if (read_child_raw(pid, addr, (unsigned char *)&ts, sizeof(ts)) < sizeof(ts)) {
        snprintf(out, out_size, "0x%llx", addr);
        return;
    }

    snprintf(out, out_size, "{tv_sec=%lld, tv_nsec=%lld}",
             (long long)ts.tv_sec, (long long)ts.tv_nsec);
}

/* wait4's output struct rusage, only meaningful *after* the syscall
 * returns (deferred to the exit-stop, like wstatus in the same
 * call). Like struct stat/timespec, and unlike struct sigaction,
 * there's no glibc-vs-kernel translation for struct rusage — it's
 * passed straight through unchanged — so overlaying glibc's own
 * type (<sys/resource.h>) onto a read_child_raw() copy is safe.
 *
 * Only ru_utime/ru_stime (CPU time actually used) and ru_maxrss
 * (peak memory) are decoded — the fields most worth seeing at a
 * glance, the same call this project already made for struct stat.
 * The other dozen-odd counters (page faults, swaps, IPC messages,
 * context switches, ...) are rarely examined and would mostly add
 * noise. */
void format_rusage(pid_t pid, unsigned long long addr, char *out, size_t out_size) {
    if (addr == 0) {
        snprintf(out, out_size, "NULL");
        return;
    }

    struct rusage ru;
    if (read_child_raw(pid, addr, (unsigned char *)&ru, sizeof(ru)) < sizeof(ru)) {
        snprintf(out, out_size, "0x%llx", addr);
        return;
    }

    snprintf(out, out_size,
             "{ru_utime={tv_sec=%lld, tv_usec=%lld}, ru_stime={tv_sec=%lld, tv_usec=%lld}, ru_maxrss=%ld}",
             (long long)ru.ru_utime.tv_sec, (long long)ru.ru_utime.tv_usec,
             (long long)ru.ru_stime.tv_sec, (long long)ru.ru_stime.tv_usec,
             ru.ru_maxrss);
}

/* epoll_ctl()'s op argument — a plain enum lookup like fcntl's cmd,
 * not bits to OR. */
static const flag_entry epoll_op_table[] = {
    { EPOLL_CTL_ADD, "EPOLL_CTL_ADD" },
    { EPOLL_CTL_DEL, "EPOLL_CTL_DEL" },
    { EPOLL_CTL_MOD, "EPOLL_CTL_MOD" },
    { 0,             NULL },
};

void format_epoll_op(unsigned long long value, char *out, size_t out_size) {
    for (int i = 0; epoll_op_table[i].name != NULL; i++) {
        if (epoll_op_table[i].value == value) {
            snprintf(out, out_size, "%s", epoll_op_table[i].name);
            return;
        }
    }
    snprintf(out, out_size, "0x%llx", value);
}

/* epoll_ctl()'s event argument and epoll_wait()'s output array
 * share this one struct epoll_event shape. Unlike struct sigaction,
 * there's no glibc-wrapper translation between userspace and
 * kernel here — struct epoll_event is a direct passthrough, and
 * glibc's own <sys/epoll.h> already declares it with whatever
 * packing each architecture's kernel ABI actually expects (x86-64's
 * kernel ABI famously packs it to 12 bytes to preserve a 32-bit-era
 * layout; other architectures, aarch64 included, use the natural
 * 16-byte layout instead). Always using sizeof(struct epoll_event)
 * rather than a hardcoded size means the correct stride for
 * whichever architecture this is built for falls out automatically,
 * the same reasoning already relied on for struct stat's layout
 * differing across architectures.
 *
 * The data field is a union (fd/u32/u64/pointer) with no way to
 * know from the trace alone which member the caller actually meant
 * to use, so — matching what real strace does here — both integer
 * interpretations are shown rather than guessing one. */
static const flag_entry epoll_events_flag_table[] = {
    { EPOLLIN,      "EPOLLIN" },
    { EPOLLOUT,     "EPOLLOUT" },
    { EPOLLPRI,     "EPOLLPRI" },
    { EPOLLERR,     "EPOLLERR" },
    { EPOLLHUP,     "EPOLLHUP" },
    { EPOLLRDNORM,  "EPOLLRDNORM" },
    { EPOLLRDBAND,  "EPOLLRDBAND" },
    { EPOLLWRNORM,  "EPOLLWRNORM" },
    { EPOLLWRBAND,  "EPOLLWRBAND" },
    { EPOLLMSG,     "EPOLLMSG" },
    { EPOLLRDHUP,   "EPOLLRDHUP" },
#ifdef EPOLLEXCLUSIVE
    { EPOLLEXCLUSIVE, "EPOLLEXCLUSIVE" },
#endif
#ifdef EPOLLWAKEUP
    { EPOLLWAKEUP,  "EPOLLWAKEUP" },
#endif
    { EPOLLONESHOT, "EPOLLONESHOT" },
    { EPOLLET,      "EPOLLET" },
    { 0,            NULL },
};

static void format_epoll_events_value(uint32_t events, char *out, size_t out_size) {
    if (events == 0) {
        snprintf(out, out_size, "0");
        return;
    }
    unsigned long long remaining = events;
    size_t oi = 0;
    for (int i = 0; epoll_events_flag_table[i].name != NULL && oi < out_size; i++) {
        if ((remaining & epoll_events_flag_table[i].value) == epoll_events_flag_table[i].value) {
            oi += (size_t)snprintf(out + oi, out_size - oi, "%s%s", oi ? "|" : "", epoll_events_flag_table[i].name);
            remaining &= ~epoll_events_flag_table[i].value;
        }
    }
    if (remaining != 0 && oi < out_size)
        snprintf(out + oi, out_size - oi, "%s0x%llx", oi ? "|" : "", remaining);
}

static void format_one_epoll_event(const struct epoll_event *ev, char *out, size_t out_size) {
    char eventsbuf[256];
    format_epoll_events_value(ev->events, eventsbuf, sizeof(eventsbuf));
    snprintf(out, out_size, "{events=%s, data={u32=%u, u64=%llu}}",
             eventsbuf, ev->data.u32, (unsigned long long)ev->data.u64);
}

void format_epoll_event(pid_t pid, unsigned long long addr, char *out, size_t out_size) {
    if (addr == 0) {
        snprintf(out, out_size, "NULL");
        return;
    }

    struct epoll_event ev;
    if (read_child_raw(pid, addr, (unsigned char *)&ev, sizeof(ev)) < sizeof(ev)) {
        snprintf(out, out_size, "0x%llx", addr);
        return;
    }

    format_one_epoll_event(&ev, out, out_size);
}

/* epoll_wait()'s output array of struct epoll_event, only
 * meaningful *after* the syscall returns — ret is how many entries
 * the kernel actually filled in, not maxevents (the buffer's
 * declared capacity). Capped at 8 rendered entries, with a trailing
 * "..." past that, the same convention format_getdents_buf() and
 * format_msghdr()'s iovec array use. */
#define EPOLL_EVENTS_MAX_ENTRIES 8

void format_epoll_events_buf(pid_t pid, unsigned long long addr, long ret, char *out, size_t out_size) {
    if (ret <= 0) {
        snprintf(out, out_size, "0x%llx", addr);
        return;
    }

    size_t count = (size_t)ret;
    int truncated = count > EPOLL_EVENTS_MAX_ENTRIES;
    if (truncated)
        count = EPOLL_EVENTS_MAX_ENTRIES;

    size_t oi = (size_t)snprintf(out, out_size, "[");
    for (size_t i = 0; i < count && oi < out_size; i++) {
        struct epoll_event ev;
        unsigned long long ev_addr = addr + i * sizeof(ev);
        if (read_child_raw(pid, ev_addr, (unsigned char *)&ev, sizeof(ev)) < sizeof(ev))
            break;

        char evbuf[256];
        format_one_epoll_event(&ev, evbuf, sizeof(evbuf));
        oi += (size_t)snprintf(out + oi, out_size - oi, "%s%s", i ? ", " : "", evbuf);
    }
    if (truncated && oi < out_size)
        oi += (size_t)snprintf(out + oi, out_size - oi, ", ...");
    if (oi < out_size)
        snprintf(out + oi, out_size - oi, "]");
}

/* poll()'s fds argument — a genuinely different shape from every
 * other buffer/array this file decodes: it's populated by the
 * caller before the syscall runs (each entry's fd and events), but
 * every entry's revents field is then overwritten by the kernel
 * before the syscall returns, so the same array is both an input
 * and an output on the very same call. Deferred to the exit-stop
 * like every other kernel-populated argument, showing both the
 * caller's original events and the kernel's revents together,
 * rather than showing the array twice (once at entry without
 * revents, once at exit with it) the way two separate arguments
 * would be handled.
 *
 * struct pollfd (<poll.h>) is a small, fixed-width struct (int fd;
 * short events; short revents;) passed by pointer straight through
 * to the kernel unchanged — no libc-wrapper translation the way
 * struct sigaction has, no cross-architecture packing difference
 * the way struct epoll_event has — so overlaying it onto a
 * read_child_raw() copy per entry is safe without further
 * verification. nfds (the array length) is the caller's own count,
 * not the return value — unlike getdents64/epoll_wait, where the
 * return value says how many entries are actually valid, every
 * struct pollfd the caller declared is meaningful here regardless
 * of how many actually saw activity (the kernel zeroes revents for
 * the rest, not leaving them undefined). */
static const flag_entry poll_events_flag_table[] = {
    { POLLIN,     "POLLIN" },
    { POLLPRI,    "POLLPRI" },
    { POLLOUT,    "POLLOUT" },
    { POLLERR,    "POLLERR" },
    { POLLHUP,    "POLLHUP" },
    { POLLNVAL,   "POLLNVAL" },
    { POLLRDNORM, "POLLRDNORM" },
    { POLLRDBAND, "POLLRDBAND" },
    { POLLWRNORM, "POLLWRNORM" },
    { POLLWRBAND, "POLLWRBAND" },
#ifdef POLLRDHUP
    { POLLRDHUP,  "POLLRDHUP" },
#endif
    { 0,          NULL },
};

static void format_poll_events_value(short events, char *out, size_t out_size) {
    if (events == 0) {
        snprintf(out, out_size, "0");
        return;
    }
    unsigned long long remaining = (unsigned short)events;
    size_t oi = 0;
    for (int i = 0; poll_events_flag_table[i].name != NULL && oi < out_size; i++) {
        if ((remaining & poll_events_flag_table[i].value) == poll_events_flag_table[i].value) {
            oi += (size_t)snprintf(out + oi, out_size - oi, "%s%s", oi ? "|" : "", poll_events_flag_table[i].name);
            remaining &= ~poll_events_flag_table[i].value;
        }
    }
    if (remaining != 0 && oi < out_size)
        snprintf(out + oi, out_size - oi, "%s0x%llx", oi ? "|" : "", remaining);
}

#define POLLFDS_MAX_ENTRIES 8

void format_pollfds_buf(pid_t pid, unsigned long long addr, unsigned long long nfds,
                         char *out, size_t out_size) {
    if (addr == 0) {
        snprintf(out, out_size, "NULL");
        return;
    }

    int truncated = nfds > POLLFDS_MAX_ENTRIES;
    size_t count = truncated ? POLLFDS_MAX_ENTRIES : (size_t)nfds;

    size_t oi = (size_t)snprintf(out, out_size, "[");
    for (size_t i = 0; i < count && oi < out_size; i++) {
        struct pollfd pfd;
        unsigned long long pfd_addr = addr + i * sizeof(pfd);
        if (read_child_raw(pid, pfd_addr, (unsigned char *)&pfd, sizeof(pfd)) < sizeof(pfd))
            break;

        char eventsbuf[128];
        format_poll_events_value(pfd.events, eventsbuf, sizeof(eventsbuf));
        char reventsbuf[128];
        format_poll_events_value(pfd.revents, reventsbuf, sizeof(reventsbuf));
        oi += (size_t)snprintf(out + oi, out_size - oi, "%s{fd=%d, events=%s, revents=%s}",
                                i ? ", " : "", pfd.fd, eventsbuf, reventsbuf);
    }
    if (truncated && oi < out_size)
        oi += (size_t)snprintf(out + oi, out_size - oi, ", ...");
    if (oi < out_size)
        snprintf(out + oi, out_size - oi, "]");
}
