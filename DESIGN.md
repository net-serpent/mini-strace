# Design notes

Internals: source layout, ptrace mechanics, and the reasoning behind
each decoder. For usage, see [README.md](README.md).

## Source layout

- `src/mini_strace.c`: the tracer loop (`run_tracer()`), per-tracee
  state, the `-c` summary table, `main()`'s argument parsing.
- `src/arch.h`: x86-64/ARM64 register access. Header-only: small,
  purely `static`, used only by `run_tracer()`.
- `src/arg_routing.{c,h}`: lookup tables mapping syscall name to
  which argument slot(s) hold a value of a given kind. Says where to
  look, not how to read or format what is there.
- `src/child_mem.{c,h}`: `PTRACE_PEEKDATA` primitives that read
  bytes out of the traced process's address space: strings, buffers,
  `argv`/`envp` arrays, raw structs.
- `src/decoders.{c,h}`: formatting a raw value once `arg_routing`
  has identified the argument. Every `format_*` function and its
  value-to-name table (`O_*`, `PROT_*`, `AF_*`, signal names, etc).

`arg_routing` and `trace_filter` (the `-e trace=SET` machinery, also
its own module) have no dependency on anything else in the project.
`decoders` depends on `child_mem` to dereference pointers it is
given. `mini_strace.c` depends on all four modules plus `arch.h`.

## ptrace mechanics

The child calls `PTRACE_TRACEME`, then `SIGSTOP`s itself before
`execvp`. The parent waits for that stop, then loops on
`PTRACE_SYSCALL`, which stops the child at every syscall entry and
exit and lets the tracer read its registers in between.

x86-64 and ARM64 use different register names, different
`ptrace()` calls to fetch them (`PTRACE_GETREGS` vs
`PTRACE_GETREGSET`), different registers for the arguments, and
different syscall numbering. All of that is behind `#ifdef
__x86_64__` / `#ifdef __aarch64__` in `arch.h`.

## Syscall name table

`scripts/gen_syscall_table.sh` preprocesses the platform's syscall
header with gcc and extracts the `__NR_*` defines, avoiding a
hardcoded header path (the path differs across toolchains and
distros). A few syscalls (`mmap`, `stat`, `fstat`) resolve through a
level of indirection (`__NR_mmap` -> `__NR3264_mmap` -> `222`); the
generator follows that chain. The table is regenerated on every
`make` and is not committed, since it must match the build machine.

## Argument count: syscall_argc_table

Every syscall's raw arguments live in 6 fixed registers regardless
of how many of them the syscall actually uses — the ABI doesn't
distinguish "unused" from "zero". Originally this codebase printed
all 6 unconditionally, so `access(path, mode)` showed 4 extra fields
that were just whatever those registers happened to hold at the
time, and a 0-argument syscall like `getpid` showed 6 of them.

`syscall_argc()` (`arg_routing.c`) is a lookup from syscall name to
its real argument count, and `print_call()` (`mini_strace.c`) uses
it to print only that many of the 6 formatted `argbuf` slots instead
of always all 6; a name it doesn't recognize falls back to the old
behavior (all 6), rather than guessing.

Counts are the *raw kernel syscall*'s arity, not the glibc wrapper
function's — these occasionally differ. `fchmodat`'s libc wrapper
takes a 4th `flags` argument that the actual `fchmodat` syscall
doesn't have (flags support needs the newer `fchmodat2` syscall
instead, which glibc falls back from only when the kernel supports
it); tracing the raw syscall this project actually sees means the
real arity is 3, matching the kernel, not 4.

The table isn't exhaustive over every Linux syscall (there are
hundreds, and this project has no way to verify correctness against
real behavior for ones nobody's actually traced with it). It covers
every syscall this codebase already has dedicated argument decoding
for elsewhere in this file — their real signatures already had to
be known to write that decoding — plus a short list of syscalls
that show up in essentially every trace regardless of what's being
run (`brk`, `mmap`/`munmap`, process/thread info like `getpid`,
`exit_group`, and similar startup bookkeeping).

Verifying this against real traces in this project's aarch64 dev
container surfaced a portability trap: aarch64's generic syscall ABI
dropped several legacy syscalls entirely, so `access()` on aarch64
actually runs as a `faccessat(AT_FDCWD, path, mode)` call under the
hood (3 real arguments) rather than the 2-argument `access` syscall
x86-64 still has, and `vfork()` doesn't exist there as its own raw
syscall at all (aarch64 only implements vfork semantics via
`clone(CLONE_VFORK, ...)`). Both counts are correct, they just apply
to different underlying syscalls depending on which architecture
actually ran the trace; `syscall_argc_table` carries entries for
both names with their own correct arity, and nothing resolves one
name to the other.

## Deferred prints: read(), sockaddr, wait4

`write()`'s buffer has real data at the entry-stop, so it prints
immediately. `read()`'s buffer is empty at that point; the tracer
defers printing to the exit-stop and uses the return value (actual
byte count) as the dump length.

`accept`/`accept4`/`getsockname`/`getpeername`/`recvfrom`'s sockaddr
is the same case: empty until the syscall returns. It goes through
the same entry/exit deferral, tracked in `pending_sockaddr_entry`
alongside `read()`'s `pending_read_entry`. The `socklen_t *`
reporting how much of the struct is real is itself only valid after
the call, so it is re-read via `ptrace` at the exit-stop rather than
trusted from entry.

`recvfrom` needs both deferrals on the same call: a data buffer and
a sockaddr, each populated only after the syscall returns. It is the
only syscall in both `read_arg_table` and `accept_arg_table`. The
pending-state fields are not mutually exclusive: the exit-stop print
checks each of the 6 argument slots against all of them, so any
combination renders into the same line.

`wait4`'s `wstatus` is a third deferred-argument shape: a plain
`int`, not a buffer or struct. It decodes into the
`WIFEXITED`/`WIFSIGNALED`/`WIFSTOPPED` form real `strace` uses via a
single `PTRACE_PEEKDATA`. Tracked in `pending_wait_status_idx`
(an argument-slot index, or `-1`), since there is nothing else to
carry. `waitid()`'s equivalent is a `siginfo_t` and is not covered.

## -e trace=SET

Three hardcoded category tables (file/network/process syscall
names) plus exact-match against the raw syscall name. Not a full
syscall classification database. The tracer still steps through
every syscall regardless of the filter; filtering only decides
whether to print, so a suppressed syscall still needs its entry/exit
bookkeeping kept in sync, it just skips the `printf`.

## -f (follow forks)

Uses `PTRACE_O_TRACEFORK`/`TRACEVFORK`/`TRACECLONE` so new children
auto-attach to the tracer with the same options inherited. The main
loop switches from waiting on one fixed pid to `waitpid(-1, ...)`,
picking up whichever tracee stops next, with a fixed-size table
tracking each pid's entry/exit state independently.

Known limitation: a syscall's `name(args)` and its `= ret` are still
two separate prints, so a different process's line can land between
them when several processes stop near the same time. Cosmetic only;
the data is still present.

## -c (summary)

Reuses the entry/exit timestamps `-T` records, folding each call
into a running total keyed by syscall name instead of printing a
line. Fixed-size table, linear-scan lookup, selection-sorted by
total time once the trace ends, printed as one table.

## -o (output file)

Opens the file in the tracer and threads that `FILE *` through in
place of the hardcoded `stdout`/`stderr`. Opened before `fork()`, so
an exec'd tracee inherits the fd, but only as an extra unused fd
alongside its real 0/1/2. Nothing redirects those, so the tracee's
own I/O is unaffected.

## -s (string/buffer size cap)

Does not resize any buffer at runtime. The raw-read and
escaped-output buffers are fixed 1024-byte stack arrays;
`max_str_len` only caps how much of that buffer gets used.
`ptrace(2)` reads whole machine words (8 bytes) at a time, so the
read window is rounded up to a word boundary before reading, then
the displayed length is clamped to the requested size.

## -y (fd resolution)

Resolves a fd argument via `readlink()` on `/proc/pid/fd/N`. The
symlink target is either a real path or a description such as
`socket:[12345]`/`pipe:[12345]` for fds not backed by a path;
`readlink()` returns either as plain text. A fixed-size table (same
shape as the string-argument table) says which argument slots are
fds per syscall. Negative values (`AT_FDCWD` and similar, passed as
a `*at()` syscall's dirfd) are left as-is rather than treated as a
real fd number.

## execve/execveat argv/envp

Walks the pointer array directly: each slot is its own `char*`,
fetched with its own `PTRACE_PEEKDATA`, then handed to the same
string-reading logic used elsewhere (so `-s` applies per element).
Capped at 32 entries to bound both line length and ptrace call
count for large environments; a trailing `...` marks truncation
past that cap.

## sockaddr decoding: connect/bind/sendto

Reads the raw struct bytes (`read_child_raw()`) and interprets the
first two bytes as `sa_family`, which is host-endian. The port
fields inside `sockaddr_in`/`sockaddr_in6` are network byte order
regardless of host endianness and are unpacked byte by byte rather
than assumed to match host layout. IPv4's address is formatted the
same way (4 bytes); IPv6's 16 bytes are handed to `inet_ntop()`
as-is, since that function takes the address in raw wire form, not
as a host-endian integer. `AF_INET`, `AF_INET6`, and `AF_UNIX` are
decoded; other families show the numeric value.

## open/openat flags

A flat OR of named bits against the real `<fcntl.h>` macros, not
hardcoded numbers (some flags, e.g. `O_LARGEFILE`, have differed
across architectures). The low two bits (`O_RDONLY`/`O_WRONLY`/
`O_RDWR`) are not independent flags; they form a small enum-like
value and are handled separately before the flag table is walked.
`O_SYNC` and `O_TMPFILE` are each an existing flag plus an extra
bit, not independent bits, so they are checked (and consumed)
before their subset flag (`O_DSYNC`, `O_DIRECTORY`) can match; the
wrong table order would print one real flag as two.

## mmap/mprotect PROT_*, mmap MAP_*

Same OR-of-matched-names approach as `open`'s flags, without the
composite-flag or access-mode cases: `PROT_READ`/`PROT_WRITE`/
`PROT_EXEC` and the `MAP_*` flags are independent bits.
`PROT_NONE` (value `0`) is handled as its own named case up front,
the same way `open`'s access mode is, since "no bits matched" and
"the value is legitimately zero" must print differently.

## mount flags

Another plain OR-of-matched-names walk, same shape as `mmap`'s
`MAP_*` flags — `MS_BIND`/`MS_RDONLY`/`MS_REMOUNT`/etc. are
independent bits, not a mutually exclusive enum, so real combinations
like `MS_BIND|MS_RDONLY` (exposing a directory read-only via a bind
mount, a common pattern) decode as both names together. `MS_LAZYTIME`
is guarded with `#ifdef`, the same portability precaution
`CLONE_PIDFD` gets in the `clone`/`clone3` section, for glibc
versions whose `<sys/mount.h>` predates it.

Verified with a real `mount(source, target, NULL, MS_BIND|MS_RDONLY,
NULL)` call. The call itself fails with `EPERM` in this project's
unprivileged dev container (no `CAP_SYS_ADMIN`), which doesn't
matter for this decoder: the flags argument is populated by the
caller before the syscall runs, so it decodes correctly regardless
of whether the call actually succeeds.

## socket/socketpair domain and type

Each is a single enum value, not bits to OR (a socket is never both
`AF_INET` and `AF_UNIX`), so both are table lookups. Type has one
exception: Linux lets `SOCK_CLOEXEC`/`SOCK_NONBLOCK` ride along
OR'd into the same int as the base type (they are `O_CLOEXEC`/
`O_NONBLOCK` reused, chosen because those bits do not overlap any
real socket type's low bits). Those two are peeled off and appended
as separate names; the base type is still a lookup.

## kill/tkill/tgkill signal number

Reuses `sigabbrev_np()`, already used to name a signal being
delivered to the tracee, for the opposite purpose: naming the
signal about to be sent. Signal `0` is special-cased ahead of the
lookup: it is a real value (a "can I signal this pid" existence
check that sends nothing), not a signal name. `rt_sigaction`'s
first argument (which signal's disposition is being configured)
reuses this same decoder — see "rt_sigaction struct sigaction"
below for why it, unlike `kill`/`tkill`/`tgkill`, needs its decode
dispatched from both the entry- and exit-stop.

## lseek whence

The simplest lookup: a straight enum match, no flags to OR, no
zero-vs-no-match ambiguity. `SEEK_SET` being `0` is an ordinary
table entry, not a special case.

## fcntl cmd

Same lookup shape, longer table: `F_DUPFD`, `F_GETFD`/`F_SETFD`,
`F_GETFL`/`F_SETFL`, `F_GETLK`/`F_SETLK`/`F_SETLKW`, and others.
Only `cmd` is decoded. The third argument's meaning depends on
which `cmd` this is (a flags value for `F_SETFL`, a `struct
flock*` for locking commands, ignored for others) and is left as
plain hex.

## rt_sigprocmask how

Same lookup shape as `lseek`/`fcntl`. `SIG_BLOCK` being `0` is not
special-cased for the same reason. Only x86-64 and aarch64 are
supported by this codebase, and neither has a legacy `sigprocmask(2)`
syscall of its own; signal mask changes go through `rt_sigprocmask`
on both, so that is the only syscall name matched.

## access/faccessat mode

An OR-of-bits walk, like `PROT_*`/`MAP_*`: `R_OK`/`W_OK`/`X_OK` are
combinable (checking read+write access is one call with both bits
set). `F_OK` (value `0`) gets the same up-front special case as
`PROT_NONE`.

## clock_gettime/clock_nanosleep clockid

A plain lookup, same as `lseek`/`fcntl`/`rt_sigprocmask`.
`time.time()`/`time.monotonic()` and similar calls in most
languages do not reach this syscall at all: glibc serves them from
the VDSO, a page of code mapped into every process that reads the
kernel's clock data directly, skipping the syscall and context
switch. Slower clocks such as `CLOCK_PROCESS_CPUTIME_ID`, or
anything invoked via `syscall()` directly, still show up normally.

## clone/clone3 flags

`clone` and `clone3` use two different calling conventions for the
same flags. `clone`'s flags are a plain integer, arg 0 of the raw
syscall on both x86-64 and aarch64 (a few older architectures
reorder clone's raw syscall arguments; neither of this project's two
supported architectures does). `clone3`'s single argument is a
pointer to `struct clone_args`, so decoding it requires reading the
tracee's memory rather than just formatting a value already in
hand, the same shape as `format_sockaddr`.

Both paths funnel into one shared function,
`format_clone_flags_value()`, that takes `flags` and `exit_signal`
as separate parameters and produces one output format for both
syscalls. `format_clone_flags()` (`clone`) splits its single integer
argument into the two: the low byte (`CSIGNAL`, `0xff`) is not a
flag bit, it is the signal sent to the parent on exit, encoded there
because `clone`'s interface predates `clone3`'s separate
`exit_signal` field. A `CLONE_THREAD` call has no exit signal
(`exit_signal == 0`, printed as nothing); a plain fork-like call
typically has `exit_signal == SIGCHLD`, decoded via `sigabbrev_np()`
the same way `kill`'s target signal is.

`format_clone3_flags()` reads `struct clone_args` (Linux uapi
`<linux/sched.h>`) directly: `flags` at offset 0, `exit_signal` at
offset 32, both 8-byte fields regardless of the `size` argument
(which only tells the kernel how many trailing fields are present).
Read via `read_child_raw()`, the same primitive `format_sockaddr`
uses; unlike `sockaddr_in`'s network-order port field, `clone_args`
fields are plain host-endian integers, since `ptrace(2)` only ever
traces a process on the same machine and byte order.

Verified against a real `pthread_create()` (Python's `threading`
module): modern glibc tries `clone3` first, and this container's
seccomp profile rejects it with `ENOSYS`, so both the `clone3`
attempt and the `clone` fallback show up in the same trace with
identical decoded flags, confirming both code paths agree. A plain
`fork()`-driven `clone` call was checked for the `SIGCHLD` exit
signal, and a hand-built `clone3` call (`syscall(SYS_clone3, ...)`
with an explicit `struct clone_args`) was checked for `exit_signal`
specifically, since the thread case leaves it at 0.

## ioctl request codes

`ioctl`'s request argument isn't a small enum like `fcntl`'s cmd or
`lseek`'s whence — Linux has thousands of request codes, one set per
driver and subsystem, assigned via a shared bit layout rather than a
flat list: `<linux/ioctl.h>` packs a direction (none/read/write),
type (a per-subsystem character), number, and payload size into one
32-bit value, and each subsystem's headers just call the `_IO`/
`_IOR`/`_IOW`/`_IOWR` macros to build their own constants from it.

Decoding every request would mean a lookup table with thousands of
entries and, for most of them, a struct layout to decode the third
argument, which is far more scope than this project covers.
Instead, `format_ioctl_request()` (`decoders.c`) does what real
`strace` does for a request it doesn't specifically know: a small
table of terminal (tty) ioctls, decoded by name, covers what
dominates real-world traces (any program checking whether its
stdin/stdout is a terminal, reading window size, allocating a pty).
Anything else falls back to decoding the bit layout itself via
`_IOC_DIR`/`_IOC_TYPE`/`_IOC_NR`/`_IOC_SIZE`, e.g.
`_IOC(_IOC_READ, 0x89, 0x27, 32)`, rather than a bare hex number —
still useful (the direction and payload size are visible even for
an unrecognized request) without needing to know what that request
does.

The third argument (the request's own data, usually a struct
pointer) is left as plain hex/fd, matching every request this
project doesn't otherwise decode; its layout depends entirely on
which request this is, and only the request table above is in
scope here.

Verified against `FIONREAD` on a pipe (a known request, argument 0,
decodes by name), a hand-built unknown request via `_IOR('z', 1,
int)` (falls back to the bit-layout decoding, `_IOC(_IOC_READ,
0x7a, 0x1, 4)`), and `TIOCGWINSZ`/`TIOCGPTN`/`TIOCSPTLCK` against a
real pty allocated with `posix_openpt()`.

## sendmsg/recvmsg struct msghdr

`sendmsg`/`recvmsg`'s single meaningful argument is a pointer to
`struct msghdr`:

```c
struct msghdr {
    void         *msg_name;        /* destination/sender address */
    socklen_t     msg_namelen;
    struct iovec *msg_iov;         /* scatter/gather data array */
    size_t        msg_iovlen;
    void         *msg_control;     /* ancillary data (cmsg) */
    size_t        msg_controllen;
    int           msg_flags;
};
```

Both syscalls share one formatter, `format_msghdr()`, called from
two different points depending on when each field is actually
populated. `sendmsg`'s `msghdr` is entirely the caller's own data,
already valid before the syscall runs, so it's dereferenced at the
entry-stop, the same category as `connect`/`bind`/`sendto`'s
sockaddr. `recvmsg`'s is only meaningful *after* the call returns —
the kernel fills in the sender's address, the received bytes,
ancillary data, and `msg_flags` — so it's deferred to the exit-stop
via a new `pending_msghdr_idx` field on `tracee_state`, the same
category as `accept`/`getsockname`'s sockaddr and `wait4`'s
wstatus. Struct `msghdr` itself is read from the tracee's memory in
one `read_child_raw()` into a local `struct msghdr` rather than
hand-decoding field offsets the way `format_clone3_flags()` has to
for `clone_args` (which isn't a standard glibc type): `msghdr` and
`iovec` are both ordinary types this codebase already includes via
`<sys/socket.h>`/`<sys/uio.h>`, and ptrace only ever traces a
process on the same machine and architecture, so the tracee's
layout is identical to the tracer's own.

`msg_name`/`msg_namelen` reuse `format_sockaddr()` directly — same
decoding `connect`/`accept`/etc. already get. `msg_iov` is walked
as an array of up to 8 entries (`MSGHDR_MAX_IOV`, with a trailing
`...` past that), each read individually via its own
`read_child_raw()` since the array itself is a separate pointer from
the struct. For `sendmsg`, each iovec's declared `iov_len` is
trusted as-is, since that's exactly the data the caller is sending.
For `recvmsg`, the kernel only reports *total* bytes received across
every iovec (the syscall's return value), not per-iovec — same as
`readv` — so `format_msghdr()` takes that return value as a
`total_bytes` budget and consumes it across the iovecs in the same
order the kernel itself would have filled them; `iov_len` in the
output still shows each buffer's declared capacity (matching real
`strace`), while `iov_base`'s displayed content is capped to
whatever fraction of the budget that iovec actually got.

`msg_control` (ancillary/cmsg data) is a sequence of `struct
cmsghdr` entries with kernel-defined alignment between them
(`CMSG_ALIGN`), not worth reimplementing by hand. Instead, the
tracee's control buffer (up to 512 bytes, `MSGHDR_MAX_CONTROL`) is
copied into a local buffer, wrapped in a throwaway `struct msghdr`
that actually points at *this* process's own memory, and walked
with the real `CMSG_FIRSTHDR`/`CMSG_NXTHDR`/`CMSG_DATA` macros —
the same ones real sender/receiver code uses, sidestepping the
alignment rules entirely. `SOL_SOCKET`/`SCM_RIGHTS` (passed file
descriptors — the reason cmsg shows up in most real-world traces,
e.g. systemd/Docker socket activation and D-Bus fd passing) decodes
into the actual fd numbers; `SCM_CREDENTIALS` decodes into
pid/uid/gid. Anything else shows its level/type/length without
guessing at a payload shape this table doesn't know.

Verified with a `socketpair(AF_UNIX, SOCK_DGRAM, ...)` pair passing
one open fd via `SCM_RIGHTS` alongside a short string: the `sendmsg`
side shows the outgoing fd number, the iovec's exact text, and
`SCM_RIGHTS`; the `recvmsg` side shows the newly-assigned received
fd number, the same text truncated correctly against the return
value while the receive buffer's full declared size stays in
`iov_len`, and `SCM_RIGHTS` again on the receiving end. A separate
`sendmsg` to a real `AF_INET` address with two iovecs confirmed
`msg_name` decodes through the shared sockaddr formatter and
multiple iovecs render in order with `msg_control=NULL` when there
isn't any.

## stat/lstat/fstat/newfstatat struct stat

`stat`, `lstat`, and `fstat`'s output `struct stat` is a fourth
deferred-argument shape (alongside `read()`'s buffer,
`accept`-family's sockaddr, and `wait4`'s wstatus in "Deferred
prints" above): unpopulated at the entry-stop, valid only once the
syscall returns, so `stat_buf_arg_mask` and `pending_stat_idx`
follow the same entry/exit split as `pending_wait_status_idx`.
`newfstatat` (what `stat`/`lstat`'s libc wrappers actually call on
architectures that dropped the legacy syscalls — see below) writes
the same struct at a different argument index (2, not 1, since it
also takes a `dirfd`), so it gets its own table entry rather than
being treated as an alias.

`format_stat_buf()` reads `struct stat` directly into a local
variable via `read_child_raw()`, the same trick `format_msghdr()`
uses for `struct msghdr`: it's an ordinary type already available
through `<sys/stat.h>`, and ptrace only ever traces a process on the
same machine and architecture, so the tracee's layout matches the
tracer's exactly — including the parts of `struct stat`'s layout
(field widths, padding) that actually differ between x86-64 and
aarch64, since whichever one this is built for is the one whose
`<sys/stat.h>` got compiled in.

Only `st_mode` (file type via `S_ISREG`-style macros, plus the
permission bits in octal), `st_size`, `st_nlink`, `st_uid`, and
`st_gid` are decoded — the fields most worth seeing at a glance.
Timestamps aren't: turning `st_atime`/`st_mtime`/`st_ctime` into
anything more readable than a raw epoch integer needs real time
formatting, more machinery than this project's other decoders take
on for one struct's fields.

Adding `stat`/`lstat`/`newfstatat` to the deferred category surfaced
a real gap in the deferred exit-stop print path: it checked
`fd_arg_mask` for its fallback case but never `string_arg_mask`, so
a deferred syscall's path argument (something none of the three
pre-existing deferred cases — `read`, sockaddr, `wait4` — actually
have) printed as a raw pointer instead of a decoded string.
`newfstatat("/etc/hostname", ...)` briefly regressed to
`newfstatat(0xaaaa1234, ...)` before this was caught by manually
diffing real trace output against expectations, not by the existing
test suite (none of it exercised a deferred call with a path
argument until this feature added one). Fixed by checking
`string_arg_mask` first in the exit-stop's per-argument loop, same
priority position it has in the entry-stop's immediate-print loop.

Verified against a real file (`fstat` decodes `S_IFREG` and the
right size), a symlink via `lstat` (decodes `S_IFLNK|0777` without
following it — permission bits on a symlink are meaningless and the
kernel reports them as `0777` by convention), and a nonexistent path
(the call fails with `ENOENT` and the unpopulated struct correctly
falls back to a raw pointer instead of decoding garbage).

## statx struct statx

`statx`'s `mask` argument (which fields the caller wants filled in)
and `statxbuf` output are decoded alongside the path argument the
plain stat family already had. `mask` is an OR-of-bits walk like
every other flags argument in this file, with `STATX_BASIC_STATS` —
the common default request, itself a combination of the individual
`STATX_TYPE`/`MODE`/`NLINK`/`UID`/`GID`/`ATIME`/`MTIME`/`CTIME`/
`INO`/`SIZE`/`BLOCKS` bits — listed first in the table so it's
matched and consumed whole rather than exploded into eleven
individual names, the same technique `open_flag_table` uses for
`O_TMPFILE`/`O_SYNC` needing to claim their bits before the plain
flags they're built from get a chance to match on what's left over.

`statx` always has a `struct statx*` argument, so — like
`clock_gettime`/`clock_nanosleep`'s `clockid` before this — `mask`'s
decode is never reachable from the entry-stop's own dispatch chain
(the whole call is unconditionally routed through the deferred
path) and is dispatched from the exit-stop's loop only; this project
now checks for exactly this situation whenever a syscall gains a new
kernel-populated argument, rather than discovering it the hard way
again.

`struct statx` itself, unlike `struct stat`, was deliberately
designed (Linux 4.11) to have one fixed 256-byte layout on every
architecture — no arch-specific variation to account for the way
`struct stat`'s layout genuinely differs between x86-64 and aarch64,
and no libc-wrapper translation the way `struct sigaction` has — so
overlaying glibc's own type onto a `read_child_raw()` copy needed no
further verification beyond what `format_stat_buf()` already
established is safe for a stat-shaped struct.

`format_statx_buf()` decodes the exact same subset
`format_stat_buf()` does — `stx_mode` (file type + permission bits,
via the same `stat_file_type_name()` helper, since the bit meanings
are identical to plain `stat`'s `st_mode`), `stx_size`, `stx_nlink`,
`stx_uid`, `stx_gid` — so a `statx` trace and a plain `stat` trace
show the same shape for the fields they share. Everything `struct
statx` adds beyond plain `stat` (extended attributes, `btime`, mount
ID, block device major/minor, DIO alignment, ...) is left
undecoded, the same scope boundary plain `stat` already draws at its
own timestamps.

Verified against a real file (`STATX_BASIC_STATS` decodes as the
combined name rather than eleven separate flags, the output struct
matches what `fstat` would show for the same file, and the path
argument still decodes as a string alongside the deferred struct)
and a nonexistent path (fails with `ENOENT`, path still decodes,
struct correctly falls back to raw hex).

## getdents64 directory entries

`getdents64`'s output buffer is deferred the same way `read()`'s is
(unpopulated at the entry-stop, real return value tells the tracer
how many bytes are actually valid), but unlike `read()` the bytes
aren't arbitrary data to dump as an escaped string — they're a
packed sequence of directory entries to parse, so this gets its own
`pending_getdents_idx` and its own decoder rather than reusing
`read_arg_table`/`read_child_buffer`.

The kernel's wire format for each entry (`struct linux_dirent64` per
`getdents64(2)`) isn't exposed by any glibc header — glibc only
exposes the higher-level `opendir()`/`readdir()` API built on top of
it — so like `struct clone_args` in the `clone3` section above,
there's no real local type to overlay a `read_child_raw()` copy
onto. Fields are read at their fixed byte offsets instead: `u64
d_ino` at 0, `s64 d_off` at 8, `u16 d_reclen` at 16, `u8 d_type` at
18, then a NUL-terminated `d_name` starting at 19, padded to fill
out `d_reclen` bytes. Unlike `struct stat`/`clone_args`, this layout
has no architecture-specific variants — it's one fixed format across
every Linux architecture since it was introduced.

Entries are packed back-to-back with no separator; each entry's own
`d_reclen` (its total size, header included) says how far to advance
to find the next one. A `d_reclen` too small to hold a header, or
one that would read past the bytes actually returned, stops parsing
immediately rather than reading past what was actually copied out of
the tracee. Both the number of bytes read (`GETDENTS_MAX_BYTES`,
4096) and the number of entries actually rendered
(`GETDENTS_MAX_ENTRIES`, 8) are capped, with a trailing `...` when
either limit was hit — a directory listing can have thousands of
entries, and a single trace line showing all of them would be far
less readable than a real terminal ever wants.

`d_type` is decoded via the real `DT_REG`/`DT_DIR`/`DT_LNK`/...
macros from `<dirent.h>`, matching every other exact-value lookup in
this file (clockid, fcntl's cmd, ...) using real macros over
hardcoded numbers. `d_off` is shown as whatever integer the
filesystem actually put there — on most filesystems this is an
opaque seek cookie, not a sequential counter, so large
unpredictable-looking values are expected and correct, not a sign
of anything decoded wrong.

Also added `getdents64` to `trace_filter.c`'s `file` category list
for `-e trace=file` — it was missing even though every other
directory-adjacent syscall (`getcwd`, `readlink`, ...) was already
in it.

Verified against a real directory: a regular file and a symlink both
decode with the correct `d_type`, the final "no more entries" call
(return value `0`) falls back to a raw pointer rather than an empty
or garbage decode, and a 20-file directory confirms the entry-count
cap triggers the `...` truncation marker.

## rt_sigaction struct sigaction

`rt_sigaction`'s `act`/`oldact` arguments are a `struct sigaction`
pointer, and — unlike every struct this project decodes elsewhere —
glibc's userspace `struct sigaction` (from `<signal.h>`) is *not*
what the raw syscall actually reads or writes. `format_stat_buf()`
and `format_msghdr()` can safely overlay glibc's own `struct stat`/
`struct msghdr` onto a `read_child_raw()` copy because those types
pass through to the kernel unchanged. `struct sigaction` doesn't:
glibc's `sigaction()` wrapper *translates* between its own userspace
layout (a handler, a 128-byte `sa_mask` sized for up to 1024 signals,
then `sa_flags`, then `sa_restorer`) and a smaller kernel-side layout
in a different field order, before ever calling the raw syscall.
Overlaying glibc's type here would silently read the wrong bytes
into the wrong fields — a real correctness bug, not a safe
degradation to hex.

The kernel's actual on-the-wire layout isn't taken from documentation
alone: it was verified empirically for this project, since getting a
struct layout wrong here would look like a working decoder while
quietly showing incorrect values. The verification made a raw
`syscall(SYS_rt_sigaction, ...)` call with a hand-built struct in a
hypothesized field order, immediately followed by a second raw call
requesting the same disposition back via `oldact`, and confirmed
every field round-tripped correctly — handler, flags, restorer, and
mask all matched what was set. This was run on both architectures
this project targets (a real aarch64 machine, and x86-64 via both a
GitHub Actions runner and local QEMU emulation, all three agreeing),
not assumed to be identical across them. The confirmed layout is
four consecutive 8-byte fields:

```c
struct kernel_sigaction {
    unsigned long handler;
    unsigned long flags;
    unsigned long restorer;
    unsigned long mask;    /* one word — 64 signals, matching the
                             * sigsetsize every real call here uses */
};
```

This is a struct the project defines itself, not exposed by any
glibc or kernel header under this shape — the same situation as
`clone3`'s `struct clone_args` and `getdents64`'s
`struct linux_dirent64`, both also kernel-only wire formats with no
userspace declaration to borrow. Its fields are named `handler`/
`flags`/`restorer`/`mask` rather than the POSIX `sa_*` names on
purpose: glibc's `<bits/sigaction.h>` `#define`s `sa_handler` (and
similarly for the others) as macros implementing its own union trick
for supporting both a plain handler and a `sa_sigaction` callback
through the same field — with `_GNU_SOURCE` already active, those
macros are live in this file too, and naming a field `sa_handler`
here would have the preprocessor silently rewrite it into a
reference to a member this struct doesn't have. (This surfaced as a
real compile error the first time — `'struct kernel_sigaction' has
no member named '__sigaction_handler'` — which is what caught it.)

`sa_handler` decodes `SIG_DFL`/`SIG_IGN` by name (both real macros,
`(void *)0`/`(void *)1`) and falls back to a bare hex address
otherwise — resolving that address to a symbol name would need debug
info this project doesn't parse. `sa_flags` is the usual OR-of-bits
walk every other flags argument in this file uses; `sa_mask` renders
as a bracketed list of blocked signal names (`[SIGUSR1 SIGTERM]`,
`[]` when empty) via the same `sigabbrev_np()` already used for
`kill`'s target signal.

Like the stat family, `act` is populated by the caller before the
syscall runs (entry-stop, same category as `clone3`'s `clone_args`)
while `oldact` is only filled in by the kernel afterward (exit-stop,
same category as `stat_buf`). Since routing is keyed on syscall
name rather than on whether a particular call's `oldact` happens to
be `NULL`, *every* `rt_sigaction` call goes through the deferred
path — which meant `sig` (the signal number) and `act` also needed
their decode dispatch added to the exit-stop's per-argument loop,
not just the entry-stop's, or they'd never be reached at all for
this syscall. Same lesson as `string_arg_mask` needing to be added
there for the stat family's path argument.

Verified against a real signal handler installed via glibc's
`sigaction()`: `SIG_IGN` decodes for a handler explicitly ignored,
a real function pointer decodes as a hex address, `SA_RESTART`
decodes in `sa_flags`, a mask blocking `SIGUSR1`/`SIGTERM` decodes
by name, an omitted `oldact` shows `NULL`, and a follow-up call
requesting the previously-installed disposition back via `oldact`
decodes that deferred struct correctly too.

## clock_gettime/clock_settime/nanosleep/clock_nanosleep struct timespec

Unlike `struct sigaction`, `struct timespec` (`<time.h>`) has no
glibc-vs-kernel translation layer — it's passed straight through to
these syscalls unchanged, the same situation `struct stat`/
`struct msghdr` are in, so `format_timespec()` safely overlays it
onto a `read_child_raw()` copy without needing the empirical
verification `struct sigaction` required.

Which argument gets decoded, and when, splits the same way the stat
family's does: `clock_settime`'s new time and `nanosleep`/
`clock_nanosleep`'s requested duration are populated by the caller
before the syscall runs (entry-stop, `timespec_in_arg_mask`);
`clock_gettime`'s result and `nanosleep`/`clock_nanosleep`'s
remaining time (meaningful only if the sleep was interrupted) are
populated by the kernel afterward (exit-stop,
`timespec_out_arg_mask`, via a new `pending_timespec_out_idx`).

This surfaced two real bugs while wiring it up, both the same root
cause and worth calling out because it's now happened three times
across three different features (the stat family's path argument
earlier, `rt_sigaction`'s `sig`/`act` before this): whenever a
syscall's routing is decided by *name* rather than by which
arguments a specific call actually uses, adding a new
kernel-populated argument to a syscall that previously had none
routes *every* call to that syscall through the deferred path —
silently making any of that syscall's entry-populated arguments
unreachable in the entry-stop's own dispatch chain, since it never
runs for that syscall anymore.

Both bugs were caught by testing against a real trace, not by
reasoning about the code:

1. `clockid_arg_mask` was only ever dispatched from the entry-stop.
   `clock_gettime` (whose only argument besides `clockid` is its
   kernel-populated result) and `clock_nanosleep` (which always has
   a deferred remaining-time argument) never reach that dispatch —
   both showed `clockid` as raw hex until `clockid_mask` was added
   to the exit-stop's loop too.
2. The exit-stop's *outer* condition — the one deciding whether the
   deferred-print block runs *at all* — was missing
   `pending_timespec_out_idx >= 0`. A syscall whose *only* pending
   field is a deferred timespec (`nanosleep` has no stat/msghdr/
   sigaction component) skipped the entire print, producing a bare
   `= 0` with no syscall name or arguments at all — a much louder,
   easier-to-notice failure than the first bug, which is what caught
   it during manual verification.

Testing this also confirmed something not previously observed in
this project: aarch64 has no raw `nanosleep` syscall either (the
same situation `access`/`vfork` are in) — glibc's `nanosleep()`
there compiles down to `clock_nanosleep(CLOCK_REALTIME, 0, req,
rem)`, so a trace on aarch64 shows `clock_nanosleep(...)` for code
that called `nanosleep()`, while the same code on x86-64 shows
`nanosleep(...)`. Both are correct; they're genuinely different
syscalls depending on the architecture the trace actually ran on.

Verified against `clock_gettime` via a raw `syscall(SYS_clock_gettime,
...)` call (bypassing the VDSO glibc's own `clock_gettime()` usually
serves this from, see the clockid section above), `nanosleep()`'s
requested duration, an explicit `clock_nanosleep()` call decoding
clockid plus both its request and remaining-time arguments, and
`clock_settime()` decoding its clockid and requested time (the call
itself fails with `EPERM` in this project's unprivileged dev
container, which — same as `mount`'s flags — doesn't matter for
decoding an already-populated argument).

## wait4 struct rusage

Like `struct stat`/`struct timespec`, `struct rusage`
(`<sys/resource.h>`) has no glibc-vs-kernel translation layer —
`wait4`'s kernel-populated `rusage` output is the same type glibc
itself declares, so `format_rusage()` overlays it onto a
`read_child_raw()` copy the same safe way, no empirical ABI check
needed the way `struct sigaction` required.

Only `ru_utime`/`ru_stime` (CPU time actually used) and `ru_maxrss`
(peak memory) are decoded — the fields most worth seeing at a
glance, same call this project already made for `struct stat`'s
subset of fields. The other dozen-odd counters `struct rusage`
carries (page faults, swaps, IPC messages sent/received, context
switches, ...) are rarely examined and would mostly add noise.

Unlike every other deferred-argument addition so far, this one
needed no new entry-vs-exit split to get right: `wait4` was already
always routed through the deferred path before this (its `wstatus`
argument has always required it), so adding `rusage` as a second
deferred field on the same call was just a matter of extending the
existing pending-state machinery — `pending_rusage_idx` alongside
`pending_wait_status_idx`, both populated only once the syscall
returns — with no risk of the "syscall's other arguments silently
become unreachable" bug that hit the stat family's path,
`rt_sigaction`'s `sig`/`act`, and `clock_gettime`/`clock_nanosleep`'s
`clockid` before this.

Gated on `ret >= 0`, matching `format_stat_buf`'s convention: a
failed `wait4` (no child to reap, `ECHILD`) never has the kernel
touch `rusage` at all, so decoding it would be showing whatever
garbage happened to already be in that memory, not real data.

Verified against a real reaped child (`ru_utime`/`ru_stime`/
`ru_maxrss` all show plausible values) and a `wait4(-1, ...)` call
with no children left, which fails with `ECHILD` and correctly
leaves both `wstatus` and `rusage` as raw pointers rather than
decoding either.

## epoll_ctl/epoll_wait struct epoll_event

`struct epoll_event` is another direct kernel passthrough, not a
translated type the way `struct sigaction` is — but it has its own
real architecture-specific wrinkle worth naming: on x86-64 the
kernel's expected layout is `__attribute__((packed))` to 12 bytes
(preserving a 32-bit-era ABI), while other architectures, aarch64
included, use the natural 16-byte layout instead (confirmed by
`sizeof(struct epoll_event)` in this project's own dev container).
Glibc's own `<sys/epoll.h>` already declares the struct with
whatever packing each architecture's kernel actually expects, so —
same reasoning already relied on for `struct stat`'s layout
differing across architectures — always using `sizeof(struct
epoll_event)` rather than a hardcoded size means the correct size
and array stride fall out automatically for whichever architecture
this is built for, without needing `struct sigaction`'s kind of
empirical ABI verification: there's no libc-wrapper-level
translation happening here, just a struct definition that already
accounts for the difference.

`format_one_epoll_event()` decodes the shared shape both syscalls
use: `events` (an OR-of-bits walk like every other flags argument in
this file) and `data`, a union with no way to know from the trace
alone which member (`fd`/`u32`/`u64`/`ptr`) the caller actually
meant — so, matching what real `strace` does here, both integer
interpretations (`u32` and `u64`) are shown rather than guessing
one.

`epoll_ctl`'s `op` (`EPOLL_CTL_ADD`/`MOD`/`DEL`) is a plain enum
lookup like `fcntl`'s `cmd`. Its `event` argument is populated by
the caller before the syscall runs (entry-stop, like `clone3`'s
`clone_args`); `epoll_wait`'s output array is only populated by the
kernel afterward (exit-stop, `format_epoll_events_buf()`, capped at
8 rendered entries with a trailing `...` past that — same convention
`format_getdents_buf()` and `format_msghdr()`'s iovec array use).
`ret` is how many entries the kernel actually filled in, not
`maxevents` (the buffer's declared capacity), the same relationship
`getdents64`'s return value has to its buffer.

Verifying this against a real trace surfaced the same
architecture-vs-glibc-choice situation already documented for
`access`/`faccessat` and `nanosleep`/`clock_nanosleep`: glibc's
`epoll_wait()` compiles down to a call to the `epoll_pwait` syscall
(with a `NULL` sigmask) rather than the `epoll_wait` syscall — so
`epoll_events_arg_mask` and `syscall_argc_table` both cover
`epoll_pwait` at the same argument index, and a trace of code that
calls `epoll_wait()` shows `epoll_pwait(...)` instead. This isn't
even architecture-specific the way `access`/`nanosleep` are: aarch64
doesn't have a raw `epoll_wait` syscall number at all (`SYS_epoll_wait`
doesn't exist as a macro there), while x86-64 does have one, but this
project's dev-container glibc still prefers routing through
`epoll_pwait` regardless.

Verified against a real `epoll_create1()`/`epoll_ctl()`/`epoll_wait()`
sequence: `EPOLL_CTL_ADD` with `EPOLLIN|EPOLLET` and a real fd decode
correctly, `EPOLL_CTL_DEL` with a `NULL` event decodes correctly, a
ready event appears in `epoll_wait`'s (actually `epoll_pwait`'s)
output array with the right flags and fd, and a second call with
nothing left registered times out with 0 ready events, correctly
falling back to a raw pointer instead of an empty or garbage array.

## poll struct pollfd

`poll`'s `fds` argument is a genuinely different shape from every
other buffer or array this project decodes: it's populated by the
*caller* before the syscall runs (each entry's `fd` and requested
`events`), but the kernel then overwrites every entry's `revents`
field before the syscall returns — so the same array is both an
input and an output on the same call. Rather than showing it twice
(once at entry without `revents`, once at exit with it, the way two
separate arguments would be handled), the whole thing is deferred to
the exit-stop and shown once, with the caller's `events` and the
kernel's `revents` together in each entry.

`nfds` (the array's length) isn't itself deferred — it's a plain
value the caller already supplied — but the array it describes still
needs deferring, so this reuses `buffer_arg_entry`'s "one arg is a
buffer, another holds its length" shape the same way
`accept_arg_table`'s deferred pairs do, added as a new
`pending_pollfds_entry` field on `tracee_state` (a pointer, like
`pending_sockaddr_entry`, rather than a lookup keyed by index).
Unlike `getdents64`/`epoll_wait`, `nfds` isn't compared against the
return value to decide how many entries are valid — every entry the
caller declared is meaningful regardless of how many actually saw
activity, since the kernel zeroes `revents` for the rest rather than
leaving them undefined.

`struct pollfd` (`<poll.h>`: `int fd; short events; short
revents;`) is a small, fixed-width struct passed by pointer straight
through to the kernel unchanged — no libc-wrapper translation the
way `struct sigaction` has, no cross-architecture packing
difference the way `struct epoll_event` has — so overlaying it onto
a `read_child_raw()` copy per entry needed no further verification
beyond what `struct stat`/`struct rusage` already established is
safe. `events`/`revents` decode via the same `POLLIN`/`POLLOUT`/...
`OR`-of-bits walk every other flags argument in this file uses.
Capped at 8 rendered entries, with a trailing `...` past that — same
convention `format_getdents_buf()`/`format_epoll_events_buf()` use.

Verifying this against a real trace surfaced the same
architecture-vs-glibc-choice situation documented for `access`/
`faccessat`, `nanosleep`/`clock_nanosleep`, and `epoll_wait`/
`epoll_pwait` — a fourth instance of it now: glibc's `poll()`
compiles down to a call to the `ppoll` syscall (with a `NULL`
timeout/sigmask) rather than the `poll` syscall, so
`pollfds_arg_table` and `syscall_argc_table` both cover `ppoll` at
the same argument indices, and a trace of code calling `poll()`
shows `ppoll(...)` instead.

Verified against a real two-entry array (one fd made readable via a
pipe write, one fd checked for writability): both entries decode
with matching `events`/`revents`, and a separate, genuinely empty
pipe checked with a short timeout correctly shows `revents=0` for an
fd with no activity rather than stale or garbage flags.

## Testing

`tests/run_tests.sh` runs every flag and decoder above against real
programs. `tests/property_test_decoders.c` covers the part of the
codebase that is testable without a live `ptrace` session: the pure
`format_*` decoders in `decoders.c`, which take a raw value and an
output buffer and do not touch the tracee's memory.

The property test harness runs every such decoder against a set of
edge values (`0`, all bits set, sign-extended 32-bit patterns, ...)
plus a deterministic pseudo-random stream, each crossed against
output buffer sizes from `0` up to the real cap. Built with
`-fsanitize=address,undefined`, so an overflow of even one byte
aborts immediately.

This caught a real bug on its first run: `format_map_flags`'s final
fallback `snprintf` call was missing the `oi < out_size` guard every
other decoder in the file has. `snprintf`'s C99 return value is how
many bytes it would have written, not how many actually fit, so a
long enough flag combination into a small enough buffer pushed `oi`
past `out_size`; without the guard, `out_size - oi` (both `size_t`,
unsigned) underflowed into a huge number, and the resulting
`snprintf` call wrote past the buffer. See `CHANGELOG.md` for the
fix.

`read_child_*`'s `ptrace(2)` calls in `child_mem.c` are not covered
by the property test harness. Fuzzing those would require either
mocking `ptrace(2)` or driving a real traced process into
adversarial memory layouts; neither is implemented.

Not a coverage-guided fuzzer: no libFuzzer/AFL integration, no
corpus. The harness runs a fixed set of deterministic sweeps.
