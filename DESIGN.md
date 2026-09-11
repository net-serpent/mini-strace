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
check that sends nothing), not a signal name.

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
