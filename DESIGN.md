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
