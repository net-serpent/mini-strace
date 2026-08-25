# mini-strace

[![CI](https://github.com/net-serpent/stracebeta/actions/workflows/ci.yml/badge.svg)](https://github.com/net-serpent/stracebeta/actions/workflows/ci.yml)

A stripped-down clone of `strace`, built on Linux's `ptrace(2)` API.

## What it does

Traces a target program and prints every syscall: name, arguments,
return value. Failed calls show the errno name (`ENOENT`, not `2`).
A handful of common syscalls get extra treatment `open`/`stat`/
`execve`/`symlink`/`link`/`mount` and friends show their path
arguments as actual strings instead of pointers, `execve`/`execveat`
show their `argv`/`envp` arrays decoded too, `read`/`write` show
the bytes they're moving, and `connect`/`bind`/`sendto`/`recvfrom`/
`accept`/`getsockname`/`getpeername` show the socket address decoded
(`{sa_family=AF_INET, sin_port=htons(80),
sin_addr=inet_addr("1.2.3.4")}` for IPv4, the equivalent for IPv6,
`{sa_family=AF_UNIX, sun_path="/path"}` for Unix sockets) instead of
a raw pointer, `open`/`openat` show their flags decoded
(`O_WRONLY|O_CREAT|O_TRUNC` instead of `0x241`), and `mmap`/
`mprotect` show their protection/mapping flags decoded
(`PROT_READ|PROT_WRITE`, `MAP_PRIVATE|MAP_ANONYMOUS`). You can also
narrow the trace down with
`-e trace=SET`, where SET is a comma-separated mix of categories
(`file`, `network`, `process`) and/or exact syscall names:
`-e trace=file` shows only filesystem calls, `-e trace=network,openat`
shows networking plus that one specific syscall:

```
execve("/bin/cat", ["cat", "foo.txt"], ["PATH=/usr/bin", "HOME=/root"], 0xffffffff, 0x7f45c4f4c740) = 0
access("/etc/ld.so.preload", 0x4, 0x556158984d10, 0x22, 0x7ff5eca8b000, 0x7ff5ecac1440) = -2 (ENOENT)
openat(0xffffff9c, "/etc/ld.so.cache", 0x80000, 0x0, 0x0, 0x0) = 3
openat(0xffffff9c, "/tmp/somefile.txt", 0x0, 0x0, 0xffffffff, 0x0) = 3
read(0x3, "test data content\n", 0x20000, 0x22, 0x0, 0x7fe3515c0440) = 18
write(0x1, "test data content\n", 0x12, 0x22, 0x0, 0x7fe3515c0440) = 18
read(0x3, 0x7fa474eae000, 0x20000, 0x22, 0x0, 0x7fa474f1f440) = 0
[mini-strace] process exited, code 0, total syscalls: 37
```

## Build & run

```bash
make
./mini-strace /bin/echo hello world
./mini-strace -e trace=file /bin/cat some-file.txt
```

You can also attach to an already-running process by PID instead of
launching a new one:

```bash
./mini-strace -p 12345
./mini-strace -e trace=network -p 12345
```

By default only the one process you launch (or attach to) gets
traced — anything it forks runs untraced. Pass `-f` to follow into
child processes too; each output line gets a `[pid N] ` prefix so
you can tell which process it came from:

```bash
./mini-strace -f /bin/sh -c 'echo hi'
./mini-strace -f -e trace=process /bin/make
```

Pass `-T` to time each syscall (wall clock, from entry-stop to
exit-stop) and append it to the line, e.g. `= 0 <1.000484>`:

```bash
./mini-strace -T /bin/sleep 1
```

Pass `-c` for a summary instead of a line per call: total calls,
errors, and time spent grouped by syscall name, sorted slowest-first:

```bash
./mini-strace -c /bin/ls
```

```
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 42.20    0.000080          20         4         0 close
 20.15    0.000038          12         3         0 fstat
 14.34    0.000027          13         2         0 openat
------ ----------- ----------- --------- --------- ----------------
100.00    0.000190                    12         1 total
```

Pass `-o FILE` to send the trace (and the `[mini-strace] ...` status
lines) to a file instead of stdout/stderr. The traced program's own
stdin/stdout/stderr are untouched, so its actual output still shows
up on your terminal same as always:

```bash
./mini-strace -o trace.log /bin/echo hello
```

String and buffer arguments are truncated at 200 bytes by default
(shown with a trailing `...`). Pass `-s SIZE` to raise or lower that:

```bash
./mini-strace -s 4 /bin/echo hello-world
# write(1, "hell"..., 11) = 11
```

Pass `-y` to resolve file descriptor arguments to what they actually
point to, via `/proc/pid/fd/N`:

```bash
./mini-strace -y /bin/cat /etc/hostname
# openat(0xffffff9c, "/etc/hostname", 0x0, 0x0, 0x0, 0x0) = 3
# read(3</etc/hostname>, "myhost\n"..., 0x20000, 0x1, 0x0, ...) = 7
```

On macOS:

```bash
docker compose run --rm dev
# now inside the container
make
./mini-strace /bin/echo hello world
```

## Testing

`tests/run_tests.sh` exercises every flag above against real programs
— it's the same checks that were run by hand during development, made
repeatable. Needs Linux (same as the tool itself):

```bash
make
bash tests/run_tests.sh
```

On macOS, run it inside the dev container the same way as the build:

```bash
docker compose run --rm dev
make
bash tests/run_tests.sh
```

CI runs this on every push/PR to `main` (see the badge at the top).
One test (`-p` attach to a sibling process) is skipped rather than
failed if the environment's ptrace permissions don't allow it — some
sandboxes restrict `PTRACE_ATTACH` to direct descendants only.

## How it works

The child does `PTRACE_TRACEME` then `SIGSTOP`s itself before
`execvp`. The parent waits for that, then loops on `PTRACE_SYSCALL`,
which stops the child at every syscall entry and exit and lets the
tracer read its registers in between.

x86-64 and ARM64 disagree here: register
names, `PTRACE_GETREGS` vs `PTRACE_GETREGSET`, which registers hold
the arguments, syscall numbering from scratch. All of that lives
behind `#ifdef __x86_64__` / `#ifdef __aarch64__`, behind a small set
of helper functions so the main loop doesn't have to know which
platform it's on.

Syscall names typed by: `scripts/gen_syscall_table.sh`
asks gcc to preprocess the platform's syscall header and pulls the
`__NR_*` defines out of that, which sidesteps having to hardcode a
header path (that path differs across toolchains and distros). A few
syscalls: `mmap`, `stat`, `fstat` aren't a plain number in the
header, they're defined through a level of indirection (`__NR_mmap`
-> `__NR3264_mmap` -> `222`), so the generator follows that chain. The
table gets regenerated on every `make`, since it has to match
whatever machine you're actually building on and isn't committed.

`read()` needed a different approach than `write()`. `write()`'s
buffer already has real data at the entry-stop, so it prints
immediately like everything else. `read()`'s buffer is empty at that
point, so for that one the tracer holds
off printing anything at entry, waits for the exit-stop, and uses the
return value (the actual byte count, usually less than what was
requested) as the dump length.

`-e trace=SET` filtering is deliberately simple: three hardcoded
category tables (file/network/process syscall names) plus exact-match
against the raw syscall name, no proper syscall classification
database. The tracer still steps through every syscall either way, 
filtering only decides whether to print, not whether to trace, so a
suppressed syscall still needs its entry/exit bookkeeping kept in
sync with everything else, it just skips the `printf`.

`-f` uses `PTRACE_O_TRACEFORK`/`TRACEVFORK`/`TRACECLONE` so new
children auto-attach to the tracer with the same options already
inherited, then the main loop switches from waiting on one fixed pid
to `waitpid(-1, ...)`, picking up whichever tracee stops next, with a
small fixed-size table tracking each pid's own entry/exit state
independently. One known rough edge: since a syscall's `name(args)`
and its `= ret` are still two separate prints (so a call that's still
running is visible before it returns, same as real strace), a
different process's line can land in between them when several
processes are stopped near the same time — cosmetic only, the data
itself is still all there.

`-c` reuses the same entry/exit timestamps `-T` records, just folds
each call into a running total keyed by syscall name instead of
printing a line — a fixed-size table (linear-scan lookup, same style
as everywhere else in this file), selection-sorted by total time once
the trace ends, then printed as one table.

`-o` opens the file in the tracer itself and threads that `FILE *`
through in place of the hardcoded `stdout`/`stderr` everything else
used to print to. Opening it before `fork()` means an exec'd tracee
inherits the fd too, but only as an extra unused one sitting alongside
its real fd 0/1/2 — nothing redirects *those*, so the tracee's own
I/O is unaffected either way.

`-s` doesn't resize anything at runtime — the raw-read and escaped-
output buffers are still fixed-size stack arrays, just sized 1024
bytes (up from the old hardcoded 200) so `-s` has room to raise the
cap. What actually changes at runtime is `max_str_len`, which caps
how much of that fixed buffer gets used. One wrinkle: `ptrace(2)`
only ever reads whole machine words (8 bytes), so a `-s` value
smaller than that would make the read loop exit before reading
anything at all if it were bounded by the raw byte count directly —
the read window gets rounded up to a word boundary instead, and the
*displayed* length is clamped to the real requested size afterward.

`-y` resolves a fd argument via `readlink()` on `/proc/pid/fd/N` —
that symlink target is either a real path, or a description like
`socket:[12345]`/`pipe:[12345]` for fds that aren't backed by a path
at all, which `readlink()` returns as plain text either way. A second
fixed-size table (same shape as the one driving string-argument
dereferencing) says which argument slots are fds per syscall;
negative values (`AT_FDCWD` and friends passed as a *at() syscall's
dirfd) are left alone rather than treated as a real fd number.

`execve`/`execveat`'s `argv`/`envp` decoding walks the pointer array
itself — each slot is its own `char*`, fetched with its own
`PTRACE_PEEKDATA`, then handed to the same string-reading logic
everything else uses (so it respects `-s` per element too). Capped at
32 entries so a huge environment can't blow up the line length or the
ptrace call count; a `...` at the end means the array kept going past
that cap.

`connect`/`bind`/`sendto`'s sockaddr decoding reads the raw struct
bytes (`read_child_raw()`, same peek loop as everything else minus
the string-escaping) and interprets the first two bytes as
`sa_family` — always host-endian, unlike the port fields inside
`sockaddr_in`/`sockaddr_in6`, which are always network byte order
regardless of the host, so those get unpacked byte-by-byte rather
than assumed to match the tracer's own endianness. The address
itself (`sin_addr`/`sin6_addr`) doesn't need that treatment — IPv4
gets the same manual byte-by-byte formatting since it's just 4 bytes,
but IPv6's 16 bytes are handed to `inet_ntop()` as-is, since that
function is defined to take the address in its raw on-the-wire form,
not as a host-endian integer. `AF_INET`, `AF_INET6`, and `AF_UNIX`
are decoded; anything else just shows the numeric family.

`accept`/`accept4`/`getsockname`/`getpeername`/`recvfrom`'s sockaddr
is the opposite case — empty until the syscall returns, like
`read()`'s buffer — so it goes through the same kind of entry/exit
deferral, tracked in its own `pending_sockaddr_entry` field alongside
`read()`'s `pending_read_entry`. One extra wrinkle these have that
`read()` doesn't: the `socklen_t *` telling you how much of the
struct is real is itself only valid *after* the call too, so that
pointer gets re-read with its own `ptrace` peek at the exit-stop
rather than trusted from entry.

`recvfrom` is the one syscall that needs *both* deferrals on the same
call — a data buffer and a sockaddr, each only populated once the
syscall returns — so it's the only entry in both `read_arg_table` and
`accept_arg_table` at once. None of the pending-state fields are
mutually exclusive: the exit-stop print just checks each of the 6
argument slots against all of them, so whichever one (or several, or
none) applies gets rendered into the same line. `recvfrom(3, "hello",
1024, 0, {sa_family=AF_INET, ...}, ...) = 5` comes out of the same
code path that gives plain `read()` its buffer and `accept()` its
address.

`wait4`'s `wstatus` output is the same deferred-argument shape again,
just a plain `int` this time instead of a buffer or a struct —
decoded into the `WIFEXITED`/`WIFSIGNALED`/`WIFSTOPPED` form real
`strace` uses (`[{WIFEXITED(s) && WEXITSTATUS(s) == 0}]`) via a
single `PTRACE_PEEKDATA`, since an `int` fits in one machine word. It
slots into the same three-way "which deferred fields are set"
exit-stop print as everything else in this section, via a third
pending field (`pending_wait_status_idx`) that — unlike the other
two, which are struct pointers — just needs a plain argument-slot
index (or `-1` for none), since there's nothing else to carry.
`waitid()`'s equivalent is a `siginfo_t`, a different and more
involved decode, and isn't covered.

`open`/`openat`'s flags decoding is a flat OR of named bits against
the real `<fcntl.h>` macros rather than hardcoded numbers — a few of
these have historically differed across architectures, so trusting
the libc header instead of a hand-copied constant avoids getting that
wrong on some future platform. The low two bits (`O_RDONLY`/
`O_WRONLY`/`O_RDWR`) aren't independent flags — they're a small
enum-like value, not bits to OR against — so they're peeled off and
named separately before the rest of the table is walked. `O_SYNC` and
`O_TMPFILE` are each defined as an existing flag *plus* an extra bit,
not bits of their own, so they're checked (and their bits consumed)
before their "subset" flag — `O_DSYNC`, `O_DIRECTORY` — gets a chance
to match on what's left over; get the table order wrong and one real
flag would print as two.

`mmap`/`mprotect`'s `PROT_*` and `mmap`'s `MAP_*` decoding reuses the
same OR-of-matched-names approach as `open`'s flags, just without any
of its wrinkles — `PROT_READ`/`PROT_WRITE`/`PROT_EXEC` and the `MAP_*`
flags are all genuinely independent bits, no composite values or
access-mode-style small integers to special-case. `PROT_NONE` (value
`0`) is handled as its own named case up front, the same way `open`'s
access mode is, since "no bits matched" and "the value was
legitimately zero" need to print differently.

## Requirements

Linux, x86-64 or ARM64, gcc, make, python3 (only used by the syscall
table generator).
