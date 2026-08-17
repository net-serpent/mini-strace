# mini-strace

A stripped-down clone of `strace`, built on Linux's `ptrace(2)` API.

## What it does

Traces a target program and prints every syscall: name, arguments,
return value. Failed calls show the errno name (`ENOENT`, not `2`).
A handful of common syscalls get extra treatment `open`/`stat`/
`execve` and friends show their path argument as an actual string
instead of a pointer, `execve`/`execveat` show their `argv`/`envp`
arrays decoded too, and `read`/`write` show the bytes they're
moving. You can also narrow the trace down with `-e trace=SET`,
where SET is a comma-separated mix of categories (`file`, `network`,
`process`) and/or exact syscall names: `-e trace=file` shows only
filesystem calls, `-e trace=network,openat` shows networking plus
that one specific syscall:

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

## Requirements

Linux, x86-64 or ARM64, gcc, make, python3 (only used by the syscall
table generator).
