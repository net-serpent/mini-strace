# Changelog

All notable changes to this project are documented here. Format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions are tagged in git from `v1.0.0` onward.

`v1.0.0` covers everything built before this file existed — the
project had no tags or release process before now, so rather than
inventing a `v0.1`/`v0.2`/... history for points that were never
actually cut as releases, this first entry summarizes the whole
run-up in one place. From here on, new entries land under
`[Unreleased]` as they're built, and get a real version + git tag
when they ship.

## [Unreleased]

## [1.0.0] - 2026-09-01

### Added — core tracing

- `ptrace(2)`-based syscall tracer for x86-64 and ARM64 (aarch64)
  Linux: traces a launched program (or `-p PID` to attach to one
  already running) and prints every syscall's name, arguments, and
  return value, with failed calls showing the errno name
  (`ENOENT`, not `2`).
- `-f` follows `fork()`/`vfork()`/`clone()` into child processes
  instead of only ever watching the one process that was launched;
  output lines get a `[pid N] ` prefix.
- Signals delivered to a traced process (crashes, external kills,
  ...) get their own `--- SIGNAME (description) ---` line before
  being forwarded on, same as real `strace`.
- `-e trace=SET` filters which syscalls get printed — a
  comma-separated mix of categories (`file`, `network`, `process`)
  and/or exact syscall names.
- `-T` times each syscall (wall clock, entry-stop to exit-stop) and
  appends it as `<seconds.microseconds>`.
- `-c` replaces per-call output with a summary table — calls,
  errors, and total time grouped by syscall name, sorted
  slowest-first.
- `-o FILE` sends the trace to a file instead of stdout/stderr,
  without touching the traced program's own stdin/stdout/stderr.
- `-s SIZE` caps how many raw bytes of a string/buffer argument get
  read and shown before truncating with `...` (default 200).
- `-y` resolves file descriptor arguments to whatever they point to
  via `/proc/pid/fd/N`, e.g. `read(3</etc/passwd>, ...)`.

### Added — argument decoding

Instead of a bare pointer or a raw number, these now show something
readable:

- `open`/`stat`/`execve`/`symlink`/`link`/`mount` and friends: path
  arguments as actual strings.
- `execve`/`execveat`: `argv`/`envp` arrays, decoded element by
  element.
- `read`/`write`: the bytes being moved.
- `connect`/`bind`/`sendto`/`recvfrom`/`accept`/`getsockname`/
  `getpeername`: the socket address (`AF_INET`, `AF_INET6`, and
  `AF_UNIX`, including abstract-socket `@` paths) instead of a raw
  pointer — `recvfrom` shows both the received data *and* the
  sender's address in the same line.
- `socket`/`socketpair`: domain and type (`AF_INET`,
  `SOCK_STREAM|SOCK_CLOEXEC`, ...).
- `open`/`openat`: flags (`O_WRONLY|O_CREAT|O_TRUNC` instead of a
  hex number).
- `mmap`/`mprotect`: protection/mapping flags (`PROT_READ|PROT_WRITE`,
  `MAP_PRIVATE|MAP_ANONYMOUS`).
- `wait4`: exit status, decoded into the `WIFEXITED`/`WIFSIGNALED`/
  `WIFSTOPPED` form real `strace` uses.
- `kill`/`tkill`/`tgkill`: target signal by name (`SIGTERM`), with
  the "null signal" `0` kept as plain `0`.
- `lseek`: `whence` (`SEEK_SET`/`SEEK_CUR`/`SEEK_END`).
- `fcntl`: `cmd` (`F_GETFD`, `F_SETFL`, `F_DUPFD_CLOEXEC`, ...).
- `rt_sigprocmask`: `how` (`SIG_BLOCK`/`SIG_UNBLOCK`/`SIG_SETMASK`).
- `access`/`faccessat`/`faccessat2`: `mode` (`R_OK|W_OK`, `F_OK`).
- `clock_gettime`/`clock_settime`/`clock_getres`/`clock_nanosleep`:
  `clockid` (`CLOCK_REALTIME`, `CLOCK_MONOTONIC`, ...).

### Added — testing & tooling

- `tests/run_tests.sh`: a regression suite exercising every flag and
  decoder above against real programs and real syscalls.
- GitHub Actions CI (`.github/workflows/ci.yml`) running the suite
  on every push/PR to `main`.
- `Dockerfile`/`docker-compose.yml` for building and running on
  Linux from a non-Linux host (`ptrace` needs a real Linux kernel).

### Changed

- Split the single ~2000-line `src/mini_strace.c` into modules —
  `arch.h` (register access), `arg_routing.{c,h}` (which argument
  holds what), `child_mem.{c,h}` (reading the tracee's memory),
  `decoders.{c,h}` (formatting raw values), and `mini_strace.c`
  itself (the tracer loop, per-tracee state, and `main()`) — with no
  behavior change, verified by the full test suite passing
  identically before and after.
