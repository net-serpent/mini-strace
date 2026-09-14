# Changelog

All notable changes to this project are documented here. Format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions are tagged in git from `v1.0.0` onward.

The project had no tags or release process before `v1.0.0`. Rather
than reconstructing a `v0.1`/`v0.2`/... history for points that were
never actually cut as releases, the `v1.0.0` entry summarizes
everything built up to that point in one place. New entries land
under `[Unreleased]` as they are built and get a version + git tag
on release.

## [Unreleased]

### Added

- `LICENSE`: MIT.
- `mount`: flags (`MS_BIND|MS_RDONLY`, ...) instead of a raw number.
- `getdents64`: the directory entries actually read (`d_ino`,
  `d_off`, `d_reclen`, `d_name`, `d_type` via the real `DT_*`
  macros) instead of a raw buffer pointer. Capped at 8 rendered
  entries and 4096 bytes read, with a trailing `...` when either
  limit is hit. Also added to `trace_filter.c`'s `file` category for
  `-e trace=file`, which it had been missing from.
- `stat`/`lstat`/`fstat`/`newfstatat`: the resulting `struct stat`
  (`st_mode` as file type + permission bits, `st_size`, `st_nlink`,
  `st_uid`, `st_gid`) instead of a raw pointer. Deferred to the
  exit-stop like `wait4`'s wstatus, since the struct isn't populated
  until the syscall actually returns.
- `sendmsg`/`recvmsg`: the full `struct msghdr` — destination/sender
  address (via the same sockaddr decoding `connect`/`accept`/...
  already get), each `iovec`'s data, and ancillary data. `sendmsg`'s
  is decoded at the entry-stop (already the caller's own data);
  `recvmsg`'s is deferred to the exit-stop, since the kernel only
  fills it in once the call returns. `SCM_RIGHTS` (passed file
  descriptors) and `SCM_CREDENTIALS` (sender pid/uid/gid) ancillary
  data decode into their actual meaning; anything else shows
  level/type/length only.
- `ioctl`: the request code decoded by name for the terminal (tty)
  ioctls (`TIOCGWINSZ`, `FIONREAD`, ...), which cover most
  real-world traces; any other request falls back to decoding its
  direction/type/number/size bit layout (`_IOC(_IOC_READ, 0x89,
  0x27, 32)`) instead of a bare hex number. The request-specific
  third argument is left as-is, its layout depends on which request
  it is.
- `clone`/`clone3`: flags (`CLONE_VM|CLONE_FS|CLONE_FILES|...`), with
  the exit signal decoded and shown separately (`|SIGCHLD`) instead
  of left packed into flags' unlabeled low byte. `clone3`'s
  `struct clone_args` is read from the tracee's memory; both
  syscalls share one formatting path, so `clone` and `clone3` calls
  performing the same operation decode identically.
- `tests/property_test_decoders.c`: property tests for the pure
  `format_*` decoders in `decoders.c` (no `ptrace` dependency).
  Built with `-fsanitize=address,undefined`, run via
  `make property-test`, wired into CI. Sweeps hand-picked edge
  values and a deterministic random stream against a range of
  output buffer sizes down to 0.

### Changed

- Syscalls now print exactly as many arguments as they actually
  take (`access(path, mode)`), not all 6 raw register slots
  regardless of real arity (`access(path, mode, 0x..., 0x...,
  0x..., 0x...)`, the leftover 4 being whatever those registers
  happened to hold). Covers every syscall this project already has
  dedicated argument decoding for, plus a short list of syscalls
  that show up in essentially every trace (`brk`, `mmap`/`munmap`,
  `getpid` and similar process/thread info, ...); anything else
  still falls back to all 6, since its real arity isn't known.

### Fixed

- `format_map_flags`'s final fallback `snprintf` call was missing
  the `oi < out_size` guard present in every other decoder in the
  file. `snprintf`'s C99 return value is how many bytes it would
  have written, not how many fit; without the guard, a long enough
  flag combination into a small enough buffer pushed `oi` past
  `out_size`, and `out_size - oi` (both `size_t`) underflowed into a
  heap-buffer-overflow. Found by the new property tests on their
  first run.

## [1.0.0] - 2026-09-01

### Added: core tracing

- `ptrace(2)`-based syscall tracer for x86-64 and ARM64 (aarch64)
  Linux. Traces a launched program, or attaches to one already
  running with `-p PID`. Prints every syscall's name, arguments, and
  return value; failed calls show the errno name (`ENOENT`, not
  `2`).
- `-f` follows `fork()`/`vfork()`/`clone()` into child processes
  instead of only the process that was launched. Output lines get a
  `[pid N] ` prefix.
- Signals delivered to a traced process (crashes, external kills)
  get a `--- SIGNAME (description) ---` line before being forwarded,
  matching real `strace`.
- `-e trace=SET` filters which syscalls are printed: a
  comma-separated mix of categories (`file`, `network`, `process`)
  and/or exact syscall names.
- `-T` times each syscall (wall clock, entry-stop to exit-stop) and
  appends it as `<seconds.microseconds>`.
- `-c` replaces per-call output with a summary table: calls, errors,
  and total time grouped by syscall name, sorted slowest-first.
- `-o FILE` sends the trace to a file instead of stdout/stderr,
  without touching the traced program's own stdin/stdout/stderr.
- `-s SIZE` caps how many raw bytes of a string/buffer argument are
  read and shown before truncating with `...` (default 200).
- `-y` resolves file descriptor arguments to what they point to, via
  `/proc/pid/fd/N`, e.g. `read(3</etc/passwd>, ...)`.

### Added: argument decoding

Decoded instead of printed as a bare pointer or raw number:

- `open`/`stat`/`execve`/`symlink`/`link`/`mount` and similar: path
  arguments as strings.
- `execve`/`execveat`: `argv`/`envp` arrays, decoded element by
  element.
- `read`/`write`: the bytes moved.
- `connect`/`bind`/`sendto`/`recvfrom`/`accept`/`getsockname`/
  `getpeername`: the socket address (`AF_INET`, `AF_INET6`,
  `AF_UNIX`, including abstract-socket `@` paths). `recvfrom` shows
  both the received data and the sender's address in the same line.
- `socket`/`socketpair`: domain and type (`AF_INET`,
  `SOCK_STREAM|SOCK_CLOEXEC`, ...).
- `open`/`openat`: flags (`O_WRONLY|O_CREAT|O_TRUNC` instead of a
  hex number).
- `mmap`/`mprotect`: protection/mapping flags (`PROT_READ|PROT_WRITE`,
  `MAP_PRIVATE|MAP_ANONYMOUS`).
- `wait4`: exit status, decoded into the `WIFEXITED`/`WIFSIGNALED`/
  `WIFSTOPPED` form real `strace` uses.
- `kill`/`tkill`/`tgkill`: target signal by name (`SIGTERM`); the
  null signal `0` prints as plain `0`.
- `lseek`: `whence` (`SEEK_SET`/`SEEK_CUR`/`SEEK_END`).
- `fcntl`: `cmd` (`F_GETFD`, `F_SETFL`, `F_DUPFD_CLOEXEC`, ...).
- `rt_sigprocmask`: `how` (`SIG_BLOCK`/`SIG_UNBLOCK`/`SIG_SETMASK`).
- `access`/`faccessat`/`faccessat2`: `mode` (`R_OK|W_OK`, `F_OK`).
- `clock_gettime`/`clock_settime`/`clock_getres`/`clock_nanosleep`:
  `clockid` (`CLOCK_REALTIME`, `CLOCK_MONOTONIC`, ...).

### Added: testing & tooling

- `tests/run_tests.sh`: regression suite exercising every flag and
  decoder above against real programs and real syscalls.
- GitHub Actions CI (`.github/workflows/ci.yml`) running the suite
  on every push/PR to `main`.
- `Dockerfile`/`docker-compose.yml` for building and running on
  Linux from a non-Linux host (`ptrace` needs a real Linux kernel).

### Changed

- Split the single ~2000-line `src/mini_strace.c` into modules:
  `arch.h` (register access), `arg_routing.{c,h}` (which argument
  holds what), `child_mem.{c,h}` (reading the tracee's memory),
  `decoders.{c,h}` (formatting raw values), and `mini_strace.c`
  itself (tracer loop, per-tracee state, `main()`). No behavior
  change; verified by the test suite passing identically before and
  after.
