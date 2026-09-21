# mini-strace

[![CI](https://github.com/net-serpent/mini-strace/actions/workflows/ci.yml/badge.svg)](https://github.com/net-serpent/mini-strace/actions/workflows/ci.yml)

A stripped-down clone of `strace`, built on Linux's `ptrace(2)` API.
See [CHANGELOG.md](CHANGELOG.md) for release history and
[DESIGN.md](DESIGN.md) for internals.

## What it does

Traces a target program and prints every syscall: name, arguments,
return value. Failed calls show the errno name (`ENOENT`, not `2`).

A number of syscalls decode their arguments instead of printing a
bare pointer or a raw number:

- `open`/`stat`/`execve`/`symlink`/`link`/`mount` and similar: path
  arguments as strings
- `execve`/`execveat`: `argv`/`envp` arrays, decoded
- `read`/`write`: the bytes moved
- `connect`/`bind`/`sendto`/`recvfrom`/`accept`/`getsockname`/
  `getpeername`: the socket address, e.g. `{sa_family=AF_INET,
  sin_port=htons(80), sin_addr=inet_addr("1.2.3.4")}` for IPv4, the
  equivalent for IPv6, `{sa_family=AF_UNIX, sun_path="/path"}` for
  Unix sockets
- `open`/`openat`: flags (`O_WRONLY|O_CREAT|O_TRUNC` instead of
  `0x241`)
- `mmap`/`mprotect`: protection/mapping flags (`PROT_READ|PROT_WRITE`,
  `MAP_PRIVATE|MAP_ANONYMOUS`)
- `mount`: flags (`MS_BIND|MS_RDONLY`, ...) instead of a raw number
- `socket`/`socketpair`: domain and type
  (`socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, 0x0)` instead of two
  bare hex numbers)
- `kill`/`tkill`/`tgkill`: target signal by name (`SIGTERM` instead
  of `0xf`; the null signal `0` prints as plain `0`)
- `lseek`: `whence` (`SEEK_SET`/`SEEK_CUR`/`SEEK_END` instead of
  `0`/`1`/`2`)
- `fcntl`: `cmd` (`F_GETFD`, `F_SETFL`, `F_DUPFD_CLOEXEC`, ...)
- `rt_sigprocmask`: `how` (`SIG_BLOCK`/`SIG_UNBLOCK`/`SIG_SETMASK`)
- `access`/`faccessat`/`faccessat2`: `mode` (`R_OK|W_OK`, `F_OK`)
- `clock_gettime`/`clock_settime`/`clock_getres`/`clock_nanosleep`:
  `clockid` (`CLOCK_REALTIME`/`CLOCK_MONOTONIC`, ...)
- `clock_gettime`/`clock_settime`/`nanosleep`/`clock_nanosleep`: the
  `struct timespec` itself (`{tv_sec=1234, tv_nsec=5678}`) instead of
  a raw pointer
- `clone`/`clone3`: flags (`CLONE_VM|CLONE_FS|CLONE_FILES|...`), with
  the exit signal shown alongside them (`|SIGCHLD`) instead of
  packed into an unlabeled low byte
- `ioctl`: the request code (`TIOCGWINSZ`, `FIONREAD`, ...) instead
  of a raw number; an unrecognized request decodes its
  direction/type/number/size bit layout (`_IOC(_IOC_READ, 0x89,
  0x27, 32)`) instead of showing only hex
- `sendmsg`/`recvmsg`: the full `struct msghdr` — destination/sender
  address, each `iovec`'s data, and ancillary data (`SCM_RIGHTS`
  file descriptor passing, `SCM_CREDENTIALS`) instead of a raw
  pointer
- `stat`/`lstat`/`fstat`/`newfstatat`: the resulting `struct stat`
  (`{st_mode=S_IFREG|0644, st_size=1234, st_nlink=1, st_uid=0,
  st_gid=0}`) instead of a raw pointer
- `wait4`: exit status, decoded into the `WIFEXITED`/`WIFSIGNALED`/
  `WIFSTOPPED` form real `strace` uses, and the resulting
  `struct rusage` (`ru_utime`/`ru_stime`/`ru_maxrss`) instead of raw
  pointers
- `epoll_ctl`: `op` (`EPOLL_CTL_ADD`/`EPOLL_CTL_MOD`/`EPOLL_CTL_DEL`)
  and the `struct epoll_event` (`{events=EPOLLIN|EPOLLET,
  data={u32=4, u64=4}}`) instead of a raw number and pointer
- `epoll_wait`/`epoll_pwait`: the array of ready events actually
  returned instead of a raw buffer pointer
- `getdents64`: the directory entries actually read
  (`[{d_ino=1234, d_off=..., d_reclen=32, d_name="file.txt",
  d_type=DT_REG}, ...]`) instead of a raw buffer pointer
- `rt_sigaction`: the signal being configured by name, and the
  `struct sigaction` itself (`{sa_handler=0x..., sa_flags=SA_RESTART,
  sa_mask=[SIGUSR1 SIGTERM]}`, or `SIG_DFL`/`SIG_IGN` in place of a
  handler address) instead of raw pointers

Narrow the trace with `-e trace=SET`, a comma-separated mix of
categories (`file`, `network`, `process`) and/or exact syscall
names: `-e trace=file` shows only filesystem calls,
`-e trace=network,openat` shows networking plus that one syscall.

```
execve("/bin/cat", ["cat", "foo.txt"], ["PATH=/usr/bin", "HOME=/root"]) = 0
access("/etc/ld.so.preload", 0x4) = -2 (ENOENT)
openat(0xffffff9c, "/etc/ld.so.cache", 0x80000, 0x0) = 3
openat(0xffffff9c, "/tmp/somefile.txt", 0x0, 0x0) = 3
read(0x3, "test data content\n", 0x20000) = 18
write(0x1, "test data content\n", 0x12) = 18
read(0x3, 0x7fa474eae000, 0x20000) = 0
[mini-strace] process exited, code 0, total syscalls: 37
```

Each syscall prints exactly as many arguments as it actually takes
(`access(path, mode)`, not six slots padded with leftover register
values); an unrecognized syscall still shows all 6 raw slots, since
its real arity isn't known.

## Build & run

```bash
make
./mini-strace /bin/echo hello world
./mini-strace -e trace=file /bin/cat some-file.txt
```

Attach to an already-running process by PID instead of launching a
new one:

```bash
./mini-strace -p 12345
./mini-strace -e trace=network -p 12345
```

By default only the process you launch (or attach to) is traced;
anything it forks runs untraced. `-f` follows into child processes
too; each output line gets a `[pid N] ` prefix identifying the
process:

```bash
./mini-strace -f /bin/sh -c 'echo hi'
./mini-strace -f -e trace=process /bin/make
```

`-T` times each syscall (wall clock, entry-stop to exit-stop) and
appends it to the line, e.g. `= 0 <1.000484>`:

```bash
./mini-strace -T /bin/sleep 1
```

`-c` prints a summary instead of a line per call: total calls,
errors, and time spent, grouped by syscall name, sorted
slowest-first:

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

`-o FILE` sends the trace (and the `[mini-strace] ...` status lines)
to a file instead of stdout/stderr. The traced program's own
stdin/stdout/stderr are untouched:

```bash
./mini-strace -o trace.log /bin/echo hello
```

String and buffer arguments are truncated at 200 bytes by default
(shown with a trailing `...`). `-s SIZE` raises or lowers that:

```bash
./mini-strace -s 4 /bin/echo hello-world
# write(1, "hell"..., 11) = 11
```

`-y` resolves file descriptor arguments to what they point to, via
`/proc/pid/fd/N`:

```bash
./mini-strace -y /bin/cat /etc/hostname
# openat(0xffffff9c, "/etc/hostname", 0x0, 0x0) = 3
# read(3</etc/hostname>, "myhost\n"..., 0x20000) = 7
```

On macOS:

```bash
docker compose run --rm dev
# now inside the container
make
./mini-strace /bin/echo hello world
```

## Testing

```bash
make
bash tests/run_tests.sh
```

On macOS, run it inside the dev container the same way as the
build:

```bash
docker compose run --rm dev
make
bash tests/run_tests.sh
```

CI runs this on every push/PR to `main`. One test (`-p` attach to a
sibling process) is skipped rather than failed if the environment's
ptrace permissions do not allow it; some sandboxes restrict
`PTRACE_ATTACH` to direct descendants only.

Property tests for the pure decoders in `decoders.c`:

```bash
make property-test
```

See [DESIGN.md](DESIGN.md#testing) for what this covers and why.

## Requirements

Linux, x86-64 or ARM64, gcc, make, python3 (only used by the syscall
table generator).

## License

MIT, see [LICENSE](LICENSE).
