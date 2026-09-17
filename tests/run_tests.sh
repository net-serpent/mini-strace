#!/bin/bash
# Regression tests for mini-strace. Linux-only (needs ptrace), run from
# the repo root after `make`:
#
#   make && bash tests/run_tests.sh
#
# Each test runs the real binary against a real program and greps the
# output for the pattern that specific feature is supposed to produce
# — these are the same checks that were run by hand throughout
# development, just made repeatable instead of one-off.

set -u

STRACE=./mini-strace
PASS=0
FAIL=0
SKIP=0

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
skip() { SKIP=$((SKIP + 1)); echo "  SKIP: $1 ($2)"; }
fail() {
    FAIL=$((FAIL + 1))
    echo "  FAIL: $1"
    echo "        expected to match: $2"
    echo "        --- output ---"
    echo "$3" | sed 's/^/        /'
    echo "        --------------"
}

# $1 = description, $2 = extended-regex pattern, $3 = text to search
check_contains() {
    if echo "$3" | grep -qE "$2"; then
        pass "$1"
    else
        fail "$1" "$2" "$3"
    fi
}

check_not_contains() {
    if echo "$3" | grep -qE "$2"; then
        fail "$1 (should NOT match)" "$2" "$3"
    else
        pass "$1"
    fi
}

echo "=== basic exec trace ==="
out=$($STRACE /bin/echo hello 2>&1)
check_contains "execve of the target is shown" 'execve\("/bin/echo"' "$out"
check_contains "write() shows the actual output" 'write\(0x1, "hello' "$out"
check_contains "exit summary with total syscall count" 'process exited, code 0, total syscalls' "$out"

echo "=== -e trace=SET filtering ==="
out=$($STRACE -e trace=file /bin/echo hello 2>&1)
check_not_contains "process-category execve excluded by trace=file" '^execve' "$out"
check_contains "file-category openat still shown" 'openat\(' "$out"

out=$($STRACE -e trace=process /bin/echo hello 2>&1)
check_contains "process-category execve shown by trace=process" 'execve\(' "$out"
check_not_contains "file-category openat excluded by trace=process" 'openat\(' "$out"

echo "=== -f follow forks ==="
out=$($STRACE -f /bin/sh -c '/bin/echo forked' 2>&1)
check_contains "output lines get a [pid N] prefix" '\[pid [0-9]+\]' "$out"
check_contains "the forked child's own execve is traced" 'execve\("/bin/echo"' "$out"

echo "=== signal delivery ==="
cat >/tmp/mini_strace_test_crash.c <<'EOF'
int main(void) { volatile int *p = 0; *p = 1; return 0; }
EOF
gcc -O0 -o /tmp/mini_strace_test_crash /tmp/mini_strace_test_crash.c
out=$($STRACE /tmp/mini_strace_test_crash 2>&1)
check_contains "SIGSEGV is announced before the process dies" '\-\-\- SIGSEGV' "$out"
check_contains "final summary reports the killing signal" 'killed by signal 11' "$out"

echo "=== -T timing ==="
out=$($STRACE -T /bin/sleep 1 2>&1)
check_contains "elapsed time is appended to a syscall line" '<[0-9]+\.[0-9]+>' "$out"

echo "=== -c summary mode ==="
out=$($STRACE -c /bin/echo hi 2>&1)
check_contains "summary table header is printed" '% time' "$out"
check_contains "summary table has a total row" '^100\.00' "$out"
check_not_contains "no per-call execve line under -c" '^execve\(' "$out"

echo "=== -o output file ==="
rm -f /tmp/mini_strace_test_trace.log
out=$($STRACE -o /tmp/mini_strace_test_trace.log /bin/echo output-file-marker 2>&1)
check_contains "traced program's own stdout still reaches us" 'output-file-marker' "$out"
check_not_contains "trace content does NOT leak onto stdout" 'execve\(' "$out"
if [ -s /tmp/mini_strace_test_trace.log ] && grep -q 'execve(' /tmp/mini_strace_test_trace.log; then
    pass "trace content actually landed in the -o file"
else
    fail "trace content actually landed in the -o file" "execve( in /tmp/mini_strace_test_trace.log" "$(cat /tmp/mini_strace_test_trace.log 2>&1)"
fi

echo "=== -s string/buffer size cap ==="
out=$($STRACE -s 4 /bin/echo hello-world 2>&1)
check_contains "string truncated at the requested size" '"hell"\.\.\.' "$out"

echo "=== -y fd path resolution ==="
out=$($STRACE -y /bin/cat /etc/hostname 2>&1)
check_contains "fd is annotated with the path it points to" '<[^>]*hostname>' "$out"

echo "=== execve argv/envp decoding ==="
out=$($STRACE /bin/echo foo bar 2>&1)
check_contains "argv is decoded as a string array" '\["/bin/echo", "foo", "bar"\]' "$out"

echo "=== expanded path-string syscalls ==="
rm -f /tmp/mini_strace_test_symlink_target /tmp/mini_strace_test_symlink_link
touch /tmp/mini_strace_test_symlink_target
out=$($STRACE /bin/ln -s /tmp/mini_strace_test_symlink_target /tmp/mini_strace_test_symlink_link 2>&1)
check_contains "symlink target/linkpath both decoded as strings" \
    'symlinkat\("/tmp/mini_strace_test_symlink_target", .*"/tmp/mini_strace_test_symlink_link"' "$out"

echo "=== sockaddr decoding: AF_INET ==="
out=$($STRACE -e trace=network python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1)
try:
    s.connect(("93.184.216.34", 80))
except Exception:
    pass
' 2>&1)
check_contains "IPv4 address decoded in connect()" 'sin_addr=inet_addr\("93\.184\.216\.34"\)' "$out"

echo "=== sockaddr decoding: AF_INET6 ==="
out=$($STRACE -e trace=network python3 -c '
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.settimeout(1)
try:
    s.connect(("::1", 12345))
except Exception:
    pass
' 2>&1)
check_contains "IPv6 loopback address decoded in connect()" 'sin6_addr=inet_pton\(AF_INET6, "::1"\)' "$out"

echo "=== sockaddr decoding: AF_UNIX ==="
rm -f /tmp/mini_strace_test.sock
out=$($STRACE -e trace=network python3 -c '
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind("/tmp/mini_strace_test.sock")
' 2>&1)
check_contains "unix socket path decoded in bind()" 'sun_path="/tmp/mini_strace_test\.sock"' "$out"

echo "=== recvfrom: combined data + sockaddr deferral ==="
cat >/tmp/mini_strace_test_udp.py <<'EOF'
import socket, os
srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
srv.bind(("127.0.0.1", 0))
port = srv.getsockname()[1]
pid = os.fork()
if pid == 0:
    import time
    time.sleep(0.3)
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    c.sendto(b"hello-udp", ("127.0.0.1", port))
    os._exit(0)
else:
    data, addr = srv.recvfrom(1024)
    os.waitpid(pid, 0)
EOF
out=$($STRACE -e trace=network python3 /tmp/mini_strace_test_udp.py 2>&1)
check_contains "recvfrom shows the received data" 'recvfrom\(0x[0-9a-f]+, "hello-udp"' "$out"
check_contains "recvfrom shows the sender's address in the same line" \
    'recvfrom\(.*sin_addr=inet_addr\("127\.0\.0\.1"\)' "$out"

echo "=== accept/getsockname/getpeername deferred sockaddr ==="
cat >/tmp/mini_strace_test_tcp.py <<'EOF'
import socket, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0))
port = s.getsockname()[1]
s.listen(1)
pid = os.fork()
if pid == 0:
    import time
    time.sleep(0.3)
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.connect(("127.0.0.1", port))
    time.sleep(0.5)
    os._exit(0)
else:
    conn, addr = s.accept()
    conn.getpeername()
    os.waitpid(pid, 0)
EOF
out=$($STRACE -e trace=network python3 /tmp/mini_strace_test_tcp.py 2>&1)
check_contains "accept() decodes the connecting peer's address" \
    'accept4?\(.*sin_addr=inet_addr\("127\.0\.0\.1"\)' "$out"
check_contains "getpeername() decodes the peer address" \
    'getpeername\(.*sin_addr=inet_addr\("127\.0\.0\.1"\)' "$out"

echo "=== wait4 status decoding ==="
out=$($STRACE /bin/sh -c '/bin/true' 2>&1)
check_contains "normal exit status decoded" \
    'wait4\(.*WIFEXITED\(s\) && WEXITSTATUS\(s\) == 0' "$out"

cat >/tmp/mini_strace_test_crashchild.c <<'EOF'
int main(void) { volatile int *p = 0; *p = 1; return 0; }
EOF
gcc -O0 -o /tmp/mini_strace_test_crashchild /tmp/mini_strace_test_crashchild.c
out=$($STRACE /bin/sh -c /tmp/mini_strace_test_crashchild 2>&1)
check_contains "signal-killed child status decoded" \
    'wait4\(.*WIFSIGNALED\(s\) && WTERMSIG\(s\) == SIGSEGV' "$out"

echo "=== open/openat flags decoding ==="
out=$($STRACE /bin/cat /etc/hostname 2>&1)
check_contains "plain read-only open decoded" 'openat\(.*O_RDONLY\|O_CLOEXEC' "$out"

rm -f /tmp/mini_strace_test_flagtest.txt
out=$($STRACE python3 -c "open('/tmp/mini_strace_test_flagtest.txt', 'w')" 2>&1)
check_contains "write+create+truncate open decoded" \
    'openat\(.*O_WRONLY\|O_CREAT\|O_TRUNC' "$out"

echo "=== mmap/mprotect flags decoding ==="
out=$($STRACE /bin/echo hi 2>&1)
check_contains "anonymous mmap shows PROT_READ|PROT_WRITE" \
    'mmap\(.*PROT_READ\|PROT_WRITE.*MAP_PRIVATE\|MAP_ANONYMOUS' "$out"
check_contains "mprotect shows a decoded PROT value" 'mprotect\(.*PROT_(READ|NONE|EXEC|WRITE)' "$out"

out=$($STRACE python3 -c '
import mmap
m = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE)
m.close()
' 2>&1)
check_contains "explicit PROT_READ|PROT_WRITE mmap decoded" \
    'mmap\(.*PROT_READ\|PROT_WRITE.*MAP_SHARED\|MAP_ANONYMOUS' "$out"

echo "=== socket() domain/type decoding ==="
out=$($STRACE -e trace=network python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.close()
' 2>&1)
check_contains "TCP socket domain/type decoded" 'socket\(AF_INET, SOCK_STREAM\|SOCK_CLOEXEC' "$out"

out=$($STRACE -e trace=network python3 -c '
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.close()
' 2>&1)
check_contains "unix socket domain decoded" 'socket\(AF_UNIX, SOCK_STREAM' "$out"

out=$($STRACE -e trace=network python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_NONBLOCK)
s.close()
' 2>&1)
check_contains "combined SOCK_CLOEXEC|SOCK_NONBLOCK decoded" \
    'socket\(AF_INET, SOCK_STREAM\|SOCK_CLOEXEC\|SOCK_NONBLOCK' "$out"

echo "=== kill() signal decoding ==="
out=$($STRACE python3 -c '
import os, signal
os.kill(os.getpid(), signal.SIGTERM)
' 2>&1)
check_contains "SIGTERM decoded" 'kill\([^,]*, SIGTERM' "$out"

out=$($STRACE python3 -c '
import os
os.kill(os.getpid(), 0)
' 2>&1)
check_contains "null signal (0) printed as plain 0, not a fake name" 'kill\([^,]*, 0\)' "$out"

echo "=== lseek() whence decoding ==="
out=$($STRACE python3 -c '
f = open("/etc/hostname", "rb")
f.seek(0, 0)
f.seek(1, 1)
f.seek(0, 2)
' 2>&1)
check_contains "SEEK_SET decoded" 'lseek\(0x[0-9a-f]+, 0x0, SEEK_SET' "$out"
check_contains "SEEK_CUR decoded" 'lseek\(0x[0-9a-f]+, 0x1, SEEK_CUR' "$out"
check_contains "SEEK_END decoded" 'lseek\(0x[0-9a-f]+, 0x0, SEEK_END' "$out"

echo "=== fcntl() cmd decoding ==="
out=$($STRACE python3 -c 'pass' 2>&1)
check_contains "F_GETFD decoded (interpreter startup)" 'fcntl\(0x[0-9a-f]+, F_GETFD' "$out"

out=$($STRACE python3 -c '
import fcntl, os
fd = os.open("/etc/hostname", os.O_RDONLY)
fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 0)
' 2>&1)
check_contains "F_DUPFD_CLOEXEC decoded" 'fcntl\(0x[0-9a-f]+, F_DUPFD_CLOEXEC' "$out"

out=$($STRACE python3 -c '
import fcntl, os
fd = os.open("/etc/hostname", os.O_RDONLY)
flags = fcntl.fcntl(fd, fcntl.F_GETFL)
fcntl.fcntl(fd, fcntl.F_SETFL, flags)
' 2>&1)
check_contains "F_GETFL decoded" 'fcntl\(0x[0-9a-f]+, F_GETFL' "$out"
check_contains "F_SETFL decoded" 'fcntl\(0x[0-9a-f]+, F_SETFL' "$out"

echo "=== rt_sigprocmask() how decoding ==="
out=$($STRACE python3 -c '
import signal
signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGTERM])
' 2>&1)
check_contains "SIG_BLOCK decoded" 'rt_sigprocmask\(SIG_BLOCK' "$out"

out=$($STRACE python3 -c '
import signal
signal.pthread_sigmask(signal.SIG_UNBLOCK, [signal.SIGTERM])
' 2>&1)
check_contains "SIG_UNBLOCK decoded" 'rt_sigprocmask\(SIG_UNBLOCK' "$out"

out=$($STRACE python3 -c '
import signal
signal.pthread_sigmask(signal.SIG_SETMASK, [])
' 2>&1)
check_contains "SIG_SETMASK decoded" 'rt_sigprocmask\(SIG_SETMASK' "$out"

echo "=== access()/faccessat() mode decoding ==="
out=$($STRACE python3 -c '
import os
os.access("/etc/hostname", os.F_OK)
' 2>&1)
check_contains "F_OK decoded" '(access|faccessat)\([^)]*, F_OK' "$out"

out=$($STRACE python3 -c '
import os
os.access("/etc/hostname", os.R_OK | os.W_OK)
' 2>&1)
check_contains "combined R_OK|W_OK decoded" '(access|faccessat)\([^)]*, R_OK\|W_OK' "$out"

echo "=== clockid decoding ==="
# glibc serves time.time()/time.monotonic() from the VDSO (no real
# syscall at all), so a direct syscall() call is used here instead
# to force an actual clock_gettime syscall mini-strace can see.
cat >/tmp/mini_strace_test_clock.c <<'EOF'
#include <time.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(void) {
    struct timespec ts;
    syscall(SYS_clock_gettime, CLOCK_REALTIME, &ts);
    syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &ts);
    return 0;
}
EOF
gcc -O0 -o /tmp/mini_strace_test_clock /tmp/mini_strace_test_clock.c
out=$($STRACE /tmp/mini_strace_test_clock 2>&1)
check_contains "CLOCK_REALTIME decoded" 'clock_gettime\(CLOCK_REALTIME' "$out"
check_contains "CLOCK_MONOTONIC decoded" 'clock_gettime\(CLOCK_MONOTONIC' "$out"

echo "=== clone/clone3 flags decoding ==="
out=$($STRACE python3 -c '
import threading
t = threading.Thread(target=lambda: None)
t.start()
t.join()
' 2>&1)
check_contains "CLONE_THREAD decoded (pthread_create via clone or clone3)" \
    'clone3?\(.*CLONE_THREAD' "$out"

cat >/tmp/mini_strace_test_fork.c <<'EOF'
#include <unistd.h>
#include <sys/wait.h>

int main(void) {
    pid_t pid = fork();
    if (pid == 0)
        _exit(0);
    int status;
    waitpid(pid, &status, 0);
    return 0;
}
EOF
gcc -O0 -o /tmp/mini_strace_test_fork /tmp/mini_strace_test_fork.c
out=$($STRACE -f /tmp/mini_strace_test_fork 2>&1)
check_contains "exit signal SIGCHLD decoded on a plain fork-like clone" \
    'clone\(.*\|SIGCHLD' "$out"

cat >/tmp/mini_strace_test_clone3.c <<'EOF'
#define _GNU_SOURCE
#include <linux/sched.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <string.h>

struct clone_args_min {
    __u64 flags;
    __u64 pidfd;
    __u64 child_tid;
    __u64 parent_tid;
    __u64 exit_signal;
    __u64 stack;
    __u64 stack_size;
    __u64 tls;
};

int main(void) {
    struct clone_args_min args;
    memset(&args, 0, sizeof(args));
    args.flags = CLONE_VM | CLONE_VFORK;
    args.exit_signal = SIGCHLD;
    static char stack[65536];
    args.stack = (unsigned long)stack;
    args.stack_size = sizeof(stack);

    long ret = syscall(SYS_clone3, &args, sizeof(args));
    if (ret == 0)
        _exit(0);
    int status;
    waitpid(ret, &status, 0);
    return 0;
}
EOF
gcc -O0 -o /tmp/mini_strace_test_clone3 /tmp/mini_strace_test_clone3.c
out=$($STRACE /tmp/mini_strace_test_clone3 2>&1)
check_contains "clone3's flags field decoded (struct clone_args)" \
    'clone3\(CLONE_VM\|CLONE_VFORK' "$out"
check_contains "clone3's separate exit_signal field decoded" \
    'clone3\(.*\|SIGCHLD' "$out"

echo "=== ioctl request decoding ==="
cat >/tmp/mini_strace_test_ioctl.c <<'EOF'
#include <sys/ioctl.h>
#include <unistd.h>

#define IOCTL_TEST_UNKNOWN _IOR('z', 1, int)

int main(void) {
    int fds[2];
    if (pipe(fds) != 0)
        return 1;
    int n;
    ioctl(fds[0], FIONREAD, &n);
    ioctl(fds[0], IOCTL_TEST_UNKNOWN, &n);
    close(fds[0]);
    close(fds[1]);
    return 0;
}
EOF
gcc -O0 -o /tmp/mini_strace_test_ioctl /tmp/mini_strace_test_ioctl.c
out=$($STRACE /tmp/mini_strace_test_ioctl 2>&1)
check_contains "known ioctl request decoded by name (FIONREAD)" \
    'ioctl\(.*, FIONREAD,' "$out"
check_contains "unknown ioctl request decoded via its dir/type/nr/size bits" \
    'ioctl\(.*, _IOC\(_IOC_READ, 0x7a, 0x1, 4\),' "$out"

echo "=== sendmsg/recvmsg struct msghdr decoding ==="
cat >/tmp/mini_strace_test_msghdr_fd.c <<'EOF'
#define _GNU_SOURCE
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0)
        return 1;

    int pass_fd = open("/etc/hostname", O_RDONLY);

    char data[] = "hello";
    struct iovec iov = { .iov_base = data, .iov_len = sizeof(data) - 1 };

    char cbuf[CMSG_SPACE(sizeof(int))];
    memset(cbuf, 0, sizeof(cbuf));
    struct msghdr smsg;
    memset(&smsg, 0, sizeof(smsg));
    smsg.msg_iov = &iov;
    smsg.msg_iovlen = 1;
    smsg.msg_control = cbuf;
    smsg.msg_controllen = sizeof(cbuf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&smsg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &pass_fd, sizeof(int));

    sendmsg(sv[0], &smsg, 0);

    char rbuf[64];
    struct iovec riov = { .iov_base = rbuf, .iov_len = sizeof(rbuf) };
    char rcbuf[CMSG_SPACE(sizeof(int))];
    struct msghdr rmsg;
    memset(&rmsg, 0, sizeof(rmsg));
    rmsg.msg_iov = &riov;
    rmsg.msg_iovlen = 1;
    rmsg.msg_control = rcbuf;
    rmsg.msg_controllen = sizeof(rcbuf);

    recvmsg(sv[1], &rmsg, 0);

    close(sv[0]);
    close(sv[1]);
    close(pass_fd);
    return 0;
}
EOF
gcc -O0 -o /tmp/mini_strace_test_msghdr_fd /tmp/mini_strace_test_msghdr_fd.c
out=$($STRACE /tmp/mini_strace_test_msghdr_fd 2>&1)
check_contains "sendmsg's msg_iov data decoded" \
    'sendmsg\(.*iov_base="hello", iov_len=5' "$out"
check_contains "sendmsg's SCM_RIGHTS ancillary data (fd passing) decoded" \
    'sendmsg\(.*cmsg_type=SCM_RIGHTS, cmsg_data=\[[0-9]+\]' "$out"
check_contains "recvmsg's SCM_RIGHTS ancillary data decoded" \
    'recvmsg\(.*cmsg_type=SCM_RIGHTS, cmsg_data=\[[0-9]+\]' "$out"
check_contains "recvmsg's iov_base truncated to actual bytes received, iov_len kept as the buffer's declared size" \
    'recvmsg\(.*iov_base="hello", iov_len=64' "$out"

cat >/tmp/mini_strace_test_msghdr_addr.c <<'EOF'
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int main(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    char part1[] = "ab";
    char part2[] = "cdef";
    struct iovec iov[2] = {
        { .iov_base = part1, .iov_len = 2 },
        { .iov_base = part2, .iov_len = 4 },
    };
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &addr;
    msg.msg_namelen = sizeof(addr);
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;

    sendmsg(s, &msg, 0);
    close(s);
    return 0;
}
EOF
gcc -O0 -o /tmp/mini_strace_test_msghdr_addr /tmp/mini_strace_test_msghdr_addr.c
out=$($STRACE /tmp/mini_strace_test_msghdr_addr 2>&1)
check_contains "sendmsg's msg_name decoded via the real sockaddr formatter" \
    'sendmsg\(.*msg_name=\{sa_family=AF_INET, sin_port=htons\(9\), sin_addr=inet_addr\("127\.0\.0\.1"\)\}' "$out"
check_contains "sendmsg's multiple iovecs decoded in order" \
    'sendmsg\(.*iov_base="ab", iov_len=2\}, \{iov_base="cdef", iov_len=4\}' "$out"
check_contains "sendmsg's msg_control shown as NULL when absent" \
    'sendmsg\(.*msg_control=NULL' "$out"

echo "=== argument count matches real syscall arity ==="
cat >/tmp/mini_strace_test_argc.c <<'EOF'
#include <unistd.h>
#include <fcntl.h>

int main(void) {
    access("/", 0);   /* F_OK == 0; syscall_argc_table: 2 real args */
    getpid();         /* syscall_argc_table: 0 args */

    int fd = open("/", O_RDONLY);
    posix_fadvise(fd, 0, 0, POSIX_FADV_NORMAL);  /* not in syscall_argc_table */
    close(fd);

    return 0;
}
EOF
gcc -O0 -o /tmp/mini_strace_test_argc /tmp/mini_strace_test_argc.c
out=$($STRACE /tmp/mini_strace_test_argc 2>&1)
check_contains "access()/faccessat() prints exactly its real arguments, not all 6 raw slots" \
    '(access\("/", F_OK\)|faccessat\([^,]*, "/", F_OK\))' "$out"
check_contains "a 0-argument syscall (getpid) prints with no arguments at all" \
    'getpid\(\)' "$out"
check_contains "a syscall not in syscall_argc_table still falls back to all 6 raw slots" \
    'fadvise64\(([^,]*,){5}[^)]*\)' "$out"

echo "=== stat/lstat/fstat/newfstatat struct stat decoding ==="
cat >/tmp/mini_strace_test_stat.c <<'EOF'
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int main(void) {
    int fd = open("/etc/hostname", O_RDONLY);
    struct stat st;
    fstat(fd, &st);
    close(fd);

    symlink("/etc/hostname", "/tmp/mini_strace_test_symlink");
    lstat("/tmp/mini_strace_test_symlink", &st);

    stat("/definitely/does/not/exist", &st);

    return 0;
}
EOF
gcc -O0 -o /tmp/mini_strace_test_stat /tmp/mini_strace_test_stat.c
out=$($STRACE /tmp/mini_strace_test_stat 2>&1)
check_contains "fstat decodes a regular file's type and permissions" \
    'stat\(.*st_mode=S_IFREG\|[0-7]+' "$out"
check_contains "lstat decodes a symlink as S_IFLNK, not following it" \
    '(stat|newfstatat)\(.*S_IFLNK' "$out"
check_contains "the stat family's path argument still decodes as a string alongside the deferred struct stat" \
    '(stat\(|newfstatat\([^,]*, )"/tmp/mini_strace_test_symlink"' "$out"
check_contains "a failed stat leaves the unpopulated struct stat as raw hex, not garbage decoded content" \
    '(stat|newfstatat)\([^{]*\) = -2 \(ENOENT\)' "$out"

echo "=== getdents64 directory entry decoding ==="
mkdir -p /tmp/mini_strace_test_dir
: > /tmp/mini_strace_test_dir/regularfile.txt
ln -sf regularfile.txt /tmp/mini_strace_test_dir/symlinkfile
cat >/tmp/mini_strace_test_getdents.c <<'EOF'
#include <sys/types.h>
#include <dirent.h>
#include <stddef.h>

int main(void) {
    DIR *d = opendir("/tmp/mini_strace_test_dir");
    while (readdir(d) != NULL) {}
    closedir(d);
    return 0;
}
EOF
gcc -O0 -o /tmp/mini_strace_test_getdents /tmp/mini_strace_test_getdents.c
out=$($STRACE /tmp/mini_strace_test_getdents 2>&1)
check_contains "getdents64 decodes a regular file's name and type" \
    'getdents64\(.*d_name="regularfile.txt", d_type=DT_REG' "$out"
check_contains "getdents64 decodes a symlink's type" \
    'getdents64\(.*d_name="symlinkfile", d_type=DT_LNK' "$out"
check_contains "getdents64's final (no more entries) call falls back to raw hex, not garbage" \
    'getdents64\(0x[0-9a-f]+, 0x[0-9a-f]+, 0x[0-9a-f]+\) = 0' "$out"

mkdir -p /tmp/mini_strace_test_bigdir
for i in $(seq 1 20); do : > /tmp/mini_strace_test_bigdir/f$i.txt; done
cat >/tmp/mini_strace_test_getdents_big.c <<'EOF'
#include <sys/types.h>
#include <dirent.h>
#include <stddef.h>

int main(void) {
    DIR *d = opendir("/tmp/mini_strace_test_bigdir");
    while (readdir(d) != NULL) {}
    closedir(d);
    return 0;
}
EOF
gcc -O0 -o /tmp/mini_strace_test_getdents_big /tmp/mini_strace_test_getdents_big.c
out=$($STRACE /tmp/mini_strace_test_getdents_big 2>&1)
check_contains "getdents64 caps the number of displayed entries with an ellipsis for large directories" \
    'getdents64\(.*, \.\.\.\]' "$out"

echo "=== mount() flags decoding ==="
cat >/tmp/mini_strace_test_mount.c <<'EOF'
#include <sys/mount.h>

int main(void) {
    /* expected to fail with EPERM in an unprivileged container - the
     * flags decode from the caller's argument regardless of whether
     * the call actually succeeds */
    mount("/tmp", "/mnt", NULL, MS_BIND | MS_RDONLY, NULL);
    return 0;
}
EOF
gcc -O0 -o /tmp/mini_strace_test_mount /tmp/mini_strace_test_mount.c
out=$($STRACE /tmp/mini_strace_test_mount 2>&1)
check_contains "mount() decodes a combined MS_BIND|MS_RDONLY flags value" \
    'mount\(.*(MS_BIND\|MS_RDONLY|MS_RDONLY\|MS_BIND)' "$out"

echo "=== rt_sigaction struct sigaction decoding ==="
cat >/tmp/mini_strace_test_sigaction.c <<'EOF'
#include <signal.h>
#include <string.h>

void handler(int sig) { (void)sig; }

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));

    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    sa.sa_handler = handler;
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGUSR1);
    sigaddset(&sa.sa_mask, SIGTERM);
    struct sigaction old;
    sigaction(SIGUSR2, &sa, &old);

    sigaction(SIGUSR2, NULL, &old);

    return 0;
}
EOF
gcc -O0 -o /tmp/mini_strace_test_sigaction /tmp/mini_strace_test_sigaction.c
out=$($STRACE /tmp/mini_strace_test_sigaction 2>&1)
check_contains "rt_sigaction decodes its signal number argument by name" \
    'rt_sigaction\(SIGUSR2,' "$out"
check_contains "rt_sigaction decodes SIG_IGN instead of a raw handler value" \
    'rt_sigaction\(SIGPIPE, \{sa_handler=SIG_IGN' "$out"
check_contains "rt_sigaction decodes a real handler as a hex address" \
    'sa_handler=0x[0-9a-f]+, sa_flags=SA_RESTART' "$out"
check_contains "rt_sigaction decodes the blocked-signal mask by name" \
    'sa_mask=\[SIGUSR1 SIGTERM\]' "$out"
check_contains "rt_sigaction's oldact is NULL when the caller doesn't request it" \
    'rt_sigaction\(SIGPIPE, \{sa_handler=SIG_IGN.*\}, NULL,' "$out"
check_contains "rt_sigaction's deferred oldact decodes the previously-installed handler" \
    'rt_sigaction\(SIGUSR2, NULL, \{sa_handler=0x[0-9a-f]+, sa_flags=SA_RESTART[^,]*, sa_mask=\[SIGUSR1 SIGTERM\]\}' "$out"

echo "=== clock_gettime/clock_settime/nanosleep/clock_nanosleep struct timespec decoding ==="
cat >/tmp/mini_strace_test_timespec.c <<'EOF'
#define _GNU_SOURCE
#include <time.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    struct timespec ts;
    syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &ts);

    struct timespec req = { .tv_sec = 0, .tv_nsec = 1000000 };
    nanosleep(&req, NULL);

    struct timespec req2 = { .tv_sec = 0, .tv_nsec = 500000 };
    struct timespec rem2;
    clock_nanosleep(CLOCK_MONOTONIC, 0, &req2, &rem2);

    struct timespec newtime = { .tv_sec = 12345, .tv_nsec = 6789 };
    clock_settime(CLOCK_REALTIME, &newtime);

    return 0;
}
EOF
gcc -O0 -o /tmp/mini_strace_test_timespec /tmp/mini_strace_test_timespec.c
out=$($STRACE /tmp/mini_strace_test_timespec 2>&1)
check_contains "clock_gettime decodes its clockid and kernel-populated output timespec" \
    'clock_gettime\(CLOCK_MONOTONIC, \{tv_sec=[0-9]+, tv_nsec=[0-9]+\}\)' "$out"
check_contains "nanosleep decodes its requested duration (as nanosleep or clock_nanosleep, architecture-dependent)" \
    '(nanosleep|clock_nanosleep)\(.*tv_nsec=1000000' "$out"
check_contains "clock_nanosleep decodes its clockid, requested duration, and remaining-time output" \
    'clock_nanosleep\(CLOCK_MONOTONIC, 0x0, \{tv_sec=0, tv_nsec=500000\}, \{tv_sec=-?[0-9]+, tv_nsec=-?[0-9]+\}\)' "$out"
check_contains "clock_settime decodes its clockid and requested time" \
    'clock_settime\(CLOCK_REALTIME, \{tv_sec=12345, tv_nsec=6789\}\)' "$out"

echo "=== wait4 struct rusage decoding ==="
cat >/tmp/mini_strace_test_rusage.c <<'EOF'
#define _GNU_SOURCE
#include <sys/wait.h>
#include <sys/resource.h>
#include <unistd.h>

int main(void) {
    pid_t pid = fork();
    if (pid == 0) {
        for (volatile long i = 0; i < 5000000; i++) {}
        _exit(0);
    }
    int status;
    struct rusage ru;
    wait4(pid, &status, 0, &ru);

    struct rusage ru2;
    wait4(-1, &status, 0, &ru2);  /* no children left: ECHILD */

    return 0;
}
EOF
gcc -O0 -o /tmp/mini_strace_test_rusage /tmp/mini_strace_test_rusage.c
out=$($STRACE -f /tmp/mini_strace_test_rusage 2>&1)
check_contains "wait4 decodes ru_utime/ru_stime/ru_maxrss on a successful reap" \
    'wait4\(.*ru_utime=\{tv_sec=[0-9]+, tv_usec=[0-9]+\}, ru_stime=\{tv_sec=[0-9]+, tv_usec=[0-9]+\}, ru_maxrss=[0-9]+\}\)' "$out"
check_contains "wait4's rusage falls back to raw hex when the call fails (no children)" \
    'wait4\([^{]*\) = -10 \(ECHILD\)' "$out"

echo "=== -p attach ==="
sleep 5 &
bgpid=$!
out=$(timeout 2 $STRACE -p "$bgpid" 2>&1)
kill "$bgpid" 2>/dev/null
wait "$bgpid" 2>/dev/null
if echo "$out" | grep -qiE 'operation not permitted|no such process'; then
    skip "ptrace attach shows a syscall from the target" "PTRACE_ATTACH not permitted in this environment"
else
    check_contains "ptrace attach shows a syscall from the target" \
        'nanosleep|clock_nanosleep|restart_syscall' "$out"
fi

echo
echo "=================================="
echo "  $PASS passed, $FAIL failed, $SKIP skipped"
echo "=================================="

[ "$FAIL" -eq 0 ]
