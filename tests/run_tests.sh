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
