#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include "trace_filter.h"

static const char *file_syscalls[] = {
    "open", "openat", "close", "read", "write", "pread64", "pwrite64",
    "stat", "lstat", "fstat", "newfstatat", "statx", "access",
    "faccessat", "faccessat2", "unlink", "unlinkat", "rename",
    "renameat", "renameat2", "mkdir", "mkdirat", "rmdir", "chdir",
    "chmod", "fchmodat", "chown", "lchown", "fchownat", "truncate",
    "readlink", "readlinkat", "statfs", "lseek", "getcwd", "creat",
    "symlink", "symlinkat", "link", "linkat", "mount", "umount2",
    "chroot", "pivot_root", "utime", "utimes", "futimesat",
    NULL,
};

static const char *network_syscalls[] = {
    "socket", "connect", "accept", "accept4", "bind", "listen",
    "send", "recv", "sendto", "recvfrom", "sendmsg", "recvmsg",
    "setsockopt", "getsockopt", "shutdown", "socketpair",
    "getsockname", "getpeername",
    NULL,
};

static const char *process_syscalls[] = {
    "fork", "vfork", "clone", "clone3", "execve", "execveat", "exit",
    "exit_group", "wait4", "waitid", "kill", "tgkill", "tkill",
    "ptrace", "prctl",
    NULL,
};

static int name_in_list(const char **list, const char *name) {
    for (int i = 0; list[i] != NULL; i++) {
        if (strcmp(list[i], name) == 0)
            return 1;
    }
    return 0;
}

/* The parsed -e trace=SET tokens, filled in once by parse_trace_filter().
 * A NULL filter_tokens means "no filter — trace everything", which is
 * also the state before -e is ever parsed. */
#define MAX_FILTER_TOKENS 16
static char filter_tokens[MAX_FILTER_TOKENS][64];
static int filter_token_count = 0;

void parse_trace_filter(char *set) {
    char *tok = strtok(set, ",");
    while (tok != NULL && filter_token_count < MAX_FILTER_TOKENS) {
        snprintf(filter_tokens[filter_token_count], sizeof(filter_tokens[0]), "%s", tok);
        filter_token_count++;
        tok = strtok(NULL, ",");
    }
}

int syscall_allowed(const char *name) {
    if (filter_token_count == 0)
        return 1;  /* no filter set — trace everything */

    for (int i = 0; i < filter_token_count; i++) {
        const char *tok = filter_tokens[i];
        if (strcmp(tok, "file") == 0 && name_in_list(file_syscalls, name))
            return 1;
        if (strcmp(tok, "network") == 0 && name_in_list(network_syscalls, name))
            return 1;
        if (strcmp(tok, "process") == 0 && name_in_list(process_syscalls, name))
            return 1;
        if (strcmp(tok, name) == 0)  /* exact syscall name */
            return 1;
    }
    return 0;
}
