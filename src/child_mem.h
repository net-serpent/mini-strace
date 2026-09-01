/*
 * Reading the traced process's memory via PTRACE_PEEKDATA — the
 * classic word-at-a-time way strace has always done this (predates
 * /proc/pid/mem as a read interface, and doesn't depend on /proc
 * being mounted with the right options).
 */
#ifndef MINI_STRACE_CHILD_MEM_H
#define MINI_STRACE_CHILD_MEM_H

#include <sys/types.h>
#include <stddef.h>

/* Physical capacity of the raw read window and the escaped-output
 * buffer for string/buffer arguments — a hard ceiling, not the
 * actual truncation point a user sees day to day. max_str_len (-s
 * SIZE) picks how many raw bytes actually get shown, up to this
 * cap. Also used by mini_strace.c to size the per-argument output
 * buffers it formats every syscall's arguments into. */
#define STR_ARG_BUF_LEN 1024

/* Default -s value: how many raw bytes of a string/buffer argument
 * get read and shown before truncating with "...". Matches the old
 * hardcoded STR_ARG_BUF_LEN so default output is unchanged; -s can
 * raise or lower it, up to STR_ARG_BUF_LEN. Set directly by main()
 * when -s is passed. */
extern size_t max_str_len;

/* Reads a NUL-terminated string out of the traced process's address
 * space. Falls back to printing the raw address as "0x..." if the
 * read fails for any reason (bad pointer, unmapped page, race with
 * the tracee tearing things down, ...) — a failed dereference
 * shouldn't crash the tracer, it should just degrade gracefully. */
void read_child_string(pid_t pid, unsigned long long addr, char *out, size_t out_size);

/* Reads a NULL-terminated array of char* (execve's argv/envp) and
 * renders it as "[\"a\", \"b\", ...]", reusing read_child_string()
 * for each element. */
void read_child_argv(pid_t pid, unsigned long long addr, char *out, size_t out_size);

/* Same idea as read_child_string but for a buffer whose length is
 * known up front (from the syscall's own length argument) instead
 * of being NUL-terminated — the data isn't necessarily text, so
 * this doesn't stop early at a zero byte, it just reads min(len,
 * cap) bytes and escapes all of them. */
void read_child_buffer(pid_t pid, unsigned long long addr, unsigned long long len,
                        char *out, size_t out_size);

/* Same word-at-a-time PTRACE_PEEKDATA loop as read_child_buffer, but
 * returns the raw bytes instead of an escaped string — for callers
 * (format_sockaddr in decoders.c) that need to interpret the bytes
 * as a struct rather than display them as text. Returns the number
 * of bytes actually read, which may be less than want. */
size_t read_child_raw(pid_t pid, unsigned long long addr, unsigned char *buf, size_t want);

#endif /* MINI_STRACE_CHILD_MEM_H */
