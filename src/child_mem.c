#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/ptrace.h>

#include "child_mem.h"

size_t max_str_len = 200;

void read_child_string(pid_t pid, unsigned long long addr, char *out, size_t out_size) {
    if (addr == 0) {
        snprintf(out, out_size, "NULL");
        return;
    }

    unsigned char raw[STR_ARG_BUF_LEN];
    /* PTRACE_PEEKDATA only ever reads whole words, so the read window
     * has to round max_str_len up to a word boundary — otherwise a
     * -s value smaller than sizeof(long) would make the loop below
     * exit before reading anything at all. The actual *displayed*
     * length still gets clamped to max_str_len afterward. */
    size_t read_cap = ((max_str_len + sizeof(long) - 1) / sizeof(long)) * sizeof(long);
    if (read_cap > sizeof(raw))
        read_cap = sizeof(raw);
    size_t got = 0;

    while (got + sizeof(long) <= read_cap) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + got), NULL);
        if (word == -1 && errno != 0)
            break;  /* unmapped/invalid address — stop, use what we have */

        memcpy(raw + got, &word, sizeof(long));
        got += sizeof(long);

        int has_nul = 0;
        for (size_t i = 0; i < sizeof(long); i++) {
            if (((unsigned char *)&word)[i] == '\0') { has_nul = 1; break; }
        }
        if (has_nul)
            break;
    }

    if (got == 0) {
        snprintf(out, out_size, "0x%llx", addr);
        return;
    }

    size_t len = 0;
    while (len < got && raw[len] != '\0')
        len++;
    int truncated = (len == got);  /* string may continue past our read window */
    if (len > max_str_len) {
        len = max_str_len;  /* -s truncation, even though a NUL exists further in */
        truncated = 1;
    }

    size_t oi = 0;
    if (oi < out_size) out[oi++] = '"';
    for (size_t i = 0; i < len && oi + 5 < out_size; i++) {
        unsigned char c = raw[i];
        if (c == '"' || c == '\\') {
            out[oi++] = '\\';
            out[oi++] = (char)c;
        } else if (c == '\n') {
            out[oi++] = '\\'; out[oi++] = 'n';
        } else if (c >= 0x20 && c < 0x7f) {
            out[oi++] = (char)c;
        } else {
            oi += (size_t)snprintf(out + oi, out_size - oi, "\\x%02x", c);
        }
    }
    if (oi < out_size) out[oi++] = '"';
    if (truncated && oi + 3 < out_size) {
        memcpy(out + oi, "...", 3);
        oi += 3;
    }
    if (oi < out_size) out[oi] = '\0';
    else out[out_size - 1] = '\0';
}

/* Max entries read out of an argv[]/envp[] array before giving up
 * and marking it truncated — bounds both the ptrace call count and
 * the output line length for processes with huge environments. */
#define MAX_ARGV_ITEMS 32

void read_child_argv(pid_t pid, unsigned long long addr, char *out, size_t out_size) {
    if (addr == 0) {
        snprintf(out, out_size, "NULL");
        return;
    }

    size_t oi = 0;
    if (oi < out_size) out[oi++] = '[';

    int count = 0;
    int truncated = 0;
    for (; count < MAX_ARGV_ITEMS; count++) {
        errno = 0;
        long ptr = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + (unsigned long long)count * sizeof(long)), NULL);
        if (ptr == -1 && errno != 0)
            break;  /* unmapped/invalid address — stop, use what we have */
        if (ptr == 0)
            break;  /* NULL terminator — normal end of the array */

        char item[STR_ARG_BUF_LEN];
        read_child_string(pid, (unsigned long long)ptr, item, sizeof(item));

        if (count > 0 && oi + 2 < out_size) {
            out[oi++] = ',';
            out[oi++] = ' ';
        }
        size_t item_len = strlen(item);
        if (oi + item_len < out_size) {
            memcpy(out + oi, item, item_len);
            oi += item_len;
        }

        if (count == MAX_ARGV_ITEMS - 1)
            truncated = 1;  /* hit our cap with a real (non-NULL) entry — array may continue past it */
    }

    if (truncated && oi + 5 < out_size) {
        memcpy(out + oi, ", ...", 5);
        oi += 5;
    }

    if (oi < out_size) out[oi++] = ']';
    if (oi < out_size) out[oi] = '\0';
    else out[out_size - 1] = '\0';
}

void read_child_buffer(pid_t pid, unsigned long long addr, unsigned long long len,
                        char *out, size_t out_size) {
    if (addr == 0) {
        snprintf(out, out_size, "NULL");
        return;
    }

    size_t cap = (max_str_len < STR_ARG_BUF_LEN) ? max_str_len : STR_ARG_BUF_LEN;
    size_t want = (len < cap) ? (size_t)len : cap;
    unsigned char raw[STR_ARG_BUF_LEN];
    size_t got = 0;

    while (got < want) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + got), NULL);
        if (word == -1 && errno != 0)
            break;  /* unmapped/invalid address — stop, use what we have */

        size_t chunk = (want - got < sizeof(long)) ? (want - got) : sizeof(long);
        memcpy(raw + got, &word, chunk);
        got += chunk;
    }

    if (got == 0) {
        snprintf(out, out_size, "0x%llx", addr);
        return;
    }

    size_t oi = 0;
    if (oi < out_size) out[oi++] = '"';
    for (size_t i = 0; i < got && oi + 5 < out_size; i++) {
        unsigned char c = raw[i];
        if (c == '"' || c == '\\') {
            out[oi++] = '\\';
            out[oi++] = (char)c;
        } else if (c == '\n') {
            out[oi++] = '\\'; out[oi++] = 'n';
        } else if (c >= 0x20 && c < 0x7f) {
            out[oi++] = (char)c;
        } else {
            oi += (size_t)snprintf(out + oi, out_size - oi, "\\x%02x", c);
        }
    }
    if (oi < out_size) out[oi++] = '"';
    if (len > got && oi + 3 < out_size) {  /* real buffer is longer than what we dumped */
        memcpy(out + oi, "...", 3);
        oi += 3;
    }
    if (oi < out_size) out[oi] = '\0';
    else out[out_size - 1] = '\0';
}

size_t read_child_raw(pid_t pid, unsigned long long addr, unsigned char *buf, size_t want) {
    size_t got = 0;
    while (got < want) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + got), NULL);
        if (word == -1 && errno != 0)
            break;  /* unmapped/invalid address — stop, use what we have */

        size_t chunk = (want - got < sizeof(long)) ? (want - got) : sizeof(long);
        memcpy(buf + got, &word, chunk);
        got += chunk;
    }
    return got;
}
