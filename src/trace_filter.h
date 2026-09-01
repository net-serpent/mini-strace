/*
 * -e trace=SET filtering. SET is a comma-separated list where each
 * token is either a category name (file/network/process) or an
 * exact syscall name — same idea as real strace's -e trace, just
 * with three hardcoded categories instead of a full syscall
 * classification. Not exhaustive, covers the common ones.
 */
#ifndef MINI_STRACE_TRACE_FILTER_H
#define MINI_STRACE_TRACE_FILTER_H

/* Parses -e trace=SET's comma-separated token list into the
 * module's internal filter state. set is modified in place (via
 * strtok), matching how the caller already treats it as scratch
 * space (it's a copy of the command-line argument, not the argv
 * pointer itself). Call once, before tracing starts. */
void parse_trace_filter(char *set);

/* Whether a syscall should be printed given whatever filter (if any)
 * parse_trace_filter() last set up. Returns 1 (allowed) whenever no
 * -e trace=SET was given at all. */
int syscall_allowed(const char *name);

#endif /* MINI_STRACE_TRACE_FILTER_H */
