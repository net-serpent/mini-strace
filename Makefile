CC := gcc
CFLAGS := -Wall -Wextra -O2 -std=gnu11
# One .o per module: arg_routing (syscall+arg lookup tables),
# trace_filter (-e trace=SET), child_mem (ptrace-peek memory reads),
# decoders (raw value -> readable string), and mini_strace itself
# (the tracer loop, arch register access via arch.h, and main()).
SRCS := src/arg_routing.c src/trace_filter.c src/child_mem.c src/decoders.c src/mini_strace.c
OBJS := $(SRCS:.c=.o)
BIN := mini-strace
SYSCALL_TABLE := src/syscall_names.h

.PHONY: all clean run $(SYSCALL_TABLE)

all: $(BIN)

# Regenerated every build: the syscall table is architecture-specific
# (x86-64 and ARM64 use completely different numbering), so it always
# needs to match whatever machine you're building on.
$(SYSCALL_TABLE):
	bash scripts/gen_syscall_table.sh > $(SYSCALL_TABLE)

src/mini_strace.o: src/mini_strace.c $(SYSCALL_TABLE)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $(BIN) $(OBJS)

run: $(BIN)
	./$(BIN) /bin/echo hello world

clean:
	rm -f $(BIN) $(OBJS) $(SYSCALL_TABLE)
