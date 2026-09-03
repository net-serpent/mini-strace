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

# Property tests for the pure format_* decoders (decoders.c) — no
# ptrace, no traced process needed, so this builds as its own small
# binary straight from source rather than reusing $(OBJS), with
# ASan/UBSan enabled to actually catch an out-of-bounds write instead
# of just hoping one doesn't happen to corrupt something visible.
# See tests/property_test_decoders.c for what's actually checked.
PROPERTY_TEST_BIN := tests/property_test_decoders
PROPERTY_TEST_SRCS := tests/property_test_decoders.c src/decoders.c src/child_mem.c

.PHONY: property-test

property-test: $(PROPERTY_TEST_BIN)
	./$(PROPERTY_TEST_BIN)

$(PROPERTY_TEST_BIN): $(PROPERTY_TEST_SRCS) $(wildcard src/*.h)
	$(CC) -Wall -Wextra -O1 -g -fsanitize=address,undefined -std=gnu11 \
		-o $(PROPERTY_TEST_BIN) $(PROPERTY_TEST_SRCS)

clean:
	rm -f $(BIN) $(OBJS) $(SYSCALL_TABLE) $(PROPERTY_TEST_BIN)
