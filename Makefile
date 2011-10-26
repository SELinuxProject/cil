PREFIX ?= $(DESTDIR)/usr
LIBDIR ?= $(PREFIX)/lib
SHLIBDIR ?= $(DESTDIR)/lib
INCLUDEDIR ?= $(PREFIX)/include
SRCDIR ?= ./src
TESTDIR ?= ./test
UNITDIR ?= $(TESTDIR)/unit

LEX = flex

DEBUG=0

SECILC = secilc

UNIT = unit_tests

SECILC_SRCS = secilc.c
SECILC_OBJS = $(patsubst %.c,%.o,$(SECILC_SRCS))

TEST_SRCS = $(wildcard $(UNITDIR)/*.c)
TEST_OBJS = $(patsubst %.c,%.o,$(TEST_SRCS))

GENERATED = cil_lexer.c

CIL_SRCS= $(wildcard $(SRCDIR)/*.c) $(SRCDIR)/$(GENERATED)
CIL_OBJS= $(patsubst %.c,%.o,$(CIL_SRCS))


LIBSEPOL_STATIC = /usr/lib/libsepol.a

LIBS =
LDFLAGS =
COVCFLAGS = -fprofile-arcs -ftest-coverage -O0

CFLAGS ?= -Wall -Werror -Wshadow -Wextra -Wundef -Wmissing-format-attribute -Wcast-align -Wstrict-prototypes -Wpointer-arith -Wunused

ifeq ($(DEBUG),1)
	override CFLAGS += -g3 -O0 -gdwarf-2 -fno-strict-aliasing -DDEBUG
	override LDFLAGS += -g
else
	override CFLAGS += -O2
endif

override CFLAGS += -I$(INCLUDEDIR) -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64

ARCH := $(patsubst i%86,i386,$(shell uname -m))
ifneq (,$(filter i386,$(ARCH)))
	TLSFLAGS += -mno-tls-direct-seg-refs
endif
ifneq (,$(filter x86_64,$(ARCH)))
	override LDFLAGS += -I/usr/lib64
	override LIBSEPOL_STATIC = /usr/lib64/libsepol.a
endif

all: $(SECILC)

cil_lexer.c: cil_lexer.l
	$(LEX) -t $< > $@

%.o:  %.c %.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(UNIT): $(TEST_OBJS) $(CIL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBSEPOL_STATIC) $(LDFLAGS)

$(SECILC): $(SECILC_OBJS) $(CIL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBSEPOL_STATIC) $(LDFLAGS)

unit: $(SECILC) $(UNIT)

# Requires lcov 1.9+ (--ignore-errors)
coverage: CFLAGS += $(COVCFLAGS)
coverage: clean unit
	./unit_tests
	test -d cov || mkdir cov
	export GCOV_PREFIX_STRIP=1
	lcov --directory . --capture --output-file cov/app.info --ignore-errors source -b .
	lcov --remove cov/app.info 'test/unit/*' --remove cov/app.info '/usr/include/*' --output-file cov/app.info
	genhtml -o ./cov/html ./cov/app.info

test: $(SECILC)
	./$(SECILC) test/policy.cil

clean:
	-rm -f $(CIL_OBJS) $(TEST_OBJS) $(SECILC_OBJS) $(SRCDIR)/$(GENERATED)
	-rm -rf $(patsubst %.o,%.gcda,$(CIL_OBJS) $(SECILC_OBJS) $(TEST_OBJS))
	-rm -rf $(patsubst %.o,%.gcno,$(CIL_OBJS) $(SECILC_OBJS) $(TEST_OBJS))
	-rm -rf cov/

bare: clean
	rm -f $(SECILC)
	rm -f $(UNIT)
	rm -f policy.*
	rm -f file_contexts

.PHONY: all bare clean coverage test unit
