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

LIBCIL_STATIC = $(SRCDIR)/libcil.a

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

override CFLAGS += -I./include -I$(INCLUDEDIR) -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64

ARCH := $(patsubst i%86,i386,$(shell uname -m))
ifneq (,$(filter i386,$(ARCH)))
	TLSFLAGS += -mno-tls-direct-seg-refs
endif
ifneq (,$(filter x86_64,$(ARCH)))
	override LDFLAGS += -I/usr/lib64
endif

all: $(SECILC)

%.o:  %.c %.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIBCIL_STATIC):
	make -C src/ CFLAGS="$(CFLAGS)" libcil.a

$(UNIT): $(TEST_OBJS) $(LIBCIL_STATIC)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBCIL_STATIC) $(LIBSEPOL_STATIC) $(LDFLAGS)

$(SECILC): $(SECILC_OBJS) $(LIBCIL_STATIC)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBCIL_STATIC) $(LIBSEPOL_STATIC) $(LDFLAGS)

unit: $(SECILC) $(UNIT)

# Requires lcov 1.9+ (--ignore-errors)
coverage: CFLAGS += $(COVCFLAGS)
coverage: clean unit
	./unit_tests
	test -d cov || mkdir cov
	lcov --directory src --capture --output-file cov/app.info --ignore-errors source -b src
	lcov --remove cov/app.info '/usr/include/*' --remove cov/app.info 'sepol/*' --output-file cov/app.info
	genhtml -o ./cov/html ./cov/app.info

test: $(SECILC)
	./$(SECILC) test/policy.cil

clean:
	-rm -f $(TEST_OBJS) $(SECILC_OBJS)
	-rm -rf cov src/*.gcda src/*.gcno *.gcda *.gcno
	make -C src clean

bare: clean
	rm -f $(SECILC)
	rm -f $(UNIT)
	rm -f policy.*
	rm -f file_contexts

.PHONY: all bare clean coverage test unit
