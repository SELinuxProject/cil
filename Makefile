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

SECILC_SRC = secilc.c
TEST_SRCS = $(wildcard $(UNITDIR)/*.c)
CIL_SRCS =  secil.c cil_tree.c cil_ast.c cil_parser.c cil_symtab.c cil_lexer.c

GENERATED = cil_lexer.c

ALL_SRCS= $(wildcard $(SRCDIR)/*.c) $(SRCDIR)/$(GENERATED)
ALL_OBJS= $(patsubst %.c,%.o,$(ALL_SRCS))


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

$(UNIT): $(TEST_SRCS) $(ALL_SRCS)
	$(CC) $(CFLAGS) $(COVCFLAGS) $^ $(LIBSEPOL_STATIC) $(LDFLAGS) -o unit_tests

$(SECILC): $(SECILC_SRC) $(ALL_SRCS)
	$(CC) $(CFLAGS) -o $(SECILC) $^ $(LIBSEPOL_STATIC) $(LDFLAGS)

unit: $(SECILC) $(UNIT)

# Requires lcov 1.9+ (--ignore-errors)
coverage: clean unit
	./unit_tests
	test -d cov || mkdir cov
	export GCOV_PREFIX_STRIP=1
	lcov --directory . --capture --output-file cov/app.info --ignore-errors source
	lcov --remove cov/app.info 'test/unit/*' --output-file cov/app.info
	genhtml -o ./cov/html ./cov/app.info

test: $(SECILC)
	./$(SECILC) test/policy.cil

install:

clean: 
	-rm -f $(SRCDIR)/$(ALL_OBJS) $(SRCDIR)/$(GENERATED) run_tests
	-rm -f *.gcno *.gcda *.gcov unit_tests policy.* file_contexts
	-rm -f $(SECILC)
	-rm -rf cov/

bare: clean
	-rm -f $(SECILC)

.PHONY: cil all clean install bare test
