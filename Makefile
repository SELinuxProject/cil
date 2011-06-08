PREFIX ?= $(DESTDIR)/usr
LIBDIR ?= $(PREFIX)/lib
SHLIBDIR ?= $(DESTDIR)/lib
INCLUDEDIR ?= $(PREFIX)/include
SRCDIR ?= ./src
TESTDIR ?= ./testing
UNITDIR ?= $(TESTDIR)/unit

LEX = flex

DEBUG=1

AST_NAME = ast
PARSER_NAME = parser

AST_TEST = $(TESTDIR)/test_ast.c
PARSER_TEST = $(TESTDIR)/test_parser.c
TEST_SRCS = $(wildcard $(UNITDIR)/*.c)
CIL_SRCS =  cil.c cil_tree.c cil_ast.c cil_parser.c cil_symtab.c cil_lexer.c

GENERATED = cil_lexer.c

ALL_SRCS= $(wildcard $(SRCDIR)/*.c) $(SRCDIR)/$(GENERATED)
ALL_OBJS= $(patsubst %.c,%.o,$(ALL_SRCS))


LIBSEPOL_STATIC = /usr/lib/libsepol.a

LIBS = 
LDFLAGS = -lfl
COVCFLAGS = -fprofile-arcs -ftest-coverage

CFLAGS ?= -Wall -Werror -Wshadow -W -Wundef -Wmissing-format-attribute

ifeq ($(DEBUG),1)
	override CFLAGS += -g3 -O0 -gdwarf-2 -fno-strict-aliasing
	override LDFLAGS += -g
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

all: cil

cil: parser ast

cil_lexer.c: cil_lexer.l
	$(LEX) -t $< > $@

ast: $(AST_TEST) $(ALL_SRCS)
	$(CC) $(CFLAGS) -o $(AST_NAME) $^ $(LIBSEPOL_STATIC) $(LDFLAGS) 

parser: $(PARSER_TEST) $(ALL_SRCS)
	$(CC) $(CFLAGS) -o $(PARSER_NAME) $^ $(LIBSEPOL_STATIC) $(LDFLAGS)

unit: $(TEST_SRCS) $(ALL_SRCS)
	$(CC) $(CFLAGS) $(COVCFLAGS) $^ $(LIBSEPOL_STATIC) $(LDFLAGS) -o unit_tests

# Requires lcov 1.9+ (--ignore-errors)
coverage: clean unit
	./unit_tests
	test -d cov || mkdir cov
	export GCOV_PREFIX_STRIP=1
	lcov --directory . --capture --output-file cov/app.info --ignore-errors source
	genhtml -o ./cov/html ./cov/app.info

test: ast
	./ast testing/test.txt

install:

clean: 
	-rm -f $(SRCDIR)/$(ALL_OBJS) $(SRCDIR)/$(GENERATED) run_tests
	-rm -f *.gcno *.gcda *.gcov unit_tests policy.conf
	-rm -f $(PARSER_NAME) $(AST_NAME)
	-rm -rf cov/

bare: clean
	-rm -f $(AST_NAME) $(PARSER_NAME)

.PHONY: cil all clean install bare test
