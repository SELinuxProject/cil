PREFIX ?= $(DESTDIR)/usr
LIBDIR ?= $(PREFIX)/lib
SHLIBDIR ?= $(DESTDIR)/lib
INCLUDEDIR ?= $(PREFIX)/include

LEX = flex

AST_NAME = ast
PARSER_NAME = parser

AST_SRCS = test_ast.c cil.c cil_tree.c cil_ast.c cil_parser.c cil_lexer.c cil_symtab.c
PARSER_SRCS = test_parser.c cil.c cil_tree.c cil_ast.c cil_parser.c cil_lexer.c cil_symtab.c

GENERATED = cil_lexer.c

ALL_SRCS= $(wildcard *.c) $(GENERATED)
ALL_OBJS= $(patsubst %.c,%.o,$(ALL_SRCS))

LIBSEPOL_STATIC = /usr/lib/libsepol.a

LIBS = 
LDFLAGS = -lfl

ifeq ($(DEBUG),1)
	export CFLAGS = -g3 -O0 -gdwarf-2 -fno-strict-aliasing -Wall -Wshadow -Werror
	export LDFLAGS = -g
endif

CFLAGS ?= -Wall -W -Wundef -Wshadow -Wmissing-noreturn -Wmissing-format-attribute $(LIBS)
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

ast: $(AST_SRCS)
	$(CC) $(CFLAGS) -o $(AST_NAME) $^ $(LIBSEPOL_STATIC) $(LDFLAGS) 

parser: $(PARSER_SRCS)
	$(CC) $(CFLAGS) -o $(PARSER_NAME) $^ $(LIBSEPOL_STATIC) $(LDFLAGS)

test: ast parser
	./ast test.txt

install:

clean: 
	-rm -f $(OBJS) $(GENERATED)

bare: clean
	-rm -f $(AST_NAME) $(PARSER_NAME)

.PHONY: cil all clean install bare
