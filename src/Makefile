PREFIX ?= $(DESTDIR)/usr
LIBDIR ?= $(PREFIX)/lib
SHLIBDIR ?= $(DESTDIR)/lib
INCLUDEDIR ?= $(PREFIX)/include

LEX = flex

DEBUG=0

GENERATED = cil_lexer.c

CIL_LIBA=libcil.a 
CIL_SRCS= $(wildcard *.c) $(GENERATED)
CIL_OBJS= $(patsubst %.c,%.o,$(CIL_SRCS))

LIBSEPOL_STATIC = /usr/lib/libsepol.a

LIBS =
LDFLAGS =
COVCFLAGS = -fprofile-arcs -ftest-coverage -O0

CFLAGS ?= -Wall -Werror -Wshadow -Wextra -Wundef -Wmissing-format-attribute -Wcast-align -Wstrict-prototypes -Wpointer-arith -Wunused
override CFLAGS += -I. -I../include -D_GNU_SOURCE

ifeq ($(DEBUG),1)
	override CFLAGS += -g3 -O0 -gdwarf-2 -fno-strict-aliasing -DDEBUG
	override LDFLAGS += -g
else
	override CFLAGS += -O2
endif

override CFLAGS += -I $(LIBSEPOL_INCLUDE) -I$(INCLUDEDIR) -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64

ARCH := $(patsubst i%86,i386,$(shell uname -m))
ifneq (,$(filter i386,$(ARCH)))
	TLSFLAGS += -mno-tls-direct-seg-refs
endif
ifneq (,$(filter x86_64,$(ARCH)))
	override LDFLAGS += -I/usr/lib64
	override LIBSEPOL_STATIC = /usr/lib64/libsepol.a
endif

$(CIL_LIBA):  $(CIL_OBJS)
	$(AR) rcs $@ $^
	ranlib $@

cil_lexer.c: cil_lexer.l
	$(LEX) -t $< > $@

%.o:  %.c %.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	-rm -f $(CIL_OBJS) $(GENERATED)
	-rm -f $(CIL_LIBA)

.PHONY: clean
