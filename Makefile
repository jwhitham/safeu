# SSH Agent File Encryption Utility (safeu)
# Copyright (C) Jack Whitham 2016-2017
# 
# https://github.com/jwhitham/safeu/
# https://www.jwhitham.org/
# 
# ex: set tabstop=4 noexpandtab shiftwidth=4:
#

INCLUDES=-I.
LIBS=-L. -lsafeu -lssl
CFLAGS=-g -Wall -Werror -O2 $(INCLUDES)
ICFLAGS=-g $(INCLUDES)
LIBSAFEU=libsafeu.a
LIBTEST=tests/libtest
SAFEU=safeu

all: $(LIBSAFEU) $(SAFEU)

clean:
	rm -f $(LIBSAFEU) *.o tests/libtest.o $(LIBTEST) $(SAFEU)

$(LIBSAFEU): libsafeu.o
	ar r $(LIBSAFEU) libsafeu.o

$(SAFEU): main.o files.o $(LIBSAFEU)
	$(CC) -o $(SAFEU) main.o files.o $(CFLAGS) $(LIBS)

$(LIBTEST): tests/libtest.o $(LIBSAFEU)
	$(CC) -o $(LIBTEST) tests/libtest.o $(CFLAGS) $(LIBS)

test:
	cd tests; python test.py

