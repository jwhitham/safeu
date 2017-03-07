INCLUDES=-I.
LIBS=-L. -lacrypt -lssl
CFLAGS=-g -Wall -Werror $(INCLUDES)
ICFLAGS=-g $(INCLUDES)
LIBACRYPT=libacrypt.a
LIBTEST=tests/libtest
ACRYPT=acrypt

all: $(LIBACRYPT) $(ACRYPT)

clean:
	rm -f $(LIBACRYPT) *.o tests/libtest.o $(LIBTEST) instr_acrypt $(ACRYPT)

$(LIBACRYPT): acrypt.o
	ar r $(LIBACRYPT) acrypt.o

$(ACRYPT): acrypt_main.o acrypt_files.o $(LIBACRYPT)
	$(CC) -o $(ACRYPT) acrypt_main.o acrypt_files.o $(CFLAGS) $(LIBS)

$(LIBTEST): tests/libtest.o $(LIBACRYPT)
	$(CC) -o $(LIBTEST) tests/libtest.o $(CFLAGS) $(LIBS)

test:
	cd tests; python test.py

