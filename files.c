/* SSH Agent File Encryption Utility (safeu)
 * Copyright (C) Jack Whitham 2016-2017
 * 
 * https://github.com/jwhitham/safeu/
 * https://www.jwhitham.org/
 * 
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <openssl/rand.h>

#include "libsafeu.h"
#include "files.h"

#define MAX_PASSWORD_SIZE	(256 - 64) 
#define AC					"safeu: "



static int read_file (const char * src_fname, char ** file_in_data, unsigned * file_in_size)
{
	FILE * fd = NULL;
	size_t size = 0;

	fd = fopen (src_fname, "rb");
	(* file_in_data) = NULL;
	if (!fd) {
		perror (AC "unable to open input file");
		goto error;
	}
	fseek (fd, 0, SEEK_END);
	size = ftell (fd);
	if (size > (1 << 30)) {
		perror (AC "input file is too large");
		goto error;
	}
	(* file_in_size) = size;
	(* file_in_data) = malloc (size);
	if ((* file_in_data) == NULL) {
		perror (AC "unable to allocate memory for input file");
		goto error;
	}
	fseek (fd, 0, SEEK_SET);
	if (size != 0) {
		if (fread ((* file_in_data), size, 1, fd) != 1) {
			perror (AC "unable to read data from input file");
			goto error;
		}
	}
	fclose (fd);
	return 1;

error:
	if (fd) {
		fclose (fd);
	}
	free ((* file_in_data));
	(* file_in_data) = NULL;
	(* file_in_size) = 0;
	return 0;
}

static int write_file (const char * dest_fname, const char * file_out_data, unsigned file_out_size)
{
	FILE * fd = NULL;

	fd = fopen (dest_fname, "wb");
	if (!fd) {
		perror (AC "unable to open output file");
		goto error;
	}
	if (file_out_size != 0) {
		if (fwrite (file_out_data, file_out_size, 1, fd) != 1) {
			perror (AC "unable to write data to output file");
			goto error;
		}
	}
	fclose (fd);
	return 1;

error:
	if (fd) {
		fclose (fd);
	}
	return 0;
}


int safeu_encrypt_a_file (struct t_safeu_struct * ac,
							const char * src_fname, const char * dest_fname)
{
	int ok = 1;
	char * file_in_data = NULL;
	char * file_out_data = NULL;
	unsigned file_in_size = 0;
	unsigned file_out_size = 0;

	ok = ok && read_file (src_fname, &file_in_data, &file_in_size);
	ok = ok && safeu_encrypt_block (ac, file_in_data, file_in_size, &file_out_data, &file_out_size);
	ok = ok && write_file (dest_fname, file_out_data, file_out_size);
	free (file_in_data);
	free (file_out_data);
	return ok;
}

int safeu_decrypt_a_file (struct t_safeu_struct * ac,
							const char * src_fname, const char * dest_fname)
{
	int ok = 1;
	char * file_in_data = NULL;
	char * file_out_data = NULL;
	unsigned file_in_size = 0;
	unsigned file_out_size = 0;

	ok = ok && read_file (src_fname, &file_in_data, &file_in_size);
	ok = ok && safeu_decrypt_block (ac, file_in_data, file_in_size, &file_out_data, &file_out_size);
	ok = ok && write_file (dest_fname, file_out_data, file_out_size);
	free (file_in_data);
	free (file_out_data);
	return ok;
}

static unsigned get_number_of_identities (struct t_safeu_struct * ac)
{
	unsigned i;
	for (i = 0; safeu_get_fingerprint (ac, i); i++) {}
	return i;
}

static void test_file_encryption (struct t_safeu_struct * ac, uint64_t size)
{
	const char * test1 = "test1.tmp";
	const char * test2 = "test2.tmp";
	const char * test3 = "test3.tmp";
	char * plaintext = calloc (1, size + 1);
	char * check = NULL;
	unsigned check_size = 0;

	printf ("test file with size %d: %d %d\n", 
				(int) size, (int) size % CIPHER_BLOCK_SIZE,
				(int) size - FILE_BLOCK_SIZE);
	if (!plaintext) {
		abort ();
	}

	RAND_bytes ((uint8_t *) plaintext, size);

	if (!write_file (test1, plaintext, size)) {
		abort ();
	}

	if (!safeu_encrypt_a_file (ac, test1, test2)) {
		abort ();
	}
	if (!safeu_decrypt_a_file (ac, test2, test3)) {
		abort ();
	}
	if (!read_file (test3, &check, &check_size)) {
		abort ();
	}
	if (check_size != size) {
		fputs (AC "readback size error\n", stderr);
		abort ();
	}
	if (memcmp (check, plaintext, size) != 0) {
		fputs (AC "readback data error\n", stderr);
		abort ();
	}
	free (plaintext);
	free (check);

	unlink (test1);
	unlink (test2);
	unlink (test3);
}

void safeu_files_test (struct t_safeu_struct * ac)
{
	uint32_t i;

	if (get_number_of_identities (ac) == 0) {
		fputs (AC "no identities: cannot run tests\n", stderr);
		abort ();
	}
	for (i = 0; i < (CIPHER_BLOCK_SIZE + 2); i++) {
		test_file_encryption (ac, i);
	}
	for (i = 0; i < (CIPHER_BLOCK_SIZE + 2); i++) {
		test_file_encryption (ac, i + (FILE_BLOCK_SIZE / 2) - 1);
	}
	for (i = 0; i < ((CIPHER_BLOCK_SIZE + 2) * 2); i++) {
		test_file_encryption (ac, FILE_BLOCK_SIZE + i - CIPHER_BLOCK_SIZE);
	}
	for (i = 0; i < 3; i++) {
		test_file_encryption (ac, FILE_BLOCK_SIZE * 2 + i - 1);
	}
}

/* ex: set tabstop=4 noexpandtab shiftwidth=4: */
