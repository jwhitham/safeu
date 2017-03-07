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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <dirent.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "libsafeu.h"
#include "ssh.h"

#define MAX_STRING_SIZE		(1 << 16)
#define HEADER_FILE_ID_DWORD	0x31337
#define HEADER_PWD_ID_DWORD		0xe1ee7
#define HEADER_BLOCK_ID_DWORD	0xe1337
#define FP_BUF_SIZE			(256)
#define VERSION_DWORD		2
#ifdef COVERAGE_TEST
#define MAX_IDENTITIES		4
#else
#define MAX_IDENTITIES		(1 << 12)
#endif
#define AC					"safeu: "

typedef struct t_string_struct {
	uint32_t	size;
	uint8_t		text[1];
} t_string;

typedef struct t_identity_struct {
	t_string * key_data;
	t_string * key_type;
	t_string * comment;
	t_string * fingerprint;
} t_identity;

typedef struct t_header_v1_struct {
	uint32_t		id;					/* 0 */
	uint16_t		version;			/* 4 */
	uint16_t		unused;				/* 6 */
	uint64_t		size;				/* 8 */
	uint8_t  		key_data_hash[8];	/* 16 */
	uint8_t  		plaintext_hash[8];	/* 24 */
	uint8_t  		salt[16];			/* 32 */
										/* 48 */
} t_header_v1;

typedef struct t_header_v2_struct {
	uint32_t		id;					/* 0 */
	uint16_t		version;			/* 4 */
	uint16_t		number_of_keys;		/* 6 */
	uint64_t		size;				/* 8 */
	uint8_t  		salt[16];			/* 16 */
	uint8_t  		plaintext_hash[8];	/* 32 */
										/* 40 */
} t_header_v2;

typedef struct t_key_header_struct {
	uint8_t  		key_data_hash[8];	/* 0 */
	uint8_t			key[CIPHER_KEY_SIZE]; /* 8 */
	uint8_t			iv[CIPHER_BLOCK_SIZE]; /* 24 */
} t_key_header;


typedef struct t_safeu_struct {
	/* connection to agent */
	int socket_handle;
	uint32_t number_of_identities;
	t_identity * identities;
	t_string * agent_socket_name;
	int socket_error_flag;

	/* input buffer */
	uint64_t position_in;
	uint64_t block_in_size;
	const uint8_t * block_in;

	/* output buffer */
	uint64_t position_out;
	uint64_t block_out_size;
	uint8_t * block_out;
} t_safeu;

static uint64_t block_get_fsize_and_rewind (t_safeu * ac);
static uint64_t block_read_input (t_safeu * ac, void * data, uint64_t max_size);
static int block_write_output (t_safeu * ac, const void * data, uint64_t size);

static void send_data (t_safeu * ac, const void * data, uint32_t size)
{
	if (ac->socket_error_flag) {
		return;
	}
	if (write (ac->socket_handle, data, size) != size) {
		ac->socket_error_flag = 1;
		perror (AC "send_data failed");
	}
}

static void send_int (t_safeu * ac, uint32_t v)
{
	v = htonl (v);
	send_data (ac, &v, 4);
}

static void send_byte (t_safeu * ac, uint8_t v)
{
	send_data (ac, &v, 1);
}

static void send_string (t_safeu * ac, const t_string * v)
{
	send_int (ac, v->size);
	send_data (ac, v->text, v->size);
}

static void receive_data (t_safeu * ac, void * data, uint32_t size)
{
	if (ac->socket_error_flag) {
		memset (data, 0, size);
		return;
	}
	if (read (ac->socket_handle, data, size) != size) {
		ac->socket_error_flag = 1;
		memset (data, 0, size);
		perror (AC "receive_data failed");
	}
}

static uint32_t receive_int (t_safeu * ac)
{
	uint32_t v = 0;
	receive_data (ac, &v, 4);
	return ntohl (v);
}

static uint8_t receive_byte (t_safeu * ac)
{
	uint8_t v = 0;
	receive_data (ac, &v, 1);
	return v;
}

static void openssl_error (const char * function)
{
	fputs (AC "openssl error: ", stderr);
	fputs (function, stderr);
	fputs (" " , stderr);
	ERR_print_errors_fp (stderr);
	fputs ("\n", stderr);
	fflush (stderr);
}

static void malloc_error (void)
{
	fputs (AC "unable to allocate memory\n", stderr);
}

static t_string * new_string (uint32_t size)
{
	t_string * block = calloc (1, size + sizeof (t_string));
	if (block == NULL) {
		malloc_error ();
		return NULL;
	}
	block->size = size;
	return block;
}

static void free_string (t_string * data)
{
	free (data);
}

/* static void print_string (t_string * data)
{
	uint32_t i;

	for (i = 0; i < data->size; i++) {
		if (isprint (data->text[i])) {
			fputc (data->text[i], stdout);
		} else {
			printf ("\\x%02x", (uint8_t) data->text[i]);
		}
	}
} */

static t_string * receive_string (t_safeu * ac)
{
	uint32_t size = receive_int (ac);
	t_string * block = NULL;

	if (size >= MAX_STRING_SIZE) {
		fputs (AC "receive_string: size overflow", stderr);
		return NULL;
	}

	block = new_string (size);
	receive_data (ac, block->text, size);
	return block;
}
			
static t_string * split_string (t_string * source, uint32_t * p_start_of_part_2)
{
	t_string * part_1;

	if (source->size <= 4) {
		fputs (AC "string too small for split\n", stderr);
		return NULL;
	}

	memcpy (p_start_of_part_2, &source->text[0], 4);
	(*p_start_of_part_2) = ntohl ((*p_start_of_part_2));
	if ((*p_start_of_part_2) > (source->size - 4)) {
		fputs (AC "string split word is not valid\n", stderr);
		return NULL;
	}

	part_1 = calloc (1, (*p_start_of_part_2) + sizeof (t_string));
	if (part_1 == NULL) {
		malloc_error ();
		return NULL;
	}
	part_1->size = (*p_start_of_part_2);
	memcpy (part_1->text, &source->text[4], (*p_start_of_part_2));
	return part_1;

}

static int compute_sha512_hash (const uint8_t * data1, unsigned data1_size,
								const uint8_t * data2, unsigned data2_size,
								uint8_t * output)
{
	EVP_MD_CTX * mdctx;
	unsigned hash_size;

	mdctx = EVP_MD_CTX_create ();
	hash_size = SHA512_SIZE;
	if ((mdctx)
	&& (1 == EVP_DigestInit_ex (mdctx, EVP_sha512 (), NULL))
	&& (1 == EVP_DigestUpdate (mdctx, data1, data1_size))
	&& (1 == EVP_DigestUpdate (mdctx, data2, data2_size))
	&& (1 == EVP_DigestFinal_ex (mdctx, output, &hash_size))
	&& (hash_size == SHA512_SIZE)) {
		/* sha512 success */
		EVP_MD_CTX_destroy (mdctx);
		return 1;
	} else {
		/* failure */
		openssl_error ("EVP_DigestInit_ex sha512");
		EVP_MD_CTX_destroy (mdctx);
		return 0;
	}
}

static int compute_md5_hash (const uint8_t * data1, unsigned data1_size, uint8_t * output)
{
	EVP_MD_CTX * mdctx;
	unsigned hash_size;

	mdctx = EVP_MD_CTX_create ();
	hash_size = MD5_SIZE;
	if ((mdctx)
	&& (1 == EVP_DigestInit_ex (mdctx, EVP_md5 (), NULL))
	&& (1 == EVP_DigestUpdate (mdctx, data1, data1_size))
	&& (1 == EVP_DigestFinal_ex (mdctx, output, &hash_size))
	&& (hash_size == MD5_SIZE)) {
		/* md5 success */
		EVP_MD_CTX_destroy (mdctx);
		return 1;
	} else {
		/* failure */
		openssl_error ("EVP_DigestInit_ex md5");
		EVP_MD_CTX_destroy (mdctx);
		return 0;
	}
}

static void ctr_encrypt (const uint8_t * src, uint8_t * dest, unsigned size, AES_KEY * key, uint8_t * ctr)
{
	uint8_t tmp[CIPHER_BLOCK_SIZE];
	unsigned i, block, num_blocks = size / CIPHER_BLOCK_SIZE;

	for (block = 0; block < num_blocks; block ++) {
		/* counter -> code */
		AES_encrypt (ctr, tmp, key);
		for (i = 0; i < CIPHER_BLOCK_SIZE; i++) {
			*dest = *src ^ tmp[i];
			dest ++;
			src ++;
		}
		/* advance counter */
		for (i = 0; i < CIPHER_BLOCK_SIZE; i++) {
			ctr[i]++;
			if (ctr[i] != 0) {
				break;
			}
		}
	}
}


static t_string * get_signature (t_safeu * ac, t_string * sign_this, t_identity * identity)
{
	uint32_t receive_size;
	uint8_t receive_type;
	t_string * sign = NULL;
	t_string * sign_type = NULL;
	t_string * hash_buffer = NULL;
	uint32_t content_start;

	/* send packet size */
	send_int (ac, 1 + /* sizeof (SSH2_AGENTC_SIGN_REQUEST) */
			4 + identity->key_data->size + /* string size (identity->key_data) */
			4 + sign_this->size + /* string size (identity->key_data) */
			4);	/* sizeof flags */
	send_byte (ac, SSH2_AGENTC_SIGN_REQUEST);
	send_string (ac, identity->key_data);
	send_string (ac, sign_this);
	send_int (ac, 0) ; /* flags */

	receive_size = receive_int (ac);
	receive_type = receive_byte (ac);
	if (receive_type != SSH2_AGENT_SIGN_RESPONSE) {
		fputs (AC "agent will not sign\n", stderr);
		goto error;
	}
	if (receive_size <= 4) {
		fputs (AC "agent invalid response\n", stderr);
		goto error;
	}
	sign = receive_string (ac);
	if (sign == NULL) goto error;
	sign_type = split_string (sign, &content_start);
	if (sign_type == NULL) goto error;

	if (sign->size <= content_start) {
		fputs (AC "no sign bytes\n", stderr);
		goto error;
	}

	hash_buffer = new_string (SHA512_SIZE);

	if (!compute_sha512_hash (&sign->text[content_start], sign->size - content_start,
								(const uint8_t *) "", 0,
								hash_buffer->text)) {
		/* sha512 computation failed */
		free_string (hash_buffer);
		hash_buffer = NULL;
	}
error:
	free_string (sign);
	free_string (sign_type);
	return hash_buffer;
}

static int encrypt (struct t_safeu_struct * ac)
{
	uint8_t plaintext_hash[SHA512_SIZE];
	uint8_t key_data_hash[SHA512_SIZE];
	uint8_t plaintext[FILE_BLOCK_SIZE];
	uint8_t ciphertext[FILE_BLOCK_SIZE];
	uint8_t ctr[CIPHER_BLOCK_SIZE];
	uint64_t size, total = 0;
	uint64_t padded_size, padding;
	uint16_t identity_number;
	int ok = 0;
	t_header_v2 header;
	t_string * salt = NULL;
	t_key_header file_key;
	AES_KEY key;

	/* calculate hash of first block of plaintext */
	size = block_read_input (ac, plaintext, sizeof (plaintext));
	if (!compute_sha512_hash (plaintext, size, (const uint8_t *) "", 0, plaintext_hash)) {
		goto error;
	}

	/* extract some entropy from the input */
	RAND_add (plaintext, size, 0.1 * size);

	/* generate header */
	memset (&header, 0, sizeof (header));
	header.id = HEADER_FILE_ID_DWORD;
	header.version = VERSION_DWORD;
	memcpy (header.plaintext_hash, plaintext_hash, sizeof (header.plaintext_hash));
	header.size = size = block_get_fsize_and_rewind (ac);
	padded_size = ((size + CIPHER_BLOCK_SIZE - 1) / CIPHER_BLOCK_SIZE) * CIPHER_BLOCK_SIZE;
	padding = padded_size - size;
	header.number_of_keys = ac->number_of_identities;

	/* generate salt field of plaintext */
	salt = new_string (sizeof (header.salt));
	RAND_bytes (header.salt, sizeof (header.salt));
	memcpy (salt->text, header.salt, sizeof (header.salt));

	/* header written to disk */
	if (!block_write_output (ac, &header, sizeof (header))) {
		goto error;
	}

	/* generate file key */
	RAND_bytes (file_key.iv, sizeof (file_key.iv));
	RAND_bytes (file_key.key, sizeof (file_key.key));

	/* encrypt file key for every identity */
	for (identity_number = 0; identity_number < ac->number_of_identities; identity_number++) {
		t_identity * identity = &ac->identities[identity_number];
		t_string * rsa_key = NULL;
		t_key_header header_key;

		/* generate key data hash field for this RSA key */
		if (!compute_sha512_hash ((uint8_t *) header.salt, sizeof (header.salt),
								(uint8_t *) identity->key_data->text, identity->key_data->size,
								key_data_hash)) {
			goto error;
		}
		memcpy (header_key.key_data_hash, key_data_hash, sizeof (header_key.key_data_hash));

		/* generate session key for this RSA key */
		rsa_key = get_signature (ac, salt, identity);

		/* Use the RSA key to encrypt the key stored in the key header */
		AES_set_encrypt_key ((uint8_t *) &rsa_key->text[SHA512_SIZE / 2], CIPHER_KEY_BITS, &key);
		memcpy (ctr, &rsa_key->text[0], CIPHER_BLOCK_SIZE);
		free_string (rsa_key);
		ctr_encrypt (file_key.key, header_key.key, CIPHER_KEY_SIZE, &key, ctr);
		ctr_encrypt (file_key.iv, header_key.iv, CIPHER_BLOCK_SIZE, &key, ctr);

		/* save key */
		if (!block_write_output (ac, &header_key, sizeof (t_key_header))) {
			goto error;
		}
	}

	/* begin encrypting */
	AES_set_encrypt_key (file_key.key, CIPHER_KEY_BITS, &key);
	memcpy (ctr, file_key.iv, CIPHER_BLOCK_SIZE);

	while (total < header.size) {
		size = block_read_input (ac, plaintext, sizeof (plaintext));
		total += size;
		if (size != sizeof (plaintext)) {
			if (total != header.size) {
				fputs (AC "file ended sooner than expected (size changed?)\n", stderr);
				goto error;
			}
			if (padding > 0) {
				RAND_bytes (&plaintext[size], padding);
				size += padding;
			}
			if ((size % CIPHER_BLOCK_SIZE) != 0) {
				fputs (AC "size is not a whole number of blocks\n", stderr);
				goto error;
			}
		}

		ctr_encrypt (plaintext, ciphertext, size, &key, ctr);

		if (!block_write_output (ac, ciphertext, size)) {
			goto error;
		}
	}
	ok = 1;
error:
	free_string (salt);
	return ok;
}


static int decrypt (t_safeu * ac)
{
	uint8_t key_data_hash[SHA512_SIZE];
	uint8_t plaintext[FILE_BLOCK_SIZE];
	uint8_t ciphertext[FILE_BLOCK_SIZE];
	uint8_t ctr[CIPHER_BLOCK_SIZE];
	uint64_t read_size, total = 0;
	unsigned i, j;
	uint64_t size, padded_size, padding;
	t_header_v1 header_v1;
	t_header_v2 header_v2;
	t_string * salt = NULL;
	int ok = 0;
	int first = 1;
	int key_found = 0;
	AES_KEY key;

	/* header read from memory */
	if (block_read_input (ac, &header_v2, sizeof (header_v2)) != sizeof (header_v2)) {
		fputs (AC "unable to read header\n", stderr);
		goto error;
	}

	if (((header_v2.id != HEADER_BLOCK_ID_DWORD)
	&& (header_v2.id != HEADER_FILE_ID_DWORD)
	&& (header_v2.id != HEADER_PWD_ID_DWORD))) {
		header_v2.version = 0;
	}

	switch (header_v2.version) {
		case 1:
			/* convert version 1 header */
			block_get_fsize_and_rewind (ac);
			if (block_read_input (ac, &header_v1, sizeof (header_v1)) != sizeof (header_v1)) {
				fputs (AC "unable to read v1 header\n", stderr);
				goto error;
			}
			memset (&header_v2, 0, sizeof (header_v2));
			header_v2.size = header_v1.size;
			memcpy (&header_v2.plaintext_hash, &header_v1.plaintext_hash, 8);

			/* get salt field of ciphertext */
			salt = new_string (sizeof (header_v1.salt));
			memcpy (salt->text, header_v1.salt, sizeof (header_v1.salt));

			/* Which key for decryption? */
			for (i = 0; i < ac->number_of_identities; i++) {
				t_identity * identity = &ac->identities[i];
				if (!compute_sha512_hash ((uint8_t *) header_v1.salt, sizeof (header_v1.salt),
										(uint8_t *) identity->key_data->text, identity->key_data->size,
										key_data_hash)) {
					goto error;
				}
				if (memcmp (header_v1.key_data_hash, key_data_hash, sizeof (header_v1.key_data_hash)) == 0) {
					/* key matched, get the session key and IV */
					t_string * rsa_key = get_signature (ac, salt, identity);
					AES_set_encrypt_key ((uint8_t *) &rsa_key->text[SHA512_SIZE / 2], CIPHER_KEY_BITS, &key);
					memcpy (ctr, &rsa_key->text[0], CIPHER_BLOCK_SIZE); /* IV */
					key_found = 1;
					break;
				}
			}
			break;
		case 2:
			/* accept version 2 header */

			/* get salt field of ciphertext */
			salt = new_string (sizeof (header_v2.salt));
			memcpy (salt->text, header_v2.salt, sizeof (header_v2.salt));

			/* Which key for decryption? */
			for (j = 0; j < header_v2.number_of_keys; j++) {
				t_key_header header_key;
				t_key_header file_key;
				if (block_read_input (ac, &header_key, sizeof (header_key)) != sizeof (header_key)) {
					fputs (AC "unable to read v2 key header\n", stderr);
					goto error;
				}
				for (i = 0; i < ac->number_of_identities; i++) {
					t_identity * identity = &ac->identities[i];
					if (!compute_sha512_hash ((uint8_t *) header_v2.salt, sizeof (header_v2.salt),
											(uint8_t *) identity->key_data->text, identity->key_data->size,
											key_data_hash)) {
						goto error;
					}
					
					if (memcmp (header_key.key_data_hash, key_data_hash, sizeof (header_key.key_data_hash)) == 0) {
						/* RSA key matched */
						t_string * rsa_key = get_signature (ac, salt, identity);

						/* Use the RSA key to decrypt the key stored in the key header */
						AES_set_encrypt_key ((uint8_t *) &rsa_key->text[SHA512_SIZE / 2], CIPHER_KEY_BITS, &key);
						memcpy (ctr, &rsa_key->text[0], CIPHER_BLOCK_SIZE);
						free_string (rsa_key);
						ctr_encrypt (header_key.key, file_key.key, CIPHER_KEY_SIZE, &key, ctr);
						ctr_encrypt (header_key.iv, file_key.iv, CIPHER_BLOCK_SIZE, &key, ctr);

						/* Now use the key header key to decrypt the file */
						AES_set_encrypt_key (file_key.key, CIPHER_KEY_BITS, &key);
						memcpy (ctr, file_key.iv, CIPHER_BLOCK_SIZE);
						key_found = 1;
						break;
					}
				}
			}
			break;
		default:
			fputs (AC "ciphertext header is unexpected", stderr);
			goto error;
	}

	if (!key_found) {
		fputs (AC "decryption key is not present in the agent\n", stderr);
		goto error;
	}

	padded_size = ((header_v2.size + CIPHER_BLOCK_SIZE - 1) / CIPHER_BLOCK_SIZE) * CIPHER_BLOCK_SIZE;
	padding = padded_size - header_v2.size;

	while (total < header_v2.size) {
		/* read size is limited to remaining data */
		read_size = sizeof (ciphertext);
		if (read_size > (padded_size - total)) {
			read_size = padded_size - total;
		}

		size = block_read_input (ac, ciphertext, read_size);
		total += size;
		if (size != read_size) {
			if (total != padded_size) {
				fputs (AC "file ended sooner than expected (size changed?)\n", stderr);
				goto error;
			}
			if ((size % CIPHER_BLOCK_SIZE) != 0) {
				fputs (AC "size is not a whole number of blocks\n", stderr);
				goto error;
			}
		}

		ctr_encrypt (ciphertext, plaintext, size, &key, ctr);
		
		if (total == padded_size) {
			size -= padding;
		}

		if (first) {
			uint8_t plaintext_hash[SHA512_SIZE];
			if (!compute_sha512_hash (plaintext, size, (const uint8_t *) "", 0, plaintext_hash)) {
				goto error;
			}
			if (memcmp (header_v2.plaintext_hash, plaintext_hash, sizeof (header_v2.plaintext_hash)) != 0) {
				fputs (AC "incorrect key: hash of plaintext is not as expected\n", stderr);
				goto error;
			}
			first = 0;
		}

		if (!block_write_output (ac, plaintext, size)) {
			goto error;
		}
	}
	ok = 1;
error:
	free_string (salt);
	return ok;
}

static uint64_t block_read_input (t_safeu * ac, void * data, uint64_t max_size)
{
	uint64_t size = 0;
	if (ac->position_in < ac->block_in_size) {
		size = ac->block_in_size - ac->position_in;
	}
	if (size > max_size) {
		size = max_size;
	}
	if (size > 0) {
		memcpy (data, &ac->block_in[ac->position_in], size);
		ac->position_in += size;
	}
	return size;
}

static uint64_t block_get_fsize_and_rewind (t_safeu * ac)
{
	ac->position_in = 0;
	return ac->block_in_size;
}

static int block_write_output (t_safeu * ac, const void * data, uint64_t size)
{
	if (((uint64_t) ac->position_out + size) > (uint64_t) ac->block_out_size) {
		fprintf (stderr, AC "block write size overflow, %u+%u > %u\n",
			(unsigned) ac->position_out, (unsigned) size, (unsigned) ac->block_out_size);
		return 0;
	}
	memcpy (&ac->block_out[ac->position_out], data, size);
	ac->position_out += size;
	return 1;
}

void clear_up (struct t_safeu_struct * ac)
{
	if (!ac) {
		return;
	}
	ac->position_out = 0;
	ac->position_in = 0;
	ac->block_in_size = 0;
	ac->block_out_size = 0;
	ac->block_in = NULL;
	ac->block_out = NULL;
}

static int connect_to_agent (t_safeu * ac, const char * agent_sock)
{
	struct sockaddr_un addr;
	struct stat s;

	ac->socket_handle = -1;
	if (!agent_sock) {
		return 0;
	}
	if (strlen (agent_sock) == 0) {
		return 0;
	}
	memset ((void*)&addr, 0x0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy (addr.sun_path, agent_sock, sizeof(addr.sun_path));
	addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';
	if (stat (addr.sun_path, &s) != 0) {
		/* socket file does not exist */
		return 0;
	}
	if (!S_ISSOCK(s.st_mode)) {
		/* socket file is not a socket */
		return 0;
	}

	ac->socket_handle = socket (PF_UNIX, SOCK_STREAM, 0);
	if (ac->socket_handle < 0) {
		return 0;
	}
	if (connect (ac->socket_handle, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		return 0;
	}
	ac->agent_socket_name = new_string (strlen (addr.sun_path) + 1);
	strcpy ((char *) ac->agent_socket_name->text, addr.sun_path);
	return 1;
}

static int search_for_agent (t_safeu * ac)
{
	const char * tmp_path;
	struct dirent * tmp_de = NULL;
	DIR * tmp_dir = NULL;
	struct dirent * ssh_de = NULL;
	DIR * ssh_dir = NULL;
	char ssh_path[BUFSIZ];
	char sock_path[BUFSIZ];

	tmp_path = getenv ("TMPDIR");
	if (!tmp_path) {
		tmp_path = "";
	}
	if (strlen (tmp_path) == 0) {
		tmp_path = "/tmp";
	}

	tmp_dir = opendir (tmp_path);
	if (!tmp_dir) {
		/* no temporary directory */
		return 0;
	}
	while ((tmp_de = readdir (tmp_dir)) != NULL) {
		if ((strncmp (tmp_de->d_name, "ssh-", 4) == 0)
		|| (strncmp (tmp_de->d_name, "dropbear-", 9) == 0)) {
			/* possible agent directory */
			snprintf (ssh_path, sizeof (ssh_path), "%s/%s", tmp_path, tmp_de->d_name);
			ssh_path[sizeof (ssh_path) - 1] = '\0';
			ssh_dir = opendir (ssh_path);
			if (ssh_dir) {
				while ((ssh_de = readdir (ssh_dir)) != NULL) {
					if ((strncmp (ssh_de->d_name, "agent", 5) == 0)
					|| (strncmp (ssh_de->d_name, "auth", 4) == 0)) {
						/* possible agent socket */
						snprintf (sock_path, sizeof (sock_path), "%s/%s", ssh_path, ssh_de->d_name);
						sock_path[sizeof (sock_path) - 1] = '\0';
						if (connect_to_agent (ac, sock_path)) {
							/* connected! */
							closedir (ssh_dir);
							closedir (tmp_dir);
							return 1;
						}
					}
				}
				closedir (ssh_dir);
			}
		}
	}
	closedir (tmp_dir);
	return 0;
}

static int permitted_key_type (t_string * key_type)
{
	return strcmp ((char *) key_type->text, "ssh-rsa") == 0;
}

t_safeu * safeu_new (const char * ssh_auth_sock)
{
	t_safeu * ac = NULL;

	ac = calloc (1, sizeof (t_safeu));
	if (!ac) {
		malloc_error ();
		goto error;
	}

	/* Connect to agent */
	{
		int ok = 0;

		/* try location specified by user (if any) */
		if (ssh_auth_sock == NULL) {
			/* try searching */
			ok = search_for_agent (ac);
		} else {
			/* direct connection */
			ok = connect_to_agent (ac, ssh_auth_sock);
		}
		if (!ok) {
			if (ssh_auth_sock) {
				fprintf (stderr, AC "unable to connect to any SSH agent at %s\n", ssh_auth_sock);
			} else {
				fprintf (stderr, AC "unable to find an SSH agent running anywhere\n");
			}
			goto error;
		}
	}

	/* Ask agent for list of identities */
	{
		uint32_t ai, mi;
		uint32_t agent_list_size, memory_list_size;

		send_int (ac, 1);
		send_byte (ac, SSH2_AGENTC_REQUEST_IDENTITIES);
		if ((receive_int (ac) < 5) 	/* At least sizeof(SSH2_AGENT_IDENTITIES_ANSWER) + sizeof(number_of_identities) */
		|| (receive_byte (ac) != SSH2_AGENT_IDENTITIES_ANSWER)) {
			fputs (AC "unable to obtain list of identities\n", stderr);
			goto error;
		}

		/* zero identities is valid (though unhelpful) */
		ac->number_of_identities = 0;

		/* number of identities known to agent */
		agent_list_size = receive_int (ac);

		/* memory list may be a subset of the agent's list if there are lots of identities */
		memory_list_size = agent_list_size;
		if (memory_list_size > MAX_IDENTITIES) {
			memory_list_size = MAX_IDENTITIES;
		}
	
		ac->identities = calloc (sizeof (t_identity), memory_list_size + 1);
		if (ac->identities == NULL) {
			malloc_error ();
			free (ac);
			ac = NULL;
			goto error;
		}

		for (ai = mi = 0; ai < agent_list_size; ai++) {
			uint32_t ignore;
			t_identity * identity = &ac->identities[mi];
			int accept = 0;

			identity->key_data = receive_string (ac);
			identity->comment = receive_string (ac);
			identity->key_type = split_string (identity->key_data, &ignore);

			/* add entropy for PRNG */
			RAND_add (identity->key_data->text, identity->key_data->size, 0.1 * identity->key_data->size);

			if (mi >= memory_list_size) {
				/* cannot store more identities in memory */
				accept = 0;

			} else if (!permitted_key_type (identity->key_type)) {
				/* not a permitted key type, don't store */
				accept = 0;

			} else {
				/* advance to next memory location */
				mi++;
				ac->number_of_identities = mi;
				accept = 1;
			}

			if (accept) {
				/* Get the key fingerprint (md5) */
				uint8_t hash[MD5_SIZE];
				char fingerprint[FP_BUF_SIZE + 1];
				uint32_t j;
				int k;

				if (!compute_md5_hash (identity->key_data->text, identity->key_data->size, hash)) {
					goto error;
				}

				/* MD5 fingerprint */
				k = 0;
				for (j = 0; j < MD5_SIZE; j++) {
					k += snprintf (&fingerprint[k], FP_BUF_SIZE - k, "%02x:", hash[j]);
				}
				k --; /* remove ':' */
				fingerprint[k] = ' ';
				k++;
				fingerprint[k] = '\0';

				/* add comment and key type */
				k += snprintf (&fingerprint[k], FP_BUF_SIZE - k, "%s (%s)",
							identity->comment->text, identity->key_type->text);
				fingerprint[k] = '\0';

				identity->fingerprint = new_string (k + 1);
				strcpy ((char *) identity->fingerprint->text, fingerprint);
			} else {
				/* Free strings */
				free_string (identity->key_data); identity->key_data = NULL;
				free_string (identity->comment);  identity->comment = NULL;
				free_string (identity->key_type); identity->key_type = NULL;
			}
		}
	}

	clear_up (ac);
	return ac;

error:
	clear_up (ac);
	free (ac);
	return NULL;
}

void safeu_free (t_safeu * ac)
{
	uint32_t i;

	if (!ac) {
		return;
	}
	clear_up (ac);
	close (ac->socket_handle);
	for (i = 0; i < ac->number_of_identities; i++) {
		t_identity * identity = &ac->identities[i];

		free_string (identity->key_data);
		free_string (identity->comment);
		free_string (identity->key_type);
		free_string (identity->fingerprint);
	}
	free_string (ac->agent_socket_name);
	free (ac->identities);
	free (ac);
}

int safeu_encrypt_block (struct t_safeu_struct * ac,
							const char * block_in, unsigned block_in_size,
							char ** block_out, unsigned * block_out_size)
{
	int ok = 0;

	(* block_out) = NULL;
	(* block_out_size) = 0;
	ac->position_in = 0;
	ac->position_out = 0;

	/* encrypt */
	ac->block_in = (const uint8_t *) block_in;
	ac->block_in_size = block_in_size;
	ac->block_out_size =
		(uint64_t) block_in_size + sizeof (t_header_v2) + 
		(sizeof (t_key_header) * ac->number_of_identities) +
		CIPHER_BLOCK_SIZE;
	ac->block_out = calloc (ac->block_out_size, 1);
	if (!ac->block_out) {
		malloc_error ();
	} else if (encrypt (ac)) {
		(* block_out_size) = ac->position_out;
		(* block_out) = (char *) ac->block_out;
		ok = 1;
	}

	clear_up (ac);

	return ok;
}

int safeu_decrypt_block (struct t_safeu_struct * ac,
							const char * block_in, unsigned block_in_size,
							char ** block_out, unsigned * block_out_size)
{
	int ok = 0;

	(* block_out) = NULL;
	(* block_out_size) = 0;
	ac->position_in = 0;
	ac->position_out = 0;

	/* decrypt */
	ac->block_in = (const uint8_t *) block_in;
	ac->block_in_size = block_in_size;
	ac->block_out_size = block_in_size;
	ac->block_out = calloc (ac->block_out_size, 1);
	if (!ac->block_out) {
		malloc_error ();
	} else if (decrypt (ac)) {
		(* block_out_size) = ac->position_out;
		(* block_out) = (char *) ac->block_out;
		ok = 1;
	}

	clear_up (ac);

	return ok;
}

static void test_block_encryption (t_safeu * ac, uint64_t size, uint64_t enlarge_by)
{
	unsigned check_size = 0;
	unsigned ciphertext_size = 0;
	char * plaintext = calloc (1, size + 1);
	char * check = NULL;
	char * ciphertext = NULL;
	int rc;

	printf ("test block with size %d enlarge %d: %d\n", 
				(int) size, (int) enlarge_by, (int) size % CIPHER_BLOCK_SIZE);
	if (!plaintext) {
		malloc_error ();
		abort ();
	}

	RAND_bytes ((uint8_t *) plaintext, size);

	rc = safeu_encrypt_block (ac, plaintext, size, &ciphertext, &ciphertext_size);

	if ((!rc) || (!ciphertext)) {
		fputs (AC "encrypt return error\n", stderr);
		abort ();
	}
	if (ciphertext_size < size) {
		fputs (AC "ciphertext size error\n", stderr);
		abort ();
	}

	if (enlarge_by) {
		ciphertext_size += enlarge_by;
		ciphertext = realloc (ciphertext, ciphertext_size);
		if (!ciphertext) {
			malloc_error ();
			abort ();
		}
	}

	rc = safeu_decrypt_block (ac, ciphertext, ciphertext_size, &check, &check_size);
	if ((!rc) || (!check)) {
		fputs (AC "decrypt return error\n", stderr);
		abort ();
	}
	if (check_size != size) {
		fputs (AC "plaintext size error\n", stderr);
		abort ();
	}

	if (memcmp (check, plaintext, size) != 0) {
		fputs (AC "readback data error\n", stderr);
		abort ();
	}
	free (plaintext);
	free (ciphertext);
	free (check);
}

void safeu_test (t_safeu * ac)
{
	uint32_t i;

	if (ac->number_of_identities == 0) {
		fputs (AC "no identities: cannot run tests\n", stderr);
		abort ();
	}
	for (i = 0; i < (CIPHER_BLOCK_SIZE + 2); i++) {
		test_block_encryption (ac, i, 0);
	}
	for (i = 0; i < (CIPHER_BLOCK_SIZE + 2); i++) {
		test_block_encryption (ac, i + (FILE_BLOCK_SIZE / 2) - 1, 0);
	}
	for (i = 0; i < ((CIPHER_BLOCK_SIZE + 2) * 2); i++) {
		test_block_encryption (ac, FILE_BLOCK_SIZE + i - CIPHER_BLOCK_SIZE, 0);
	}
	for (i = 0; i < 3; i++) {
		test_block_encryption (ac, FILE_BLOCK_SIZE * 2 + i - 1, 0);
	}
	for (i = 1; i < 20; i++) {
		test_block_encryption (ac, i, i);
	}
	test_block_encryption (ac, FILE_BLOCK_SIZE * 2, 1234);
}

const char * safeu_get_fingerprint (struct t_safeu_struct * ac, unsigned index)
{
	if (index < ac->number_of_identities) {
		return (char *) ac->identities[index].fingerprint->text;
	} else {
		return NULL;
	}
}

const char * safeu_get_socket_name (struct t_safeu_struct * ac)
{
	return (char *) ac->agent_socket_name->text;
}

/* ex: set tabstop=4 noexpandtab shiftwidth=4: */
