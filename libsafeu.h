/* SSH Agent File Encryption Utility (safeu)
 * Copyright (C) Jack Whitham 2016-2017
 * 
 * https://github.com/jwhitham/safeu/
 * https://www.jwhitham.org/
 * 
 */

#ifndef SAFEU_H
#define SAFEU_H


#ifdef __cplusplus
extern "C" {
#endif

#define SHA512_SIZE			(512 / 8)
#define MD5_SIZE			(16)
#define CIPHER_BLOCK_BITS	(128)
#define CIPHER_BLOCK_SIZE	(CIPHER_BLOCK_BITS / 8)
#define CIPHER_KEY_BITS		(256)
#define CIPHER_KEY_SIZE		(CIPHER_KEY_BITS / 8)
#define FILE_BLOCK_SIZE		(1 << 16)

struct t_safeu_struct;

int safeu_encrypt_block (struct t_safeu_struct * ac,
							const char * block_in, unsigned block_in_size,
							char ** block_out, unsigned * block_out_size);
int safeu_decrypt_block (struct t_safeu_struct * ac,
							const char * block_in, unsigned block_in_size,
							char ** block_out, unsigned * block_out_size);
struct t_safeu_struct * safeu_new (const char * ssh_auth_sock);
void safeu_free (struct t_safeu_struct * ac);
void safeu_test (struct t_safeu_struct * ac);
const char * safeu_get_fingerprint (struct t_safeu_struct * ac, unsigned index);
const char * safeu_get_socket_name (struct t_safeu_struct * ac);
int safeu_version (void);

#ifdef __cplusplus
}
#endif
#endif

/* ex: set tabstop=4 noexpandtab shiftwidth=4: */
