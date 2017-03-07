#ifndef ACRYPT_H
#define ACRYPT_H

/* ex: set tabstop=4 noexpandtab shiftwidth=4: */

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

struct t_acrypt_struct;

int acrypt_encrypt_block (struct t_acrypt_struct * ac,
							const char * block_in, unsigned block_in_size,
							char ** block_out, unsigned * block_out_size);
int acrypt_decrypt_block (struct t_acrypt_struct * ac,
							const char * block_in, unsigned block_in_size,
							char ** block_out, unsigned * block_out_size);
struct t_acrypt_struct * acrypt_new (const char * ssh_auth_sock);
void acrypt_free (struct t_acrypt_struct * ac);
void acrypt_test (struct t_acrypt_struct * ac);
const char * acrypt_get_fingerprint (struct t_acrypt_struct * ac, unsigned index);
const char * acrypt_get_socket_name (struct t_acrypt_struct * ac);

#ifdef __cplusplus
}
#endif
#endif

