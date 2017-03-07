#ifndef ACRYPT_FILES_H
#define ACRYPT_FILES_H

/* ex: set tabstop=4 noexpandtab shiftwidth=4: */

#ifdef __cplusplus
extern "C" {
#endif

#include "acrypt.h"

int acrypt_encrypt_a_file (struct t_acrypt_struct * ac,
							const char * src_fname, const char * dest_fname);
int acrypt_decrypt_a_file (struct t_acrypt_struct * ac,
							const char * src_fname, const char * dest_fname);
void acrypt_files_test (struct t_acrypt_struct * ac);


#ifdef __cplusplus
}
#endif
#endif

