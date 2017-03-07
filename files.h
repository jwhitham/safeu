#ifndef ACRYPT_FILES_H
#define ACRYPT_FILES_H

/* ex: set tabstop=4 noexpandtab shiftwidth=4: */

#ifdef __cplusplus
extern "C" {
#endif

#include "libsafeu.h"

int safeu_encrypt_a_file (struct t_safeu_struct * ac,
							const char * src_fname, const char * dest_fname);
int safeu_decrypt_a_file (struct t_safeu_struct * ac,
							const char * src_fname, const char * dest_fname);
void safeu_files_test (struct t_safeu_struct * ac);


#ifdef __cplusplus
}
#endif
#endif

