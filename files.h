/* SSH Agent File Encryption Utility (safeu)
 * Copyright (C) Jack Whitham 2016-2017
 * 
 * https://github.com/jwhitham/safeu/
 * https://www.jwhitham.org/
 * 
 * ex: set tabstop=4 noexpandtab shiftwidth=4:
 */

#ifndef ACRYPT_FILES_H
#define ACRYPT_FILES_H


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

