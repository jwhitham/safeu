
/* ex: set tabstop=4 noexpandtab shiftwidth=4: */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include "acrypt.h"
#include "acrypt_files.h"

typedef struct t_option_struct {
	struct option	op;
	const char *	help;
} t_option;

static const t_option all_options[] = {
	{{"encrypt",		required_argument,	0,	'e'},
		"Encrypt file <e> using all keys stored in agent, writing to output file <o>."},
	{{"decrypt",		required_argument,	0,	'd'},
		"Decrypt file <d> writing to output file <o>."},
	{{"list",			no_argument,		0,	'l'},
		"List all keys stored in agent."},
	{{"test-acrypt",	no_argument,		0,	'T'},
		NULL},
	{{"help",			no_argument,		0,	'h'},
		NULL},
	{{"output",			required_argument,	0,	'o'},
		"Specify an output file for --encrypt."},
	{{"socket",			required_argument,	0,	's'},
		"Specify the SSH authentication agent socket file, overriding SSH_AUTH_SOCK."},
	{{"search",			no_argument,		0,	'S'},
		"Search for the SSH authentication agent socket file."},
	{{0,				0,					0,	0},
		NULL},
};

static void show_help (const char * advice)
{
	int i, j;

	if (!advice) {
		advice = "no operation specified";
	}
	printf ("acrypt: %s\n\n", advice);
		
	for (i = 0; all_options[i].op.name != NULL; i++) {
		if (all_options[i].help != NULL) {
			j = printf ("-%c, --%s", all_options[i].op.val, all_options[i].op.name);
			if (all_options[i].op.has_arg != no_argument) {
				j += printf (" <%c>", all_options[i].op.val);
			}
			while (j < 40) {
				j++;
				putchar (' ');
			}
			printf ("%s\n", all_options[i].help);
		}
	}
}

static void no_keys (void)
{
	fputs ("acrypt: error: agent does not hold any keys\n", stderr);
}

static void malloc_error (void)
{
	fputs ("acrypt: unable to allocate memory\n", stderr);
	exit (1);
}

#ifdef COVERAGE_TEST
void coverage_setup (void);
#endif

int main (int argc, char ** argv)
{
	typedef enum {unset, encrypt, decrypt, list_all_keys, test, search} t_mode;
	t_mode mode = unset;
	typedef enum {unspecified, specify_socket, specify_search} t_search_mode;
	t_search_mode search_mode = unspecified;
	const char * file = NULL;
	char * output = NULL;
	struct option * long_options = NULL;
	char * short_options = NULL;
	struct t_acrypt_struct * ac = NULL;
	const char * ssh_auth_sock = NULL;
   int ok = 0;

#ifdef COVERAGE_TEST
	#pragma RVS add_code ("coverage_setup ();");
#endif

	/* Build option structures */
	{
		int i, j, num_options;
		
		/* Counting number of options */
		for (i = 0; all_options[i].op.name != NULL; i++) {}
		num_options = i;

		/* setup short options */
		short_options = calloc (num_options * 3, sizeof (char));
		if (!short_options) {
			malloc_error ();
		}
		for (i = j = 0; i < num_options; i++) {
			short_options[j] = all_options[i].op.val;
			j++;
			if (all_options[i].op.has_arg != no_argument) {
				short_options[j] = ':';
				j++;
			}
		}
		short_options[j] = '\0';

		/* setup long options */
		long_options = calloc (num_options + 1, sizeof (t_option));
		if (!long_options) {
			malloc_error ();
		}
		for (i = 0; i < (num_options + 1); i++) {
			memcpy (&long_options[i], &all_options[i].op, sizeof (t_option));
		}
	}

	/* Parsing command-line arguments */

	while (1) {
		int option_index = 0;

		int c = getopt_long(argc, argv, short_options, long_options, &option_index);
		if (c == -1) {
			break;
		}

		switch (c) {
			case 'l':
				if (mode != unset) {
					show_help (NULL);
					return 1;
				}
				mode = list_all_keys;
				file = optarg;
				break;
			case 'T':
				if (mode != unset) {
					show_help (NULL);
					return 1;
				}
				mode = test;
				break;
			case 'e':
				if (mode != unset) {
					show_help (NULL);
					return 1;
				}
				mode = encrypt;
				file = optarg;
				break;
			case 'd':
				if (mode != unset) {
					show_help (NULL);
					return 1;
				}
				mode = decrypt;
				file = optarg;
				break;
			case 'o':
				if (output) {
					show_help ("--output specified twice");
					return 1;
				}
				output = optarg;
				break;
			case 's':
				if (search_mode != unspecified) {
					show_help ("--search / --socket specified twice");
					return 1;
				}
				search_mode = specify_socket;
				ssh_auth_sock = optarg;
				break;
			case 'S':
				if (search_mode != unspecified) {
					show_help ("--search / --socket specified twice");
					return 1;
				}
				search_mode = specify_search;
				ssh_auth_sock = NULL;
				break;
			case '?':
			case 'h':
				show_help ("--help requested");
				return 1;
			default:
				show_help ("unknown option present");
				return 1;
		}
	}

	free (long_options);
	free (short_options);

	if (optind < argc) {
		/* non-option argv elements are present */
		show_help ("unknown parameter(s) present");
		return 1;
	}
	if (mode == unset) {
		if (search_mode != specify_search) {
			show_help ("no operation was specified");
			return 1;
		}
		mode = search; /* give location of SSH_AUTH_SOCK */
	}

	/* Command-line arguments are now parsed, and considered valid.
	 * We will now carry out operations that do not require the user to
	 * specify an output file.
	 */
	
	if (search_mode == unspecified) {
		ssh_auth_sock = getenv ("SSH_AUTH_SOCK");
		if ((ssh_auth_sock == NULL)
		|| (strlen (ssh_auth_sock) == 0)) {
			fputs ("SSH agent may not be available, as the SSH_AUTH_SOCK environment variable is unset. "
				"Try --search?\n", stderr);
			return 1;
		}
	}

	ac = acrypt_new (ssh_auth_sock);
   if (!ac) {
      /* error reported by acrypt library */
      return 1;
   }

	switch (mode) {
			/* These operations require an output file, so our
			 * next step is to deal with the case where the user 
			 * didn't specify -o */
		case encrypt:
			if (!output) {
				show_help ("--output is required for --encrypt");
				return 1;
			}
			if (acrypt_get_fingerprint (ac, 0) == NULL) {
				no_keys ();
				return 1;
			}
			break;
		case decrypt:
			if (!output) {
				show_help ("--output is required for --decrypt");
				return 1;
			}
			if (acrypt_get_fingerprint (ac, 0) == NULL) {
				no_keys ();
				return 1;
			}
			break;
		case test:
			{
				printf ("calling acrypt_files_test()\n");
				acrypt_files_test (ac);
				printf ("calling acrypt_test()\n");
				acrypt_free (ac);
				printf ("test passed\n");
			}
			return 0;
		case list_all_keys:
			{
				unsigned index = 0;
				int match = 0;

				do {
					const char * f = acrypt_get_fingerprint (ac, index);
					if (f == NULL) {
						break;
					}
					index ++;
					match = 1;
					printf ("%s\n", f);
				} while (1);

				if (index == 0) {
					no_keys ();
					return 1;
				}
				acrypt_free (ac);
			}
			return 0;
		case search:
			/* results of search */
			printf ("SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK\n", acrypt_get_socket_name (ac));
			return 0;
		default:
			/* should be unreachable */
			abort ();
			break;
	}

	/* Operations requiring an output file. */

	switch (mode) {
		case encrypt:
			/* matched key */
			ok = acrypt_encrypt_a_file (ac, file, output);
			acrypt_free (ac);
			return ok ? 0 : 1;
		case decrypt:
			/* connect to agent and search keys */
			ok = acrypt_decrypt_a_file (ac, file, output);
			acrypt_free (ac);
			return ok ? 0 : 1;
		default:
			/* should be unreachable */
			abort ();
			break;
	}
	/* should be unreachable */
	abort ();
	return 1;
}
