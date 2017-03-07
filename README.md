# SSH Agent File Encryption Utility (safeu)

Copyright (C) Jack Whitham 2016-2017

This command-line utility works with an SSH authentication agent such as Pageant or ssh-agent.
It can encrypt or decrypt files using your SSH key. It can fix up your SSH settings if you
lose your connection to the agent. It is also a library and can be used to securely store
passwords for other tools such as Subversion.

Encryption features use the OpenSSL library. The algorithms used are AES-256, SHA-512, RSA
and the secure random number generator built into OpenSSL.


# Examples

Encrypt a file. A session key is generated and encrypted using each one of the RSA keys stored by your SSH agent.

    $ safeu --encrypt plaintext --output ciphertext

Decrypt a file. Your SSH agent must have at least one of the same keys present when the file was encrypted.

    $ safeu --decrypt ciphertext --output plaintext

List all keys stored in the SSH agent.

    $ safeu --list
    f2:5f:37:37:37:37:96:5f:ce:37:37:28:78:37:79:6d work key (ssh-rsa)
    21:19:37:37:37:37:f1:71:f2:37:37:9b:12:37:51:b7 home (ssh-rsa)

Search for an SSH agent and print out the SSH_AUTH_SOCK name.

    $ safeu --search
    SSH_AUTH_SOCK=/tmp/ssh-5vmq6Id9LW/agent.2313; export SSH_AUTH_SOCK

I use "tmux" to keep persistent sessions running on various servers. When I reconnect, I use --search 
to re-establish a connection to my SSH agent. I do this with the following .bashrc function:

	ssh-fix ()
	{
	   eval `safeu --search`
	}


