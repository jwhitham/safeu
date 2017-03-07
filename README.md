# SSH Agent File Encryption Utility (safeu)

Copyright (C) Jack Whitham 2016-2017

This command-line utility works with an SSH authentication agent such as Pageant or ssh-agent.
It can encrypt or decrypt files using your SSH key. It can fix up your SSH settings if you
lose your connection to the agent. It can also be used to securely store passwords for other 
tools such as Subversion.


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


# Internals

Encryption features use the OpenSSL library. The algorithms used are AES-256, SHA-512, RSA
and the secure random number generator built into OpenSSL.

The 'ssh.h' file defining the SSH agent interface is taken from dropbear. 


# Limitations

Only RSA keys are supported, in SSH2 format.


# Subversion

safeu was originally written in order to store passwords for Subversion (SVN). SVN provides
a number of ways to store passwords, and this is almost always necessary because so many SVN
commands require a connection to the server. For example, on Windows, the built-in password
storage feature is used by default. On Linux there is no universal solution for password storage
though both gnome-keyring and kwallet can provide the service. If gnome-keyring and kwallet
are not available then SVN offers to save passwords in clear text. (This is not a great idea
and SVN provides a warning to that effect.)

I normally use SVN via SSH to remote servers, with no GUI, and often the machine I am 
connected to is not running any recent Linux software. This means I cannot use gnome-keyring
or kwallet to save my passwords. I could use gpg-agent. But I already have a private key set up,
in my SSH authentication agent.

safeu allows me to use keys in the SSH agent to secure passwords. There is a patch for SVN 1.9.5
which adds the feature. This patch should be applied to the stable 1.9.5 source code; you
must then run 'autogen.sh' before 'configure --with-safeu'. Here are the setup steps I am using to build
a statically linked 'svn' binary which is quite portable across many different machines.

    cd $HOME/safeu
    make INCLUDES=-I$HOME/openssl-1.1.0d/install/include/ LIBS="-L$HOME/openssl-1.1.0d/install/lib -lcrypto -lssl -lpthread -ldl"

    cd $HOME/subversion-1.9.5
    ./autogen.sh
    ./configure --prefix=$PWD/install \
       --with-apr=$HOME/apr-1.5.2/install/ --with-apr-util=$HOME/apr-util-1.5.4/install/ \
       --with-serf=$HOME/serf-1.3.9/install/ \
       --enable-static --disable-shared \
       --with-safeu=$HOME/safeu \
       --with-libs=$HOME/openssl-1.1.0d/install/lib/
    make \
       SVN_APR_LIBS="-L$HOME/apr-1.5.2/install/lib -lapr-1 \
                -L$HOME/openssl-1.1.0d/install/lib -lssl -lcrypto"
    make install



