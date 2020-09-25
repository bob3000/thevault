# The Vault

The Vault is a command line file encryption tool. It performs symmetric AES
encryption using passwords. All cryptographic actions rely on libraries from the
[rust crypto](https://github.com/RustCrypto/block-ciphers) project.

## Features

- encrypt / decrypt a file inplace or to a different destination
- view encrypted file
- edit encrypted file
- read password from password file, environment variable, command line parameter
  or stdin

Available sub commands

```sh
thevault 0.1.0
A file encryption utility

USAGE:
    thevault <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    decrypt    Decrypts a message to a file or stdout
    edit       Opens an encrypted file in the default editor
    encrypt    Encrypts a message from a file or stdin
    help       Prints this message or the help of the given subcommand(s)
    view       Opens an encrypted file in the default pager

```

Available options and flags

```sh
thevault-encrypt 0.1.0
Encrypts a message from a file or stdin

USAGE:
    thevault encrypt [FLAGS] [OPTIONS]

FLAGS:
    -b, --base64     Write out the encrypted message as base64 encoded string
    -h, --help       Prints help information
    -i, --inplace    Wether to write to encrypted message to the source file
    -V, --version    Prints version information

OPTIONS:
    -f, --file <file>                      File to encrypt [default: stdin]
    -o, --outfile <outfile>                Destination file [default: stdout]
    -p, --password <password>              Encryption password [default: stdin] [env: THEVAULTPASS]
    -w, --password-file <password-file>    Path to file storing the encryption password [env:
                                           THEVAULTPASSFILE=]

```

## Installation

Currently the way to install The Vault is via Cargo. This might change in the
future when I found the time to do the packaging.

```sh
cargo install thevault
```

## Environment Variables

| variable name      | purpose                                                        | default value |
| ------------------ | -------------------------------------------------------------- | ------------- |
| `EDITOR`           | the text editor to be used when editing the vault              | vim           |
| `PAGER`            | the pager to be used when viewing the vault                    | less          |
| `THEVAULTPASS`     | the password used to encrypt / decrypt the vault               | `None`        |
| `THEVAULTPASSFILE` | path to a file containing the encryption / decryption password | `None`        |

## Setting a password

When working with The Vault on a frequent basis it might become tedious to type
the same password over and over again. There are several ways available to provide
the password without repeatedly typing it.

### A vault password file

```sh
head -c 32 /dev/random | base64 > ~/.thevaultpass
chmod 600 ~/.thevaultpass
thevault encrypt -i -w ~/.thevaultpass myprivatefile.txt
thevault decrypt -i -w ~/.thevaultpass myprivatefile.txt
```

### An environment variable

```sh
export THEVAULTPASS=$(head -c 32 /dev/random | base64)
thevault encrypt -i myprivatefile.txt
thevault decrypt -i myprivatefile.txt
```

### Command line option

```sh
thevault encrypt -i -p mysecretpassword  myprivatefile.txt  # Caution: the password ends up in the shell history
thevault decrypt -i -p mysecretpassword  myprivatefile.txt  # Caution: the password ends up in the shell history
```

## Examples

### Read from _stdin_ and write to _stdout_

```sh
❯ cat <<END | thevault encrypt
Beautiful is better than ugly.
Explicit is better than implicit.
Simple is better than complex.
Complex is better than complicated.
END
Password:
THEVAULTB64NDQ=e0uQ9vtxKucIiTMHqBaCi7tu3b26hEw4Xk4IvIQRadc=MjM2jVvSCWTJqCnlc3vetr5vYYo802VqEmmla40BJVlHeKjiA5wQFAYUB6LiWoej8Hh0RGnC/C6SyKfBpOTkx4VW6kY9uKwdipuTZkAUVaNB0NH2fcM0Ps5iXjQh+tcg18CDgLXLDnWH4DQm0rl10yGt3W9DLWUcpAgyW6aQPqnuWeKDbZo9zdr7zXD5AomFv2zPZcMDEN8vhU1AWqzHJXnEjudZOq+nCn5735Jn4ZC+hMY=
```

### Decrypt a file to a different destination

```sh
❯ cat zen.aes
THEVAULTB64NDQ=e0uQ9vtxKucIiTMHqBaCi7tu3b26hEw4Xk4IvIQRadc=MjM2jVvSCWTJqCnlc3vetr5vYYo802VqEmmla40BJVlHeKjiA5wQFAYUB6LiWoej8Hh0RGnC/C6SyKfBpOTkx4VW6kY9uKwdipuTZkAUVaNB0NH2fcM0Ps5iXjQh+tcg18CDgLXLDnWH4DQm0rl10yGt3W9DLWUcpAgyW6aQPqnuWeKDbZo9zdr7zXD5AomFv2zPZcMDEN8vhU1AWqzHJXnEjudZOq+nCn5735Jn4ZC+hMY=

❯ thevault decrypt -f zen.aes -o zen
Password:

❯ cat zen
Beautiful is better than ugly.
Explicit is better than implicit.
Simple is better than complex.
Complex is better than complicated.
```
