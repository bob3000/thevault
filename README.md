# The Vault

The vault is a command line file encryption tool. It performs symmetric AES
encryption using passwords. All cryptographic actions rely on libraries from the
[rust crypto](https://docs.rs/rust-crypto/0.2.36/crypto/) project.

## Installation

TODO

## Features

- encrypt / decrypt a file inplace or to a different destination
- view encrypted file
- edit encrypted file
- read password from password file, environment variable, command line parameter
  or stdin

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
79QhinA1CXegm9pRPdlkIlVWrPcX4qYIkYlAsyl2Y6CVN2A21B726rhe8bVbBk+kcDyivl7DTnq+5oUaR3TkNM8N4j2+4OCKeuihnQ7Vtv4I3WJ4IQueUJvmsoBbxuCFHVoMqGkbIdehS3CVdvovACqCGlAvH39yxh61Ds1Dp1ND8Uzkhe9JlM5wicQyy2PgSRqSvie1W7Wq732oJ1Jp9Xo7wWOAMQInLGa8+9bzIADdzJWuyTynJYo4Jn38NhlflG7B2iZ/2d6Zz2SDwJkzIQ==%                                                           
```

### Encrypt a file inplace

```sh
❯ cat <<END > zen
Beautiful is better than ugly.
Explicit is better than implicit.
Simple is better than complex.
Complex is better than complicated.
END

❯ thevault encrypt -i -f zen
Password:

❯ cat zen
XHapWrX3GY0w7armyeN6deuASMvuAoUo+3D3njamKNq73s5kptnrwKvEfmVkvG4NDay+FTSAwDmYDFMKHpQBmnq0DPK84/pplnADK2Untfzizh9ykZxd/ZLk/yLve6x2zuExSR04Ww+itbYuk1kPGgyrCpsBFkxtI8TnRZxSzmzDzjHGus/H2Qa36F/gBRZS5inxqReCYkgLRKjree9+rP+Ms8XyLc0aJWI/FmD8cKQ71k+QeJ/4ch7pIFbQ4A+fCHqSJZju45IoJIoMHm6TEQ==%                                                           
```
