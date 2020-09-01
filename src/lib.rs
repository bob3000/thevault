/*!
# The Vault

The Vault is a command line file encryption tool. It performs symmetric AES
encryption using passwords. All cryptographic actions rely on libraries from the
[rust crypto](https://docs.rs/rust-crypto/0.2.36/crypto/) project.

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
    -h, --help       Prints help information
    -i, --inplace    Wether to write to encrypted message to the source file
    -V, --version    Prints version information

OPTIONS:
    -f, --file <file>                      File to encrypt [default: stdin]
    -o, --outfile <outfile>                Destination file [default: stdout]
    -p, --password <password>              Encryption password [default: stdin] [env: THEVAULTPASS]
    -w, --password-file <password-file>    Path to file storing the encryption password

```

## Installation

Currently the way to install The Vault is via Cargo. This might change in the
future when I found the time to do the packaging.

```sh
cargo install thevault
```

## Environment Variables

| variable name  | purpose                                           | default value |
| -------------- | ------------------------------------------------- | ------------- |
| `EDITOR`       | the text editor to be used when editing the vault | vim           |
| `PAGER`        | the pager to be used when viewing the vault       | less          |
| `THEVAULTPASS` | the password used to encrypt / decrypt the vault  | `None`        |

## Setting a password

When working with The Vault on a frequent basis it might become tedious to type
the same password over and over again. There are several ways available to provide
the password without repeatedly typing it.

### A vault password file

```sh
echo mysecretpassword > ~/.thevaultpass  # Caution: the password ends up in the shell history
chmod 600 ~/.thevaultpass
thevault encrypt -i -w ~/.thevaultpass myprivatefile.txt
thevault decrypt -i -w ~/.thevaultpass myprivatefile.txt
```

### An environment variable

```sh
export THEVAULTPASS=mysecretpassword  # Caution: the password ends up in the shell history
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
79QhinA1CXegm9pRPdlkIlVWrPcX4qYIkYlAsyl2Y6CVN2A21B726rhe8bVbBk+kcDyivl7DTnq+5oUaR3TkNM8N4j2+4OCKeuihnQ7Vtv4I3WJ4IQueUJvmsoBbxuCFHVoMqGkbIdehS3CVdvovACqCGlAvH39yxh61Ds1Dp1ND8Uzkhe9JlM5wicQyy2PgSRqSvie1W7Wq732oJ1Jp9Xo7wWOAMQInLGa8+9bzIADdzJWuyTynJYo4Jn38NhlflG7B2iZ/2d6Zz2SDwJkzIQ==%
```

### Encrypt a file inplace

```sh
❯ cat <<END > zen.aes
Beautiful is better than ugly.
Explicit is better than implicit.
Simple is better than complex.
Complex is better than complicated.
END

❯ thevault encrypt -i -f zen.aes
Password:

❯ cat zen.aes
XHapWrX3GY0w7armyeN6deuASMvuAoUo+3D3njamKNq73s5kptnrwKvEfmVkvG4NDay+FTSAwDmYDFMKHpQBmnq0DPK84/pplnADK2Untfzizh9ykZxd/ZLk/yLve6x2zuExSR04Ww+itbYuk1kPGgyrCpsBFkxtI8TnRZxSzmzDzjHGus/H2Qa36F/gBRZS5inxqReCYkgLRKjree9+rP+Ms8XyLc0aJWI/FmD8cKQ71k+QeJ/4ch7pIFbQ4A+fCHqSJZju45IoJIoMHm6TEQ==%
```

### Decrypt a file to a different destination

```sh
❯ cat zen.aes
XHapWrX3GY0w7armyeN6deuASMvuAoUo+3D3njamKNq73s5kptnrwKvEfmVkvG4NDay+FTSAwDmYDFMKHpQBmnq0DPK84/pplnADK2Untfzizh9ykZxd/ZLk/yLve6x2zuExSR04Ww+itbYuk1kPGgyrCpsBFkxtI8TnRZxSzmzDzjHGus/H2Qa36F/gBRZS5inxqReCYkgLRKjree9+rP+Ms8XyLc0aJWI/FmD8cKQ71k+QeJ/4ch7pIFbQ4A+fCHqSJZju45IoJIoMHm6TEQ==%

❯ thevault decrypt -f zen.aes -o zen
Password:

❯ cat zen
Beautiful is better than ugly.
Explicit is better than implicit.
Simple is better than complex.
Complex is better than complicated.
```
*/

use aes::Aes256;
use base64::DecodeError;
use block_modes::block_padding::Iso7816;
use block_modes::{BlockMode, InvalidKeyIvLength};
use crypto_mac::MacError;
use hkdf::Hkdf;
use hmac::{Hmac, Mac, NewMac};
use rand::distributions::{Distribution, Standard};
use rand::thread_rng;
use secstr::{SecStr, SecVec};
use sha2::Sha256;
use thiserror::Error;

type Aes256Cbc = block_modes::Cbc<Aes256, Iso7816>;
type HmacSha256 = Hmac<Sha256>;

pub fn encrypt(password: SecStr, plaintext: SecVec<u8>) -> Vec<u8> {
    // generate random values
    let rng = thread_rng();
    let salt: Vec<u8> = Standard.sample_iter(rng).take(16).collect();
    let init_vec: Vec<u8> = Standard.sample_iter(rng).take(16).collect();

    // derive key
    let derived_key = Hkdf::<Sha256>::new(Some(&salt[..]), &password[..]);
    let mut key = [0u8; 32];
    derived_key.expand(&[], &mut key).unwrap();

    // encrypt
    let cipher = Aes256Cbc::new_var(&key[..], &init_vec).unwrap();
    let ciphertext = cipher.encrypt_vec(plaintext.unsecure());

    // calculate hmac
    let mut mac = HmacSha256::new_varkey(&key[..]).unwrap();
    mac.update(&ciphertext[..]);
    let checksum = mac.finalize().into_bytes();

    // build package
    let mut result: Vec<u8> = Vec::new();
    result.extend(salt);
    result.extend(init_vec);
    result.extend(checksum);
    result.extend(ciphertext);

    // base64 encode
    base64::encode(result).as_bytes().to_vec()
}

// let salt = cipher_package[..16].to_vec();
// let init_vec = cipher_package[16..32].to_vec();
// let checksum = cipher_package[32..64].to_vec();
// let ciphertext = cipher_package[64..].to_vec();
pub fn decrypt(password: SecStr, cipher_package: &[u8]) -> Result<SecVec<u8>, DecryptionError> {
    if cipher_package.len() < 64 {
        return Err(DecryptionError::InvalidCipherLength);
    }
    // base64 decode
    let cpackage = base64::decode(cipher_package)?;

    // derrive key
    let h = Hkdf::<Sha256>::new(Some(&cpackage[..16]), &password.unsecure()[..]);
    let mut key = [0u8; 32];
    h.expand(&[], &mut key).unwrap();

    // verify hmac
    let mut mac = HmacSha256::new_varkey(&key[..]).unwrap();
    mac.update(&cpackage[64..]);
    mac.verify(&cpackage[32..64])?;

    // decrypt
    let cipher = Aes256Cbc::new_var(&key[..], &cpackage[16..32])?;
    let plaintext = cipher.decrypt_vec(&cpackage[64..]).unwrap();

    Ok(SecVec::new(plaintext))
}

#[derive(Error, Debug)]
pub enum DecryptionError {
    #[error("cipher text does not contain all necessary elements")]
    InvalidCipherLength,
    #[error("HMAC verification failed")]
    HmacVerificationFailure(#[from] MacError),
    #[error("Improper key length")]
    KeyError(#[from] InvalidKeyIvLength),
    #[error("base64 decoding error")]
    Base64Error(#[from] DecodeError),
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn successful_encrypt_decrypt() {
        let password = SecStr::from("0123456789ABCDEF0123456789ABCDEF");
        let message = SecVec::from("this is a very secret message!!!");
        let ciphertext = encrypt(password.clone(), message.clone());
        assert_ne!(&message.unsecure()[..], &ciphertext[..]);
        let decrypted_text = decrypt(password, &ciphertext[..]).unwrap();
        assert_eq!(&message.unsecure(), &decrypted_text.unsecure());
    }

    #[test]
    fn base64_error() {
        let password = SecStr::from("0123456789ABCDEF0123456789ABCDEF");
        let ciphertext = b"?".repeat(65);
        let decryption_err = decrypt(password, &ciphertext[..]).unwrap_err();
        assert_eq!(decryption_err.to_string(), "base64 decoding error");
    }

    #[test]
    fn incomplete_package() {
        let password = SecStr::from("0123456789ABCDEF0123456789ABCDEF");
        let ciphertext = b"0123456789ABCDEF";
        let decryption_err = decrypt(password, &ciphertext[..]).unwrap_err();
        assert_eq!(
            decryption_err.to_string(),
            "cipher text does not contain all necessary elements"
        );
    }

    #[test]
    fn invalid_checksum() {
        let password = SecStr::from("0123456789ABCDEF0123456789ABCDEF");
        let message = SecVec::from("this is a very secret message!!!");
        let ciphertext = encrypt(password.clone(), message.clone());
        assert_ne!(&message.unsecure()[..], &ciphertext[..]);
        let end = ciphertext.len() - 4;
        let decryption_err = decrypt(password, &ciphertext[..end]).unwrap_err();
        assert_eq!(decryption_err.to_string(), "HMAC verification failed");
    }
}
