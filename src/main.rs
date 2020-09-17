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

mod crypto;
mod helper;
mod io;
use anyhow::Context;
use secstr::{SecStr, SecVec};
use std::env;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use structopt::StructOpt;

// helper functions

// sub commands
async fn vault_decrypt<'a>(
    file_input: Option<&'a Path>,
    file_output: Option<&'a Path>,
    mut password: Option<String>,
    password_file: Option<PathBuf>,
    inplace: bool,
) -> anyhow::Result<()> {
    let pass = helper::get_password(&mut password, &password_file).unwrap();
    io::read_process_write(
        file_input,
        file_output,
        inplace,
        io::Action::Decrypt,
        move |cipher_package| {
            let pw = pass.clone();
            async move {
                let plaintext = crypto::decrypt(SecStr::from(pw), cipher_package)
                    .await?
                    .unsecure()
                    .to_vec();
                Ok::<Vec<u8>, anyhow::Error>(plaintext)
            }
        },
    )
    .await?;
    Ok::<(), anyhow::Error>(())
}

async fn vault_edit<'a>(
    file_input: &'a Path,
    mut password: Option<String>,
    password_file: Option<PathBuf>,
) -> anyhow::Result<()> {
    let pass = helper::get_password(&mut password, &password_file).unwrap();
    io::read_process_write(
        Some(file_input),
        None,
        true,
        io::Action::Decrypt,
        move |cipher_package| {
            let pw = pass.clone();
            async move {
                let plaintext = crypto::decrypt(SecStr::from(pw.clone()), cipher_package)
                    .await?
                    .unsecure()
                    .to_vec();

                let editor_cmd = env::var("EDITOR").unwrap_or("vim".to_string());
                let editor =
                    helper::which(&editor_cmd).with_context(|| format!("no pager was found"))?;

                let mut tmp_file = tempfile::NamedTempFile::new()?;
                tmp_file.write_all(&plaintext)?;

                let mut editor_process = Command::new(editor)
                    .arg(tmp_file.path())
                    .spawn()
                    .with_context(|| format!("error while spawning pager {}", editor_cmd))?;
                editor_process.wait()?;

                let mut changed_text: Vec<u8> = Vec::new();
                tmp_file.reopen()?.read_to_end(&mut changed_text)?;

                let cipher_package =
                    crypto::encrypt(SecStr::from(pw), SecVec::from(changed_text.to_vec())).await;
                drop(tmp_file);
                Ok::<Vec<u8>, anyhow::Error>(cipher_package)
            }
        },
    )
    .await?;
    Ok(())
}

async fn vault_encrypt<'a>(
    file_input: Option<&'a Path>,
    file_output: Option<&'a Path>,
    mut password: Option<String>,
    password_file: Option<PathBuf>,
    inplace: bool,
    base64: bool,
) -> anyhow::Result<()> {
    let pass = helper::get_password(&mut password, &password_file).unwrap();
    let encoding = if base64 {
        io::Action::EncryptB64
    } else {
        io::Action::Encrypt
    };
    io::read_process_write(
        file_input,
        file_output,
        inplace,
        encoding,
        move |plaintext| {
            let pw = pass.clone();
            async move {
                let ciphertext =
                    crypto::encrypt(SecStr::from(pw), SecVec::new(plaintext.to_vec())).await;
                Ok::<Vec<u8>, anyhow::Error>(ciphertext)
            }
        },
    )
    .await?;
    Ok(())
}

async fn vault_view<'a>(
    file_input: &'a Path,
    mut password: Option<String>,
    password_file: Option<PathBuf>,
) -> anyhow::Result<()> {
    let pass = helper::get_password(&mut password, &password_file).unwrap();
    io::read_process_write(
        Some(file_input),
        None,
        false,
        io::Action::Decrypt,
        move |cipher_package| {
            let pw = pass.clone();
            async move {
                let plain_bytes = crypto::decrypt(SecStr::from(pw), cipher_package)
                    .await?
                    .unsecure()
                    .to_vec();
                let plaintext = String::from_utf8(plain_bytes)?;

                let pager_cmd = env::var("PAGER").unwrap_or("less".to_string());
                let pager =
                    helper::which(&pager_cmd).with_context(|| format!("no pager was found"))?;

                let mut pager_process = Command::new(pager)
                    .stdin(Stdio::piped())
                    .spawn()
                    .with_context(|| format!("error while spawning pager {}", pager_cmd))?;

                let pager_stdin = pager_process.stdin.as_mut().unwrap();
                write!(pager_stdin, "{}", plaintext)?;
                pager_process.wait()?;
                Ok::<Vec<u8>, anyhow::Error>(Vec::new())
            }
        },
    )
    .await?;
    Ok(())
}

// command line interface
#[derive(Debug, StructOpt)]
#[structopt(name = "thevault", about = "A file encryption utility")]
enum Opt {
    /// Decrypts a message to a file or stdout
    Decrypt {
        #[structopt(
            long,
            short,
            parse(from_os_str),
            help = "File to decrypt [default: stdin]"
        )]
        file: Option<PathBuf>,
        #[structopt(
            long,
            short,
            parse(from_os_str),
            help = "Destination file [default: stdout]"
        )]
        outfile: Option<PathBuf>,
        #[structopt(
            long,
            short,
            env = "THEVAULTPASS",
            hide_env_values = true,
            help = "Decryption password [default: stdin]"
        )]
        password: Option<String>,
        #[structopt(
            long,
            short("w"),
            env = "THEVAULTPASSFILE",
            parse(from_os_str),
            help = "Path to file storing the decryption password"
        )]
        password_file: Option<PathBuf>,
        #[structopt(
            long,
            short,
            help = "Wether to write to decrypted message to the source file"
        )]
        inplace: bool,
    },
    /// Opens an encrypted file in the default editor
    Edit {
        #[structopt(long, short, parse(from_os_str), help = "File to edit")]
        file: PathBuf,
        #[structopt(
            long,
            short,
            env = "THEVAULTPASS",
            hide_env_values = true,
            help = "Decryption password [default: stdin]"
        )]
        password: Option<String>,
        #[structopt(
            long,
            short("w"),
            env = "THEVAULTPASSFILE",
            parse(from_os_str),
            help = "Path to file storing the decryption password"
        )]
        password_file: Option<PathBuf>,
    },
    /// Encrypts a message from a file or stdin
    Encrypt {
        #[structopt(
            long,
            short,
            parse(from_os_str),
            help = "File to encrypt [default: stdin]"
        )]
        file: Option<PathBuf>,
        #[structopt(
            long,
            short,
            parse(from_os_str),
            help = "Destination file [default: stdout]"
        )]
        outfile: Option<PathBuf>,
        #[structopt(
            long,
            short,
            env = "THEVAULTPASS",
            hide_env_values = true,
            help = "Encryption password [default: stdin]"
        )]
        password: Option<String>,
        #[structopt(
            long,
            short("w"),
            env = "THEVAULTPASSFILE",
            parse(from_os_str),
            help = "Path to file storing the encryption password"
        )]
        password_file: Option<PathBuf>,
        #[structopt(
            long,
            short,
            help = "Wether to write to encrypted message to the source file"
        )]
        inplace: bool,
        #[structopt(
            long,
            short,
            help = "Write out the encrypted message as base64 encoded string"
        )]
        base64: bool,
    },
    /// Opens an encrypted file in the default pager
    View {
        #[structopt(long, short, parse(from_os_str), help = "File to view")]
        file: PathBuf,
        #[structopt(
            long,
            short,
            env = "THEVAULTPASS",
            hide_env_values = true,
            help = "Decryption password [default: stdin]"
        )]
        password: Option<String>,
        #[structopt(
            long,
            short("w"),
            env = "THEVAULTPASSFILE",
            parse(from_os_str),
            help = "Path to file storing the decryption password"
        )]
        password_file: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Opt::from_args();
    match opts {
        Opt::Decrypt {
            file,
            outfile,
            password,
            password_file,
            inplace,
        } => {
            vault_decrypt(
                file.as_deref(),
                outfile.as_deref(),
                password,
                password_file,
                inplace,
            )
            .await
        }
        Opt::Edit {
            file,
            password,
            password_file,
        } => vault_edit(file.as_ref(), password, password_file).await,
        Opt::Encrypt {
            file,
            outfile,
            password,
            password_file,
            inplace,
            base64,
        } => {
            vault_encrypt(
                file.as_deref(),
                outfile.as_deref(),
                password,
                password_file,
                inplace,
                base64,
            )
            .await
        }
        Opt::View {
            file,
            password,
            password_file,
        } => vault_view(file.as_ref(), password, password_file).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::{Command, Stdio};

    #[test]
    fn from_stdin() {
        let mut encrypt_cmd = Command::new("./target/release/thevault")
            .env("THEVAULTPASS", "password")
            .arg("encrypt")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("failed to spawn child process, try to run: cargo build --release");
        let plaintext = r#"Encrypt this text!"#.as_bytes();
        {
            let stdin = encrypt_cmd.stdin.as_mut().expect("failed to open stdin");
            stdin
                .write_all(plaintext)
                .expect("failed to write to stdin");
        }
        let encrypt_output = encrypt_cmd
            .wait_with_output()
            .expect("failed to read from stdout");
        let ciphertext = encrypt_output.stdout;
        assert_ne!(ciphertext, plaintext);

        let mut decrypt_cmd = Command::new("./target/release/thevault")
            .env("THEVAULTPASS", "password")
            .arg("decrypt")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("failed to spawn child process, try to run: cargo build --release");
        {
            let stdin = decrypt_cmd.stdin.as_mut().expect("failed to open stdin");
            stdin
                .write_all(&ciphertext)
                .expect("failed to write to stdin");
        }
        let decrypt_output = decrypt_cmd
            .wait_with_output()
            .expect("failed to read from stdout");
        let decrypted_text = decrypt_output.stdout;
        assert_eq!(decrypted_text, plaintext);
    }

    #[tokio::test]
    async fn from_file() {
        let mut file_input =
            tempfile::NamedTempFile::new().expect("could not create temp input file");
        let file_output =
            tempfile::NamedTempFile::new().expect("could not create temp output file");
        let file_decrypted =
            tempfile::NamedTempFile::new().expect("could not create temp decrypted file");

        let password = "password".to_string();
        let plaintext = b"this is supposed to be encrypted";
        file_input
            .write_all(plaintext)
            .expect("could not write to infile");

        vault_encrypt(
            Some(file_input.path()),
            Some(file_output.path()),
            Some(password.clone()),
            None,
            false,
            true,
        )
        .await
        .expect("error vault encryption");

        let ciphertext = fs::read(&file_output).expect("could not read ciphertext from outfile");
        assert_ne!(ciphertext, plaintext);

        vault_decrypt(
            Some(file_output.path()),
            Some(file_decrypted.path()),
            Some(password),
            None,
            false,
        )
        .await
        .expect("error vault encryption");

        let decrypted_text = fs::read(file_decrypted).expect("could not read from decrypted file");
        assert_eq!(decrypted_text, plaintext);
    }
}
