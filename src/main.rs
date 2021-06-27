/*!
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
*/

mod helper;
mod io;
mod sodium;
use anyhow::Context;
use indicatif::{ProgressBar, ProgressStyle};
use secstr::SecVec;
use std::env;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use structopt::StructOpt;
use tokio::fs as tokio_fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

const BASE64_MARKER: &[u8] = b"THEVAULTB64";

fn make_progressbar(
    verbose: bool,
    file_input: Option<&Path>,
    message: Option<&'static str>,
) -> Arc<ProgressBar> {
    let num_blocks = helper::filesize(file_input) / io::CHUNK_SIZE;
    if verbose && num_blocks > 0 {
        let bar = Arc::new(ProgressBar::new(num_blocks));
        bar.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>7}/{len:7} {msg}")
                .progress_chars("=>-"),
        );
        return bar;
    } else if verbose && num_blocks == 0 {
        let bar = Arc::new(ProgressBar::new_spinner());
        bar.set_style(
            ProgressStyle::default_spinner()
                // For more spinners check out the cli-spinners project:
                // https://github.com/sindresorhus/cli-spinners/blob/master/spinners.json
                .tick_strings(&[
                    "▹▹▹▹▹",
                    "▸▹▹▹▹",
                    "▹▸▹▹▹",
                    "▹▹▸▹▹",
                    "▹▹▹▸▹",
                    "▹▹▹▹▸",
                    "▪▪▪▪▪",
                ])
                .template("{spinner:.blue} {msg}"),
        );
        if let Some(msg) = message {
            bar.set_message(msg);
        }
        return bar;
    } else {
        return Arc::new(ProgressBar::hidden());
    }
}

async fn fn_decrypt(
    progress_bar: Arc<ProgressBar>,
    mut reader: io::BoxAsyncReader,
    mut writer: io::RefAsyncWriter<'_>,
    pass: SecVec<u8>,
    ignore_errors: bool,
) -> anyhow::Result<io::Action> {
    let mut marker = [0u8; BASE64_MARKER.len()];
    let bytes_read = reader.read(&mut marker).await?;
    if bytes_read == 0 {
        return Err(anyhow::anyhow!(
            "input source seems to be empty, aborting ..."
        ));
    }
    let (action, header) = if marker == BASE64_MARKER {
        let mut buf_header_len = vec![0u8; 4];
        let bytes_read = reader.read(&mut buf_header_len).await?;
        let header_bytes = base64::decode(buf_header_len[..bytes_read].to_vec())?;
        let header_len: u32 = String::from_utf8(header_bytes)?
            .parse()
            .with_context(|| "failed to read header size")?;
        let mut buf_header = vec![0u8; header_len as usize];
        let bytes_read = reader.read(&mut buf_header).await?;
        let header = base64::decode(buf_header[..bytes_read].to_vec())?;
        (io::Action::DecryptB64, header)
    } else {
        let header_len = reader.read_u32().await?;
        let mut buf_header = vec![0u8; header_len as usize];
        let bytes_read = reader.read(&mut buf_header).await?;
        (io::Action::Decrypt, buf_header[..bytes_read].to_vec())
    };
    let (salt, init_vec) = sodium::split_header(&header)?;
    let decrypter =
        Arc::new(sodium::Crypto::new_decrypter(&pass, salt.to_vec(), init_vec.to_vec()).await?);

    let finish_bar = Arc::clone(&progress_bar);
    io::read_process_write(reader, &mut writer, action, move |cipher_package| {
        let cpt = Arc::clone(&decrypter);
        let bar = Arc::clone(&progress_bar);
        bar.inc(1);
        async move {
            match cpt.decrypt(&cipher_package).await {
                Ok(s) => Ok::<Vec<u8>, anyhow::Error>(s.unsecure().to_vec()),
                Err(e) => {
                    eprintln!("bad block no {}", bar.position(),);
                    eprintln!("block size {}", io::CHUNK_SIZE);
                    if ignore_errors {
                        Ok::<Vec<u8>, anyhow::Error>(vec![0])
                    } else {
                        eprintln!("aborting");
                        Err(anyhow::anyhow!(e))
                    }
                }
            }
        }
    })
    .await?;
    finish_bar.finish();
    Ok(action)
}

// sub commands
async fn vault_decrypt<'a>(
    file_input: Option<&'a Path>,
    file_output: Option<&'a Path>,
    mut password: Option<String>,
    password_file: Option<PathBuf>,
    verbose: bool,
    ignore_errors: bool,
) -> anyhow::Result<io::Action> {
    let pass = helper::get_password(&mut password, &password_file).unwrap();
    let reader = helper::get_reader(file_input).await?;
    let mut writer = helper::get_writer(file_output).await?;
    let progress_bar = make_progressbar(verbose, file_input, Some("decrypting"));
    match fn_decrypt(
        Arc::clone(&progress_bar),
        reader,
        &mut writer,
        pass,
        ignore_errors,
    )
    .await
    {
        Ok(action_performed) => Ok(action_performed),
        Err(_) => {
            std::process::exit(1);
        }
    }
}

async fn vault_edit(
    file_input: &'_ Path,
    password: Option<String>,
    password_file: Option<PathBuf>,
    verbose: bool,
) -> anyhow::Result<io::Action> {
    let editor_cmd = env::var("EDITOR").unwrap_or_else(|_| "vim".to_string());
    let editor = helper::which(&editor_cmd).with_context(|| "no pager was found")?;
    let tmp_file = tempfile::NamedTempFile::new()?;

    let action_performed = vault_decrypt(
        Some(file_input),
        Some(tmp_file.path()),
        password.clone(),
        password_file.clone(),
        verbose,
        false,
    )
    .await?;

    let editor_process = Command::new(editor)
        .arg(tmp_file.path())
        .spawn()
        .with_context(|| format!("error while spawning pager {}", editor_cmd))?;
    editor_process.wait_with_output().await?;

    let b64 = action_performed == io::Action::DecryptB64;
    let action_performed = vault_encrypt(
        Some(tmp_file.path()),
        Some(file_input),
        password,
        password_file,
        b64,
        verbose,
    )
    .await?;
    Ok(action_performed)
}

async fn vault_encrypt<'a>(
    file_input: Option<&'a Path>,
    file_output: Option<&'a Path>,
    mut password: Option<String>,
    password_file: Option<PathBuf>,
    base64: bool,
    verbose: bool,
) -> anyhow::Result<io::Action> {
    let pass = helper::get_password(&mut password, &password_file).unwrap();
    let reader = helper::get_reader(file_input).await?;
    let mut writer = helper::get_writer(file_output).await?;
    let encrypter = Arc::new(sodium::Crypto::new_encrypter(&pass).await?);

    // write header
    let encoding = if base64 {
        writer
            .write_all(BASE64_MARKER)
            .await
            .with_context(|| "could not write to output, aborting ...")?;
        let header = base64::encode(encrypter.header());
        let header_len = base64::encode(format!("{:02}", header.len()));
        writer.write_all(header_len.as_bytes()).await?;
        writer.write_all(header.as_bytes()).await?;
        io::Action::EncryptB64
    } else {
        writer
            .write_all(&vec![0u8; BASE64_MARKER.len()])
            .await
            .with_context(|| "could not write to output, aborting ...")?;
        writer.write_u32(encrypter.header().len() as u32).await?;
        writer.write_all(&encrypter.header()).await?;
        io::Action::Encrypt
    };

    let progress_bar = make_progressbar(verbose, file_input, Some("encrypting"));
    let finish_bar = Arc::clone(&progress_bar);
    // start data processing
    io::read_process_write(reader, &mut writer, encoding, move |plaintext| {
        let cpt = Arc::clone(&encrypter);
        let bar = Arc::clone(&progress_bar);
        bar.inc(1);
        async move {
            let ciphertext = cpt.encrypt(SecVec::new(plaintext.to_vec())).await;
            Ok::<Vec<u8>, anyhow::Error>(ciphertext)
        }
    })
    .await?;
    finish_bar.finish();
    Ok(encoding)
}

async fn vault_view(
    file_input: &'_ Path,
    mut password: Option<String>,
    password_file: Option<PathBuf>,
    verbose: bool,
) -> anyhow::Result<io::Action> {
    let pass = helper::get_password(&mut password, &password_file).unwrap();
    let pager_cmd = env::var("PAGER").unwrap_or_else(|_| "less".to_string());
    let pager = helper::which(&pager_cmd).with_context(|| "no pager was found")?;
    let mut pager_process = Command::new(pager)
        .stdin(Stdio::piped())
        .spawn()
        .with_context(|| format!("error while spawning pager {}", pager_cmd))?;

    let reader = tokio_fs::File::open(file_input)
        .await
        .with_context(|| format!("failed to open input file {}", file_input.to_str().unwrap()))?;
    let mut writer = &mut pager_process.stdin.as_mut().unwrap();

    let progress_bar = make_progressbar(verbose, Some(file_input), Some("decrypting"));
    let action_performed =
        fn_decrypt(progress_bar, Box::new(reader), &mut writer, pass, false).await?;
    pager_process.wait_with_output().await?;
    Ok(action_performed)
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
        #[structopt(long, short("v"), help = "Verbose output")]
        verbose: bool,
        #[structopt(long, short("i"), help = "Verbose output")]
        ignore_errors: bool,
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
        #[structopt(long, short("v"), help = "Verbose output")]
        verbose: bool,
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
            help = "Write out the encrypted message as base64 encoded string"
        )]
        base64: bool,
        #[structopt(long, short("v"), help = "Verbose output")]
        verbose: bool,
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
        #[structopt(long, short("v"), help = "Verbose output")]
        verbose: bool,
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
            verbose,
            ignore_errors,
        } => {
            vault_decrypt(
                file.as_deref(),
                outfile.as_deref(),
                password,
                password_file,
                verbose,
                ignore_errors,
            )
            .await?
        }
        Opt::Edit {
            file,
            password,
            password_file,
            verbose,
        } => vault_edit(file.as_ref(), password, password_file, verbose).await?,
        Opt::Encrypt {
            file,
            outfile,
            password,
            password_file,
            base64,
            verbose,
        } => {
            vault_encrypt(
                file.as_deref(),
                outfile.as_deref(),
                password,
                password_file,
                base64,
                verbose,
            )
            .await?
        }
        Opt::View {
            file,
            password,
            password_file,
            verbose,
        } => vault_view(file.as_ref(), password, password_file, verbose).await?,
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
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
        let plaintext = b"Encrypt this text!";
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
            true,
            false,
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
            false,
        )
        .await
        .expect("error vault encryption");

        let decrypted_text = fs::read(file_decrypted).expect("could not read from decrypted file");
        assert_eq!(decrypted_text, plaintext);
    }
}
