use anyhow::Context;
use secstr::{SecStr, SecVec};
use std::env;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
enum Opt {
    Decrypt {
        #[structopt(long, short, parse(from_os_str))]
        file: Option<PathBuf>,
        #[structopt(long, short, parse(from_os_str))]
        outfile: Option<PathBuf>,
        #[structopt(long, short)]
        password: Option<String>,
        #[structopt(long, short("w"), parse(from_os_str))]
        password_file: Option<PathBuf>,
        #[structopt(long, short)]
        inplace: bool,
    },
    Edit {
        #[structopt(long, short, parse(from_os_str))]
        file: Option<PathBuf>,
        #[structopt(long, short, parse(from_os_str))]
        outfile: Option<PathBuf>,
        #[structopt(long, short)]
        password: Option<String>,
        #[structopt(long, short("w"), parse(from_os_str))]
        password_file: Option<PathBuf>,
        #[structopt(long, short)]
        inplace: bool,
    },
    Encrypt {
        #[structopt(long, short, parse(from_os_str))]
        file: Option<PathBuf>,
        #[structopt(long, short, parse(from_os_str))]
        outfile: Option<PathBuf>,
        #[structopt(long, short)]
        password: Option<String>,
        #[structopt(long, short("w"), parse(from_os_str))]
        password_file: Option<PathBuf>,
        #[structopt(long, short)]
        inplace: bool,
    },
    View {
        #[structopt(long, short, parse(from_os_str))]
        file: PathBuf,
        #[structopt(long, short)]
        password: Option<String>,
        #[structopt(long, short("w"), parse(from_os_str))]
        password_file: Option<PathBuf>,
    },
}

fn get_password(password: Option<&str>, password_file: Option<File>) -> anyhow::Result<String> {
    // First option - user entered a password as a command line option
    if password.is_some() {
        return Ok(password.unwrap().to_string());
    };

    // Second option - user set an environment variable
    let env_var_name = "THEVAULTPASS";
    if env::var(env_var_name).is_ok() {
        return Ok(env::var(env_var_name).unwrap().to_owned());
    }

    // Third option - user provided a password file
    let mut pass = String::new();
    match password_file {
        Some(mut pf) => {
            pf.read_to_string(&mut pass)?;
        }
        None => {
            pass = rpassword::read_password_from_tty(Some("Password: "))?;
        }
    };
    Ok(pass)
}

fn read_process_write<F>(
    file: Option<&Path>,
    outfile: Option<&Path>,
    inplace: bool,
    mut fn_process: F,
) -> anyhow::Result<()>
where
    F: FnMut(&Vec<u8>) -> anyhow::Result<Vec<u8>>,
{
    let do_inplace = if file == outfile { true } else { inplace };
    let mut buf: Vec<u8> = Vec::new();
    match file {
        Some(path) => File::open(path.clone())
            .with_context(|| format!("failed to open input file {}", path.to_str().unwrap()))?
            .read_to_end(&mut buf)
            .unwrap(),
        None => io::stdin().read_to_end(&mut buf).unwrap(),
    };
    let processed = fn_process(&buf)?;
    match outfile {
        Some(path) if !do_inplace => {
            let mut file = File::create(path.clone()).with_context(|| {
                format!("failed to create output file {}", path.to_str().unwrap())
            })?;
            file.write_all(&processed)?;
            file.sync_all()?;
        }
        None => {
            if do_inplace && file.is_some() {
                let path = file.unwrap();
                let mut file = File::create(path.clone()).with_context(|| {
                    format!("failed to create output file {}", path.to_str().unwrap())
                })?;
                file.write_all(&processed)?;
                file.sync_all()?;
            } else {
                io::stdout().write_all(&processed)?;
            }
        }
        _ => {}
    };
    Ok(())
}

fn vault_decrypt(
    file_input: Option<&Path>,
    file_output: Option<&Path>,
    password: Option<&str>,
    password_file: Option<&Path>,
    inplace: bool,
) -> anyhow::Result<()> {
    let pass_file = match password_file {
        Some(pf) => File::open(pf).ok(),
        None => None,
    };
    let pass = get_password(password, pass_file)?;
    read_process_write(file_input, file_output, inplace, |cipher_package| {
        let plaintext = thevault::decrypt(SecStr::from(pass.clone()), cipher_package)?
            .unsecure()
            .to_vec();
        Ok(plaintext)
    })?;
    Ok(())
}

fn vault_edit(
    file_input: Option<&Path>,
    file_output: Option<&Path>,
    password: Option<&str>,
    password_file: Option<&Path>,
    inplace: bool,
) -> anyhow::Result<()> {
    let pass_file = match password_file {
        Some(pf) => File::open(pf).ok(),
        None => None,
    };
    let pass = get_password(password, pass_file)?;
    read_process_write(file_input, file_output, inplace, |cipher_package| {
        let plaintext = thevault::decrypt(SecStr::from(pass.clone()), cipher_package)?
            .unsecure()
            .to_vec();

        let editor_cmd = env::var("EDITOR").unwrap_or("less".to_string());
        let editor = which(&editor_cmd).with_context(|| format!("no pager was found"))?;

        let mut tmp_file = tempfile::NamedTempFile::new()?;
        tmp_file.write_all(&plaintext)?;

        let mut editor_process = Command::new(editor)
            .arg(tmp_file.path())
            .spawn()
            .with_context(|| format!("error while spawning pager {}", editor_cmd))?;
        editor_process.wait()?;

        let mut changed_text: Vec<u8> = Vec::new();
        tmp_file.reopen()?.read_to_end(&mut changed_text)?;

        let cipher_package = thevault::encrypt(
            SecStr::from(pass.clone()),
            SecVec::from(changed_text.to_vec()),
        );
        drop(tmp_file);

        Ok(cipher_package)
    })?;
    Ok(())
}

fn vault_encrypt(
    file_input: Option<&Path>,
    file_output: Option<&Path>,
    password: Option<&str>,
    password_file: Option<&Path>,
    inplace: bool,
) -> anyhow::Result<()> {
    let pass_file = match password_file {
        Some(pf) => File::open(pf).ok(),
        None => None,
    };
    let pass = get_password(password, pass_file)?;
    read_process_write(file_input, file_output, inplace, |cipher_package| {
        let ciphertext = thevault::encrypt(
            SecStr::from(pass.clone()),
            SecVec::new(cipher_package.to_vec()),
        );
        Ok(ciphertext)
    })?;
    Ok(())
}

fn vault_view(
    file_input: &Path,
    password: Option<&str>,
    password_file: Option<&Path>,
) -> anyhow::Result<()> {
    let pass_file = match password_file {
        Some(pf) => File::open(pf).ok(),
        None => None,
    };
    let pass = get_password(password, pass_file)?;
    read_process_write(Some(file_input), None, false, |cipher_package| {
        let plain_bytes = thevault::decrypt(SecStr::from(pass.clone()), cipher_package)?
            .unsecure()
            .to_vec();
        let plaintext = String::from_utf8(plain_bytes)?;

        let pager_cmd = env::var("PAGER").unwrap_or("less".to_string());
        let pager = which(&pager_cmd).with_context(|| format!("no pager was found"))?;

        let mut pager_process = Command::new(pager)
            .stdin(Stdio::piped())
            .spawn()
            .with_context(|| format!("error while spawning pager {}", pager_cmd))?;

        let pager_stdin = pager_process.stdin.as_mut().unwrap();
        write!(pager_stdin, "{}", plaintext)?;
        pager_process.wait()?;
        Ok("".as_bytes().to_vec())
    })?;
    Ok(())
}

fn which(cmd: &str) -> anyhow::Result<String> {
    let output = Command::new("which").arg(cmd).output()?;
    if output.status.success() {
        let path = String::from_utf8(output.stdout)?.trim().to_string();
        return Ok(path);
    }
    let err = String::from_utf8(output.stderr)?;
    Err(anyhow::anyhow!(err))
}

fn main() -> anyhow::Result<()> {
    match Opt::from_args() {
        Opt::Decrypt {
            file,
            outfile,
            password,
            password_file,
            inplace,
        } => vault_decrypt(
            file.as_deref(),
            outfile.as_deref(),
            password.as_deref(),
            password_file.as_deref(),
            inplace,
        ),
        Opt::Edit {
            file,
            outfile,
            password,
            password_file,
            inplace,
        } => vault_edit(
            file.as_deref(),
            outfile.as_deref(),
            password.as_deref(),
            password_file.as_deref(),
            inplace,
        ),
        Opt::Encrypt {
            file,
            outfile,
            password,
            password_file,
            inplace,
        } => vault_encrypt(
            file.as_deref(),
            outfile.as_deref(),
            password.as_deref(),
            password_file.as_deref(),
            inplace,
        ),
        Opt::View {
            file,
            password,
            password_file,
        } => vault_view(file.as_ref(), password.as_deref(), password_file.as_deref()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::SeekFrom;
    use std::process::{Command, Stdio};

    #[test]
    fn password_from_cmd() {
        let pw = get_password(Some("password"), None).unwrap();
        assert_eq!(pw, "password");
    }

    #[test]
    fn password_from_file() {
        let mut tmp_file = tempfile::tempfile().expect("could not create temp file");
        write!(tmp_file, "password").expect("could not write to temp file");
        tmp_file.seek(SeekFrom::Start(0)).unwrap();
        let pw = get_password(None, Some(tmp_file)).unwrap();
        assert_eq!(pw, "password");
    }

    #[test]
    fn password_from_env() {
        env::set_var("THEVAULTPASS", "password");
        let pw = get_password(None, None).unwrap();
        assert_eq!(pw, "password");
    }

    #[test]
    fn password_from_stdin() {
        let pw = get_password(None, None).unwrap();
        assert_eq!(pw, "password");
    }

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

    #[test]
    fn from_file() {
        let mut file_input =
            tempfile::NamedTempFile::new().expect("could not create temp input file");
        let file_output =
            tempfile::NamedTempFile::new().expect("could not create temp output file");
        let file_decrypted =
            tempfile::NamedTempFile::new().expect("could not create temp decrypted file");

        let password = "password";
        let plaintext = "this is supposed to be encrypted";
        file_input
            .write_all(plaintext.as_bytes())
            .expect("could not write to infile");

        vault_encrypt(
            Some(file_input.path()),
            Some(file_output.path()),
            Some(password),
            None,
            false,
        )
        .expect("error vault encryption");

        let ciphertext =
            fs::read_to_string(&file_output).expect("could not read cipertext from outfile");
        assert_ne!(ciphertext, plaintext);

        vault_decrypt(
            Some(file_output.path()),
            Some(file_decrypted.path()),
            Some(password),
            None,
            false,
        )
        .expect("error vault encryption");

        let decrypted_text =
            fs::read_to_string(file_decrypted).expect("could not read from decrypted file");
        assert_eq!(decrypted_text, plaintext);
    }

    #[test]
    fn which_less() {
        assert!(which("less").unwrap_or("nope".into()).ends_with("/less"));
        assert!(which("lesssss")
            .unwrap_err()
            .to_string()
            .starts_with("which: no"));
    }
}
