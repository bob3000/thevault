use anyhow::Context;
use secstr::SecVec;
use std::fs;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::fs as tokio_fs;
use tokio::io as tokio_io;
use tokio::io::{AsyncRead, AsyncWrite};

// This function is searches for the encryption / decryption password on
// different places in the following order:
// 1. command line argument or environment variable
// 2. password file
// 3. read from TTY
pub fn get_password(
    password: &mut Option<String>,
    password_file: &Option<PathBuf>,
) -> anyhow::Result<SecVec<u8>> {
    // First option - user entered a password as a command line option
    if password.is_some() {
        return Ok(SecVec::from(password.take().unwrap()));
    };

    // Second option - user provided a password file
    let mut pass = String::new();
    match password_file {
        Some(pf) => {
            let mut pass_file = fs::File::open(pf)?;
            pass_file.read_to_string(&mut pass)?;
        }
        None => {
            pass = rpassword::read_password_from_tty(Some("Password: "))?;
        }
    };
    Ok(SecVec::from(pass.trim().to_owned()))
}

pub async fn get_reader(
    file: Option<&Path>,
) -> anyhow::Result<Box<dyn AsyncRead + Unpin + Send + Sync>> {
    match file {
        Some(path) => {
            let f = tokio_fs::File::open(path)
                .await
                .with_context(|| format!("failed to open input file {}", path.to_str().unwrap()))?;
            Ok(Box::new(f))
        }
        None => Ok(Box::new(tokio_io::stdin())),
    }
}

pub async fn get_writer(
    output: Option<&Path>,
) -> anyhow::Result<Box<dyn AsyncWrite + Unpin + Send + Sync>> {
    match output {
        Some(path) => {
            let f = tokio_fs::File::create(path).await.with_context(|| {
                format!("failed to create output file {}", path.to_str().unwrap())
            })?;
            Ok(Box::new(f))
        }
        None => Ok(Box::new(tokio_io::stdout())),
    }
}

// Look up if an external command is available and if yes return it's full path
pub fn which(cmd: &str) -> anyhow::Result<String> {
    let output = Command::new("which").arg(cmd).output()?;
    if output.status.success() {
        let path = String::from_utf8(output.stdout)?.trim().to_string();
        return Ok(path);
    }
    let err = String::from_utf8(output.stderr)?;
    Err(anyhow::anyhow!(err))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::SeekFrom;

    #[test]
    fn password_from_cmd() {
        let pw = get_password(&mut Some("password".to_string()), &None).unwrap();
        assert_eq!(pw.unsecure(), b"password");
    }

    #[test]
    fn password_from_file() {
        let mut tmp_file = tempfile::NamedTempFile::new().expect("could not create temp file");
        write!(tmp_file, "password").expect("could not write to temp file");
        tmp_file.seek(SeekFrom::Start(0)).unwrap();
        let pw = get_password(&mut None, &Some(tmp_file.path().to_path_buf())).unwrap();
        assert_eq!(pw.unsecure(), b"password");
    }

    #[test]
    fn which_less() {
        assert!(which("less")
            .unwrap_or_else(|_| "nope".into())
            .ends_with("/less"));
        assert!(which("lesssss")
            .unwrap_err()
            .to_string()
            .starts_with("which: no"));
    }
}
