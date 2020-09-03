use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::process::Command;
// This function is searches for the encryption / decryption password on
// different places in the following order:
// 1. command line argument or environment variable
// 2. password file
// 3. read from TTY
pub fn get_password(
    password: Option<&str>,
    password_file: Option<&Path>,
) -> anyhow::Result<String> {
    // First option - user entered a password as a command line option
    if password.is_some() {
        return Ok(password.unwrap().to_string());
    };

    // Second option - user provided a password file
    let mut pass = String::new();
    match password_file {
        Some(pf) => {
            let mut pass_file = File::open(pf)?;
            pass_file.read_to_string(&mut pass)?;
        }
        None => {
            pass = rpassword::read_password_from_tty(Some("Password: "))?;
        }
    };
    Ok(pass.trim().to_owned())
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
        let pw = get_password(Some("password"), None).unwrap();
        assert_eq!(pw, "password");
    }

    #[test]
    fn password_from_file() {
        let mut tmp_file = tempfile::NamedTempFile::new().expect("could not create temp file");
        write!(tmp_file, "password").expect("could not write to temp file");
        tmp_file.seek(SeekFrom::Start(0)).unwrap();
        let pw = get_password(None, Some(tmp_file.path())).unwrap();
        assert_eq!(pw, "password");
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
