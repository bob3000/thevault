use secstr::SecVec;
use sodiumoxide::crypto::{pwhash, secretbox};
use std::io;
use thiserror::Error;

pub const HEADER_LEN: usize = 56;

#[derive(Debug, Clone)]
pub struct Crypto {
    key: secretbox::Key,
    nonce: secretbox::Nonce,
    salt: pwhash::Salt,
}

impl Crypto {
    pub async fn new_encrypter(password: &SecVec<u8>) -> anyhow::Result<Self> {
        let salt = pwhash::gen_salt();
        let nonce = secretbox::gen_nonce();
        let key = derrive_key(&password, salt);
        Ok(Crypto { key, nonce, salt })
    }

    pub async fn new_decrypter(
        password: &SecVec<u8>,
        salt_slice: Vec<u8>,
        nonce_slice: Vec<u8>,
    ) -> anyhow::Result<Self, DecryptionError> {
        let salt = pwhash::Salt::from_slice(&salt_slice[..]).unwrap();
        let nonce = secretbox::Nonce::from_slice(&nonce_slice[..]).unwrap();
        let key = derrive_key(&password, salt);
        Ok(Crypto { key, nonce, salt })
    }

    pub async fn encrypt(&self, plaintext: SecVec<u8>) -> Vec<u8> {
        secretbox::seal(&plaintext[..], &self.nonce, &self.key)
    }

    pub async fn decrypt(&self, cipher_package: &[u8]) -> Result<SecVec<u8>, DecryptionError> {
        let plaintext = secretbox::open(&cipher_package, &self.nonce, &self.key).unwrap();
        Ok(SecVec::new(plaintext))
    }

    pub fn header(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.append(&mut self.salt[..].to_vec());
        header.append(&mut self.nonce[..].to_vec());
        header
    }
}

fn derrive_key(password: &SecVec<u8>, salt: pwhash::Salt) -> secretbox::Key {
    let mut key = secretbox::Key([0; secretbox::KEYBYTES]);
    {
        let secretbox::Key(ref mut kb) = key;
        pwhash::derive_key(
            kb,
            &password.unsecure()[..],
            &salt,
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        )
        .unwrap();
    }
    key
}

// let salt = header[..32].to_vec();
// let nonce = header[32..56].to_vec();
pub fn split_header(header: &[u8]) -> Result<(&[u8], &[u8]), DecryptionError> {
    if header.len() != HEADER_LEN {
        return Err(DecryptionError::InvalidCipherLength);
    }
    Ok((&header[..32], &header[32..]))
}

#[derive(Error, Debug)]
pub enum DecryptionError {
    #[error("cipher text does not contain all necessary elements")]
    InvalidCipherLength,
    #[error("Improper header length")]
    HeaderError(#[from] io::Error),
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn successful_encrypt_decrypt() {
        let password = SecVec::from("0123456789ABCDEF0123456789ABCDEF");
        let message = SecVec::from("this is a very secret message!!!");
        let mut cipher_package = Cursor::new(Vec::new());

        // encrypt
        let c = Crypto::new_encrypter(&password)
            .await
            .expect("error creating encrypter");
        cipher_package.write_all(&c.header()).await.unwrap();

        let ciphertext = c.encrypt(message.clone()).await;
        assert_ne!(&message.unsecure()[..], &ciphertext[..]);
        cipher_package
            .write_u32(ciphertext.len() as u32)
            .await
            .unwrap();
        cipher_package.write_all(&ciphertext).await.unwrap();
        cipher_package.set_position(0);

        // decrypt
        let mut header = [0u8; HEADER_LEN];
        cipher_package.read(&mut header).await.unwrap();
        let (salt, init_vec) = split_header(&header).unwrap();
        let d = Crypto::new_decrypter(&password, salt.to_vec(), init_vec.to_vec())
            .await
            .expect("error creating crypto from cipher package");

        let chunk_size = cipher_package.read_u32().await.unwrap();
        let mut buf: Vec<u8> = Vec::with_capacity(chunk_size as usize);
        cipher_package.read_buf(&mut buf).await.unwrap();
        let decrypted_text = d.decrypt(&buf).await.unwrap();
        assert_eq!(&message.unsecure(), &decrypted_text.unsecure());
    }
}
