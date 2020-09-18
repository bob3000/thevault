use anyhow::Context;
use async_trait::async_trait;
use futures::future::Future;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::sync::Mutex;

// Size of a chunks being read from the input source
const CHUNK_SIZE: u64 = 4096;
const BASE64_MARKER: &[u8] = b"THEVAULTB64";

struct ChunkReader;
#[async_trait]
trait ChunkReading {
    async fn read_plain_chunk(
        reader: Arc<Mutex<Box<dyn AsyncRead + Unpin + Send + Sync>>>,
    ) -> anyhow::Result<Option<Vec<u8>>>;

    async fn read_encrypted_chunk(
        reader: Arc<Mutex<Box<dyn AsyncRead + Unpin + Send + Sync>>>,
    ) -> anyhow::Result<Option<Vec<u8>>>;

    async fn read_encrypted_b64_chunk(
        reader: Arc<Mutex<Box<dyn AsyncRead + Unpin + Send + Sync>>>,
    ) -> anyhow::Result<Option<Vec<u8>>>;
}

#[async_trait]
impl ChunkReading for ChunkReader {
    async fn read_plain_chunk(
        reader: Arc<Mutex<Box<dyn AsyncRead + Unpin + Send + Sync>>>,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let chunk_size: u64 = CHUNK_SIZE;
        let mut buf: Vec<u8> = Vec::with_capacity(chunk_size as usize);
        let bytes_read = reader.lock().await.read_buf(&mut buf).await?;
        if bytes_read > 0 {
            Ok(Some(buf.to_vec()))
        } else {
            Ok(None)
        }
    }

    async fn read_encrypted_chunk(
        reader: Arc<Mutex<Box<dyn AsyncRead + Unpin + Send + Sync>>>,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let chunk_size = match reader.lock().await.read_u32().await {
            Ok(n) => n,
            Err(_) => return Ok(None),
        };
        let mut buf: Vec<u8> = Vec::with_capacity(chunk_size as usize);
        // now reading the actual chunk
        let bytes_read = reader
            .lock()
            .await
            .read_buf(&mut buf)
            .await
            .with_context(|| format!("Error reading encrypted file"))?;
        if bytes_read < chunk_size as usize {
            return Err(anyhow::anyhow!("could not read entire data chunk"));
        }
        if bytes_read > 0 {
            Ok(Some(buf))
        } else {
            Ok(None)
        }
    }

    async fn read_encrypted_b64_chunk(
        reader: Arc<Mutex<Box<dyn AsyncRead + Unpin + Send + Sync>>>,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        match Self::read_encrypted_chunk(reader).await? {
            Some(chunk) => {
                let plain = base64::decode(chunk).unwrap();
                Ok::<Option<Vec<u8>>, anyhow::Error>(Some(plain))
            }
            None => Ok::<Option<Vec<u8>>, anyhow::Error>(None),
        }
    }
}

struct ChunkWriter;
#[async_trait]
trait ChunkWriting {
    async fn write_plain_chunk(
        writer: Arc<Mutex<Box<dyn AsyncWrite + Unpin + Send + Sync>>>,
        chunk: Vec<u8>,
    ) -> anyhow::Result<()>;

    async fn write_encrypted_chunk(
        writer: Arc<Mutex<Box<dyn AsyncWrite + Unpin + Send + Sync>>>,
        chunk: Vec<u8>,
    ) -> anyhow::Result<()>;

    async fn write_encrypted_b64_chunk(
        writer: Arc<Mutex<Box<dyn AsyncWrite + Unpin + Send + Sync>>>,
        chunk: Vec<u8>,
    ) -> anyhow::Result<()>;
}

#[async_trait]
impl ChunkWriting for ChunkWriter {
    async fn write_plain_chunk(
        writer: Arc<Mutex<Box<dyn AsyncWrite + Unpin + Send + Sync>>>,
        chunk: Vec<u8>,
    ) -> anyhow::Result<()> {
        writer.lock().await.write_all(&chunk).await?;
        Ok(())
    }

    async fn write_encrypted_chunk(
        writer: Arc<Mutex<Box<dyn AsyncWrite + Unpin + Send + Sync>>>,
        chunk: Vec<u8>,
    ) -> anyhow::Result<()> {
        writer.lock().await.write_u32(chunk.len() as u32).await?;
        writer.lock().await.write_all(&chunk).await?;
        Ok(())
    }

    async fn write_encrypted_b64_chunk(
        writer: Arc<Mutex<Box<dyn AsyncWrite + Unpin + Send + Sync>>>,
        chunk: Vec<u8>,
    ) -> anyhow::Result<()> {
        let chunk = base64::encode(chunk).as_bytes().to_vec();
        ChunkWriter::write_encrypted_chunk(writer, chunk).await
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Action {
    Decrypt,
    DecryptB64,
    Encrypt,
    EncryptB64,
}

// Basically all functionality of the program requires three steps
// 1. reading from a file or stdin
// 2. apply a function on the data (encrypt or decrypt)
// 3. write to a file or stdout
// This function encapsulates this reoccurring procedure
pub async fn read_process_write<'a, F: Send + Sync + 'static, R: Send + Sync + 'static>(
    reader: Box<dyn AsyncRead + Unpin + Send + Sync>,
    writer: Box<dyn AsyncWrite + Unpin + Send + Sync>,
    action: Action,
    mut fn_process: F,
) -> anyhow::Result<Action>
where
    F: FnMut(Vec<u8>) -> R,
    R: Future<Output = anyhow::Result<Vec<u8>>> + Send + Sync,
{
    let writer = Arc::new(Mutex::new(writer));
    let reader = Arc::new(Mutex::new(reader));

    let mut action_performed = action;
    let fn_read = match action {
        Action::Decrypt => {
            let mut marker = Vec::with_capacity(BASE64_MARKER.len());
            reader.lock().await.read_buf(&mut marker).await?;
            if marker == BASE64_MARKER {
                action_performed = Action::DecryptB64;
                ChunkReader::read_encrypted_b64_chunk
            } else {
                ChunkReader::read_encrypted_chunk
            }
        }
        Action::DecryptB64 => ChunkReader::read_encrypted_b64_chunk,
        Action::Encrypt => ChunkReader::read_plain_chunk,
        Action::EncryptB64 => ChunkReader::read_plain_chunk,
    };

    let fn_write = match action {
        Action::Decrypt => ChunkWriter::write_plain_chunk,
        Action::DecryptB64 => ChunkWriter::write_plain_chunk,
        Action::Encrypt => {
            writer
                .lock()
                .await
                .write_all(&vec![0; BASE64_MARKER.len()])
                .await
                .with_context(|| format!("failed to write to output"))?;
            ChunkWriter::write_encrypted_chunk
        }
        Action::EncryptB64 => {
            writer
                .lock()
                .await
                .write_all(BASE64_MARKER)
                .await
                .with_context(|| format!("failed to write to output"))?;
            ChunkWriter::write_encrypted_b64_chunk
        }
    };

    let (mut tx, mut rx) = mpsc::channel(100);
    // start processing the file
    tokio::spawn(async move {
        while let Some(chunk) = fn_read(Arc::clone(&reader)).await? {
            if let Err(_) = tx.send(fn_process(chunk)).await {
                return Err(anyhow::anyhow!("could not write to disk"));
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    // start writing the results while still processing
    while let Some(chunk_in_progress) = rx.recv().await {
        fn_write(Arc::clone(&writer), chunk_in_progress.await?).await?;
    }

    Ok(action_performed)
}
