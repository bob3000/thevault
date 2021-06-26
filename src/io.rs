use anyhow::Context;
use async_trait::async_trait;
use futures::future::Future;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::sync::Mutex;

// Size of a chunks being read from the input source
pub const CHUNK_SIZE: u64 = 1024;
pub type BoxAsyncReader = Box<dyn AsyncRead + Unpin + Send + Sync>;
pub type RefAsyncWriter<'a> = &'a mut (dyn AsyncWrite + Unpin + Send + Sync);

struct ChunkReader;
#[async_trait]
trait ChunkReading {
    async fn read_plain_chunk(
        reader: Arc<Mutex<BoxAsyncReader>>,
    ) -> anyhow::Result<Option<Vec<u8>>>;

    async fn read_encrypted_chunk(
        reader: Arc<Mutex<BoxAsyncReader>>,
    ) -> anyhow::Result<Option<Vec<u8>>>;

    async fn read_encrypted_b64_chunk(
        reader: Arc<Mutex<BoxAsyncReader>>,
    ) -> anyhow::Result<Option<Vec<u8>>>;
}

#[async_trait]
impl ChunkReading for ChunkReader {
    async fn read_plain_chunk(
        reader: Arc<Mutex<BoxAsyncReader>>,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let mut buf = vec![0u8; CHUNK_SIZE as usize];
        let bytes_read = reader
            .lock()
            .await
            .read(&mut buf)
            .await
            .with_context(|| "Error reading encrypted file")?;

        if bytes_read == 0 {
            return Ok(None);
        }
        Ok(Some(buf[..bytes_read].to_vec()))
    }

    async fn read_encrypted_chunk(
        reader: Arc<Mutex<BoxAsyncReader>>,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let chunk_size = match reader.lock().await.read_u32().await {
            Ok(n) => n,
            Err(_) => return Ok(None),
        };
        let mut buf: Vec<u8> = vec![0u8; chunk_size as usize];
        // now reading the actual chunk
        let bytes_read = reader
            .lock()
            .await
            .read(&mut buf)
            .await
            .with_context(|| "Error reading encrypted file")?;

        if bytes_read == 0 {
            return Ok(None);
        }
        Ok(Some(buf[..bytes_read].to_vec()))
    }

    async fn read_encrypted_b64_chunk(
        reader: Arc<Mutex<BoxAsyncReader>>,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let mut buf_chunk_len = vec![0u8; 4];
        let bytes_read = reader.lock().await.read(&mut buf_chunk_len).await?;
        if bytes_read == 0 {
            return Ok(None);
        }
        let size_bytes = base64::decode(buf_chunk_len[..bytes_read].to_vec())?;
        let chunk_size: u32 = String::from_utf8(size_bytes)?
            .parse()
            .with_context(|| "failed to read chunk size")?;

        let mut buf: Vec<u8> = vec![0u8; chunk_size as usize];
        // now reading the actual chunk
        let bytes_read = reader
            .lock()
            .await
            .read(&mut buf)
            .await
            .with_context(|| "Error reading encrypted file")?;

        if bytes_read == 0 {
            return Ok(None);
        }
        let plain_chunk = base64::decode(buf[..bytes_read].to_vec())?;
        Ok(Some(plain_chunk))
    }
}

struct ChunkWriter;
#[async_trait]
trait ChunkWriting {
    async fn write_plain_chunk(
        writer: Arc<Mutex<RefAsyncWriter<'_>>>,
        chunk: Vec<u8>,
    ) -> anyhow::Result<()>;

    async fn write_encrypted_chunk(
        writer: Arc<Mutex<RefAsyncWriter<'_>>>,
        chunk: Vec<u8>,
    ) -> anyhow::Result<()>;

    async fn write_encrypted_b64_chunk(
        writer: Arc<Mutex<RefAsyncWriter<'_>>>,
        chunk: Vec<u8>,
    ) -> anyhow::Result<()>;
}

#[async_trait]
impl ChunkWriting for ChunkWriter {
    async fn write_plain_chunk(
        writer: Arc<Mutex<RefAsyncWriter<'_>>>,
        chunk: Vec<u8>,
    ) -> anyhow::Result<()> {
        writer.lock().await.write_all(&chunk).await?;
        Ok(())
    }

    async fn write_encrypted_chunk(
        writer: Arc<Mutex<RefAsyncWriter<'_>>>,
        chunk: Vec<u8>,
    ) -> anyhow::Result<()> {
        writer.lock().await.write_u32(chunk.len() as u32).await?;
        writer.lock().await.write_all(&chunk).await?;
        Ok(())
    }

    async fn write_encrypted_b64_chunk(
        writer: Arc<Mutex<RefAsyncWriter<'_>>>,
        chunk: Vec<u8>,
    ) -> anyhow::Result<()> {
        let b64_chunk = base64::encode(chunk).as_bytes().to_vec();
        let b64_chunk_len = base64::encode(format!("{:02}", b64_chunk.len()));
        writer
            .lock()
            .await
            .write_all(&b64_chunk_len.as_bytes())
            .await?;
        writer.lock().await.write_all(&b64_chunk).await?;
        Ok(())
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
pub async fn read_process_write<F: Send + Sync + 'static, R: Send + Sync + 'static>(
    reader: BoxAsyncReader,
    writer: RefAsyncWriter<'_>,
    action: Action,
    mut fn_process: F,
) -> anyhow::Result<()>
where
    F: FnMut(Vec<u8>) -> R,
    R: Future<Output = anyhow::Result<Vec<u8>>> + Send + Sync,
{
    let writer = Arc::new(Mutex::new(writer));
    let reader = Arc::new(Mutex::new(reader));

    let fn_read = match action {
        Action::Decrypt => ChunkReader::read_encrypted_chunk,
        Action::DecryptB64 => ChunkReader::read_encrypted_b64_chunk,
        Action::Encrypt => ChunkReader::read_plain_chunk,
        Action::EncryptB64 => ChunkReader::read_plain_chunk,
    };

    let fn_write = match action {
        Action::Decrypt => ChunkWriter::write_plain_chunk,
        Action::DecryptB64 => ChunkWriter::write_plain_chunk,
        Action::Encrypt => ChunkWriter::write_encrypted_chunk,
        Action::EncryptB64 => ChunkWriter::write_encrypted_b64_chunk,
    };

    let (mut tx, mut rx) = mpsc::channel(100);
    // start processing the file
    tokio::spawn(async move {
        while let Some(chunk) = fn_read(Arc::clone(&reader)).await? {
            if tx.send(fn_process(chunk)).await.is_err() {
                return Err(anyhow::anyhow!("could not write to disk"));
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    // start writing the results while still processing
    while let Some(chunk_in_progress) = rx.recv().await {
        let chunk = chunk_in_progress.await?;
        fn_write(Arc::clone(&writer), chunk).await?;
    }

    Ok(())
}
