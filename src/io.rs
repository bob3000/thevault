use anyhow::Context;
use async_trait::async_trait;
use futures::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::{self, File};
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

struct ChunkReader;
#[async_trait]
trait ChunkReading {
    async fn read_plain_chunk(
        reader: Arc<Mutex<Box<dyn AsyncRead + Unpin + Send + Sync>>>,
    ) -> anyhow::Result<Option<Vec<u8>>>;

    async fn read_encrypted_chunk(
        reader: Arc<Mutex<Box<dyn AsyncRead + Unpin + Send + Sync>>>,
    ) -> anyhow::Result<Option<Vec<u8>>>;
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
}

#[derive(Debug, Copy, Clone)]
pub enum Action {
    Decrypt,
    Encrypt,
}

// Basically all functionality of the program requires three steps
// 1. reading from a file or stdin
// 2. apply a function on the data (encrypt or decrypt)
// 3. write to a file or stdout
// This function encapsulates this reoccurring procedure
pub async fn read_process_write<'a, F: Send + Sync + 'static, R: Send + Sync + 'a>(
    file: Option<&'a Path>,
    outfile: Option<&'a Path>,
    inplace: bool,
    action: Action,
    mut fn_process: F,
) -> anyhow::Result<()>
where
    F: FnMut(Vec<u8>) -> R,
    R: Future<Output = anyhow::Result<Vec<u8>>> + Send + Sync,
{
    let do_inplace = if file == outfile { true } else { inplace };
    // for inplace encryption we actually have to use a temporary file
    let mut temporary_file: Option<PathBuf> = None;

    // create the reader
    let reader: Box<dyn AsyncRead + Unpin + Send + Sync> = match file {
        // the reader is a file if a path is given
        Some(path) => {
            let f = File::open(path.clone())
                .await
                .with_context(|| format!("failed to open input file {}", path.to_str().unwrap()))?;
            Box::new(f)
        }
        // if no path is given the reader will be stdin
        None => Box::new(io::stdin()),
    };

    // create the writer
    let writer: Option<Box<dyn AsyncWrite + Unpin + Send + Sync>> = match outfile {
        // the writer is a new file if a path is given and we're not working inplace
        Some(path) if !do_inplace => {
            let f = File::create(path.clone()).await.with_context(|| {
                format!("failed to create output file {}", path.to_str().unwrap())
            })?;
            Some(Box::new(f))
        }
        None => {
            // if we're working inplace the writer is a new temporary file
            if do_inplace && file.is_some() {
                let mut tmp_file = file.unwrap().clone().to_owned();
                tmp_file.set_extension("tmp");
                let f = File::create(tmp_file.as_path()).await.with_context(|| {
                    format!(
                        "failed to create temporary file {}",
                        tmp_file.as_path().to_str().unwrap()
                    )
                })?;
                temporary_file = Some(tmp_file);
                Some(Box::new(f))
            // if no path was given the writer is stdout
            } else {
                Some(Box::new(io::stdout()))
            }
        }
        _ => None,
    };

    let writer = Arc::new(Mutex::new(writer.unwrap()));
    let reader = Arc::new(Mutex::new(reader));

    let fn_read = match action {
        Action::Decrypt => ChunkReader::read_encrypted_chunk,
        Action::Encrypt => ChunkReader::read_plain_chunk,
    };

    let fn_write = match action {
        Action::Decrypt => ChunkWriter::write_plain_chunk,
        Action::Encrypt => ChunkWriter::write_encrypted_chunk,
    };

    while let Some(chunk) = fn_read(Arc::clone(&reader)).await? {
        let processed_chunk = fn_process(chunk).await?;
        fn_write(Arc::clone(&writer), processed_chunk).await?;
    }

    // if a temporary file was used for an inplace operation we have to rename
    // the temporary file to the actual input file
    if temporary_file.is_some() && file.is_some() {
        fs::rename(temporary_file.unwrap(), file.unwrap())
            .await
            .with_context(|| {
                format!(
                    "failed to replace {} with temporary file",
                    file.unwrap().to_str().unwrap()
                )
            })?;
    }

    Ok(())
}

#[async_trait]
impl ChunkReading for ChunkReader {
    async fn read_plain_chunk(
        reader: Arc<Mutex<Box<dyn AsyncRead + Unpin + Send + Sync>>>,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let chunk_size: u64 = 256;
        // let mut buf: Vec<u8> = Vec::with_capacity(chunk_size as usize);
        let mut buf = [0, 255];
        let bytes_read = reader.lock().await.read(&mut buf).await?;
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
            .read(&mut buf)
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
}
