use anyhow::Context;
use futures::future::Future;
use std::path::{Path, PathBuf};
use tokio::fs::{self, File};
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::broadcast::{self, Receiver, Sender};

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
    F: FnMut(Receiver<Vec<u8>>, Sender<Vec<u8>>) -> R,
    R: Future<Output = anyhow::Result<()>> + Send + Sync,
{
    let do_inplace = if file == outfile { true } else { inplace };
    // for inplace encryption we actually have to use a temporary file
    let mut temporary_file: Option<PathBuf> = None;

    // create the reader
    let mut reader: Box<dyn AsyncRead + Unpin + Send + Sync> = match file {
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

    // loop until fn_read returns an empty buffer
    let mut writer = writer.unwrap();
    let (from_reader, to_process) = broadcast::channel(10);
    let (from_process, to_writer) = broadcast::channel(10);

    tokio::spawn(async move {
        match action {
            Action::Decrypt => read_encryped_chunk(&mut reader, from_reader).await?,
            Action::Encrypt => read_plain_chunk(&mut reader, from_reader).await?,
        };
        Ok::<(), anyhow::Error>(())
    })
    .await??;

    tokio::spawn(async move {
        fn_process(to_process, from_process).await?;
        Ok::<(), anyhow::Error>(())
    });

    match action {
        Action::Decrypt => write_plain_chunk(&mut writer, to_writer).await?,
        Action::Encrypt => write_encrypted_chunk(&mut writer, to_writer).await?,
    };

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

pub async fn read_plain_chunk(
    reader: &mut (dyn AsyncRead + Unpin + Send),
    sender: Sender<Vec<u8>>,
) -> anyhow::Result<()> {
    let chunk_size: u64 = 256;
    loop {
        let mut buf: Vec<u8> = Vec::with_capacity(chunk_size as usize);
        let bytes_read = reader.take(chunk_size).read_to_end(&mut buf).await?;
        if bytes_read == 0 {
            break;
        }
        sender.send(buf).unwrap();
    }
    Ok(())
}

pub async fn read_encryped_chunk(
    reader: &mut (dyn AsyncRead + Unpin + Send),
    sender: Sender<Vec<u8>>,
) -> anyhow::Result<()> {
    loop {
        let chunk_size = match reader.read_u32().await {
            Ok(n) => n,
            Err(_) => return Ok(()),
        };
        let mut buf: Vec<u8> = Vec::with_capacity(chunk_size as usize);
        // now reading the actual chunk
        let bytes_read = reader
            .take(chunk_size as u64)
            .read_to_end(&mut buf)
            .await
            .with_context(|| format!("Error reading encrypted file"))?;
        if bytes_read == 0 {
            break;
        }
        if bytes_read < chunk_size as usize {
            return Err(anyhow::anyhow!("could not read entire data chunk"));
        }
        sender.send(buf).unwrap();
    }
    Ok(())
}

pub async fn write_plain_chunk(
    writer: &mut (dyn AsyncWrite + Unpin + Send),
    mut receiver: Receiver<Vec<u8>>,
) -> anyhow::Result<()> {
    while let Ok(chunk) = receiver.recv().await {
        writer.write_all(&chunk).await?;
    }
    Ok(())
}

pub async fn write_encrypted_chunk(
    writer: &mut (dyn AsyncWrite + Unpin + Send),
    mut receiver: Receiver<Vec<u8>>,
) -> anyhow::Result<()> {
    while let Ok(chunk) = receiver.recv().await {
        writer.write_u32(chunk.len() as u32).await?;
        writer.write_all(&chunk).await?;
    }
    Ok(())
}
