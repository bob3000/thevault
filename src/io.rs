use anyhow::Context;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::fs::{self, File};
use std::io::prelude::*;
use std::io::{self, BufReader, BufWriter};
use std::path::{Path, PathBuf};

// Basically all functionality of the program requires three steps
// 1. reading from a file or stdin
// 2. apply a function on the data (encrypt or decrypt)
// 3. write to a file or stdout
// This function encapsulates this reoccurring procedure
pub fn read_process_write<D, E, F>(
    file: Option<&Path>,
    outfile: Option<&Path>,
    inplace: bool,
    fn_read: D,
    fn_write: E,
    mut fn_process: F,
) -> anyhow::Result<()>
where
    D: Fn(&mut dyn Read) -> anyhow::Result<Vec<u8>>,
    E: Fn(&mut dyn Write, &[u8]) -> anyhow::Result<()>,
    F: FnMut(&Vec<u8>) -> anyhow::Result<Vec<u8>>,
{
    let do_inplace = if file == outfile { true } else { inplace };
    // for inplace encryption we actually have to use a temporary file
    let mut temporary_file: Option<PathBuf> = None;

    // create the reader
    let reader: Box<dyn Read> = match file {
        // the reader is a file if a path is given
        Some(path) => {
            let f = File::open(path.clone())
                .with_context(|| format!("failed to open input file {}", path.to_str().unwrap()))?;
            Box::new(f)
        }
        // if no path is given the reader will be stdin
        None => Box::new(io::stdin()),
    };

    // create the writer
    let writer: Option<Box<dyn Write>> = match outfile {
        // the writer is a new file if a path is given and we're not working inplace
        Some(path) if !do_inplace => {
            let f = File::create(path.clone()).with_context(|| {
                format!("failed to create output file {}", path.to_str().unwrap())
            })?;
            Some(Box::new(f))
        }
        None => {
            // if we're working inplace the writer is a new temporary file
            if do_inplace && file.is_some() {
                let mut tmp_file = file.unwrap().clone().to_owned();
                tmp_file.set_extension("tmp");
                let f = File::create(tmp_file.as_path()).with_context(|| {
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
    let mut wtr = BufWriter::new(writer.unwrap());
    let mut rdr = BufReader::new(reader);
    loop {
        let got_bytes = fn_read(&mut rdr)?;
        if got_bytes.len() == 0 {
            break;
        }
        let processed = fn_process(&got_bytes)?;
        fn_write(&mut wtr, &processed)?;
    }

    // if a temporary file was used for an inplace operation we have to rename
    // the temporary file to the actual input file
    if temporary_file.is_some() && file.is_some() {
        fs::rename(temporary_file.unwrap(), file.unwrap()).with_context(|| {
            format!(
                "failed to replace {} with temporary file",
                file.unwrap().to_str().unwrap()
            )
        })?;
    }

    Ok(())
}

pub fn read_plain_chunk(reader: &mut dyn Read) -> anyhow::Result<Vec<u8>> {
    let chunk_size: u64 = 256;
    let mut buf: Vec<u8> = Vec::with_capacity(chunk_size as usize);
    reader.take(chunk_size).read_to_end(&mut buf)?;
    Ok(buf)
}

pub fn read_encryped_chunk(reader: &mut dyn Read) -> anyhow::Result<Vec<u8>> {
    let chunk_size = match reader.read_u32::<BigEndian>() {
        Ok(n) => n,
        Err(_) => return Ok(Vec::new()),
    };
    let mut buf: Vec<u8> = Vec::with_capacity(chunk_size as usize);
    // now reading the actual chunk
    let bytes_read = reader
        .take(chunk_size as u64)
        .read_to_end(&mut buf)
        .with_context(|| format!("Error reading encrypted file"))?;
    if bytes_read < chunk_size as usize {
        return Err(anyhow::anyhow!("could not read entire data chunk"));
    }
    Ok(buf)
}

pub fn write_plain_chunk(writer: &mut dyn Write, chunk: &[u8]) -> anyhow::Result<()> {
    writer.write_all(&chunk)?;
    Ok(())
}

pub fn write_encrypted_chunk(writer: &mut dyn Write, chunk: &[u8]) -> anyhow::Result<()> {
    writer.write_u32::<BigEndian>(chunk.len() as u32)?;
    writer.write_all(&chunk)?;
    Ok(())
}
