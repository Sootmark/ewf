//! Read-only E01 (Expert Witness Format) images.
//!
//! [`Ewf`] exposes the acquired media as a `Read + Seek` stream, so
//! partition and file-system readers can use it like a raw image:
//!
//! - segments (`.E01`, `.E02`, …) are found and ordered automatically;
//! - every chunk's integrity is checked as it's read (zlib Adler-32 for
//!   compressed chunks, the stored Adler-32 for uncompressed ones);
//! - [`Ewf::verify`] recomputes MD5 and SHA-1 over the whole media and
//!   compares them with the hashes the acquisition tool embedded;
//! - [`Ewf::acquisition`] returns the recorded case metadata.
//!
//! Supported: EnCase 5/6-style E01 images (as written by EnCase, FTK Imager
//! and libewf). Not yet: Ex01 (EWF2), L01 logical images, encrypted images.

mod metadata;
mod section;
mod segments;

use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use common::bytes::Reader;
use common::checksum::adler32;
use common::deflate::zlib_decompress;
use common::hex;
use common::md5::Md5;
use common::sha1::Sha1;

pub use metadata::Acquisition;
use section::{invalid, read_at, read_error, Section};
pub use segments::segment_paths;

/// Bit marking a compressed chunk in a table entry.
const COMPRESSED_FLAG: u32 = 0x8000_0000;
/// Table header: entry count (4), padding (4), base offset (8), padding (4), checksum (4).
const TABLE_HEADER_SIZE: usize = 24;
/// Uncompressed chunks are followed by their Adler-32.
const CHUNK_CHECKSUM_SIZE: u64 = 4;
const MAX_CHUNK_SIZE: u64 = 64 << 20;
const MAX_CHUNKS: u64 = 1 << 32;

/// Hashes embedded by the acquisition tool.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoredHashes {
    /// MD5 of the media, lowercase hex.
    pub md5: Option<String>,
    /// SHA-1 of the media, lowercase hex.
    pub sha1: Option<String>,
}

/// The result of recomputing a stored hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashCheck {
    /// Hash embedded in the image.
    pub stored: String,
    /// Hash computed over the media now.
    pub computed: String,
}

impl HashCheck {
    /// Whether the image is intact for this hash.
    #[must_use]
    pub fn matches(&self) -> bool {
        self.stored == self.computed
    }
}

/// The outcome of [`Ewf::verify`]: one check per embedded hash.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Verification {
    /// MD5 check, when the image embeds an MD5.
    pub md5: Option<HashCheck>,
    /// SHA-1 check, when the image embeds a SHA-1.
    pub sha1: Option<HashCheck>,
}

impl Verification {
    /// Whether at least one hash was checked and every checked hash matches.
    #[must_use]
    pub fn verified(&self) -> bool {
        let checks: Vec<&HashCheck> = [&self.md5, &self.sha1].into_iter().flatten().collect();
        !checks.is_empty() && checks.iter().all(|c| c.matches())
    }
}

/// Where a chunk is stored.
#[derive(Debug, Clone, Copy)]
struct Chunk {
    segment: usize,
    offset: u64,
    stored_size: u64,
    compressed: bool,
}

/// An E01 image, readable as a raw disk.
pub struct Ewf<R> {
    segments: Vec<R>,
    chunks: Vec<Chunk>,
    chunk_size: u64,
    media_size: u64,
    bytes_per_sector: u32,
    stored: StoredHashes,
    acquisition: Option<Acquisition>,
    position: u64,
    cached: Option<(usize, Vec<u8>)>,
}

impl Ewf<BufReader<File>> {
    /// Open the image whose first segment is `first` (e.g. `disk.E01`),
    /// with all following segments found next to it.
    ///
    /// # Errors
    /// When a segment can't be opened or the image isn't readable.
    pub fn open_path(first: &Path) -> io::Result<Self> {
        let files = segment_paths(first)
            .into_iter()
            .map(|p| File::open(p).map(BufReader::new))
            .collect::<io::Result<_>>()?;
        Self::open(files)
    }
}

impl<R: Read + Seek> Ewf<R> {
    /// Open an image from its segment files, in any order.
    ///
    /// # Errors
    /// [`io::ErrorKind::InvalidData`] when a segment is damaged, segments are
    /// missing, or the geometry is impossible.
    pub fn open(files: Vec<R>) -> io::Result<Self> {
        let mut segments = Vec::with_capacity(files.len());
        for mut file in files {
            let (number, sections) = section::read_sections(&mut file)?;
            segments.push((number, file, sections));
        }
        segments.sort_by_key(|(number, _, _)| *number);
        let numbers_ok = segments
            .iter()
            .enumerate()
            .all(|(i, (n, _, _))| usize::from(*n) == i + 1);
        if segments.is_empty() || !numbers_ok {
            return Err(invalid("missing or duplicate E01 segments"));
        }
        let mut builder = Builder::default();
        for (index, (_, file, sections)) in segments.iter_mut().enumerate() {
            builder.read_segment(index, file, sections)?;
        }
        builder.finish(segments.into_iter().map(|(_, file, _)| file).collect())
    }

    /// Size of the acquired media in bytes.
    #[must_use]
    pub const fn media_size(&self) -> u64 {
        self.media_size
    }

    /// Sector size of the acquired media.
    #[must_use]
    pub const fn bytes_per_sector(&self) -> u32 {
        self.bytes_per_sector
    }

    /// Hashes embedded by the acquisition tool.
    #[must_use]
    pub const fn stored_hashes(&self) -> &StoredHashes {
        &self.stored
    }

    /// Case metadata recorded at acquisition, if present and readable.
    #[must_use]
    pub const fn acquisition(&self) -> Option<&Acquisition> {
        self.acquisition.as_ref()
    }

    /// Recompute MD5 and SHA-1 over the whole media and compare them with
    /// the embedded hashes. The read position is restored afterwards.
    ///
    /// # Errors
    /// When a chunk can't be read or fails its integrity check.
    pub fn verify(&mut self) -> io::Result<Verification> {
        let position = self.position;
        let (mut md5, mut sha1) = (Md5::new(), Sha1::new());
        for index in 0..self.chunks.len() {
            let data = self.chunk(index)?;
            md5.update(data);
            sha1.update(data);
        }
        self.position = position;
        let check = |stored: &Option<String>, computed: String| {
            stored.clone().map(|stored| HashCheck { stored, computed })
        };
        Ok(Verification {
            md5: check(&self.stored.md5, hex::encode(&md5.finalize())),
            sha1: check(&self.stored.sha1, hex::encode(&sha1.finalize())),
        })
    }

    /// The decoded content of chunk `index` (the last chunk may be shorter).
    fn chunk(&mut self, index: usize) -> io::Result<&[u8]> {
        let is_cached = matches!(&self.cached, Some((cached, _)) if *cached == index);
        if !is_cached {
            let data = self.decode_chunk(index)?;
            self.cached = Some((index, data));
        }
        match &self.cached {
            Some((_, data)) => Ok(data),
            None => Err(invalid("chunk cache empty")),
        }
    }

    fn decode_chunk(&mut self, index: usize) -> io::Result<Vec<u8>> {
        let chunk = *self
            .chunks
            .get(index)
            .ok_or_else(|| invalid("chunk missing from the tables"))?;
        let start = index as u64 * self.chunk_size;
        let expected = self.chunk_size.min(self.media_size - start) as usize;
        let stored = read_at(
            &mut self.segments[chunk.segment],
            chunk.offset,
            chunk.stored_size as usize,
        )?;
        if chunk.compressed {
            let mut data = zlib_decompress(&stored, self.chunk_size as usize)?;
            if data.len() < expected {
                return Err(invalid("compressed chunk shorter than expected"));
            }
            data.truncate(expected);
            return Ok(data);
        }
        let checksum_end = expected + CHUNK_CHECKSUM_SIZE as usize;
        if stored.len() < checksum_end {
            return Err(invalid("uncompressed chunk truncated"));
        }
        let checksum = u32::from_le_bytes([
            stored[expected],
            stored[expected + 1],
            stored[expected + 2],
            stored[expected + 3],
        ]);
        if adler32(&stored[..expected]) != checksum {
            return Err(invalid(
                "chunk Adler-32 mismatch: image corrupted or altered",
            ));
        }
        Ok(stored[..expected].to_vec())
    }
}

impl<R: Read + Seek> Read for Ewf<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.position >= self.media_size {
            return Ok(0);
        }
        let index = (self.position / self.chunk_size) as usize;
        let within = (self.position % self.chunk_size) as usize;
        let data = self.chunk(index)?;
        let available = data.len().saturating_sub(within);
        if available == 0 {
            return Err(invalid("chunk shorter than expected"));
        }
        let count = available.min(buf.len());
        buf[..count].copy_from_slice(&data[within..within + count]);
        self.position += count as u64;
        Ok(count)
    }
}

impl<R> Seek for Ewf<R> {
    fn seek(&mut self, target: SeekFrom) -> io::Result<u64> {
        let position = match target {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::End(delta) => self.media_size.checked_add_signed(delta),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
        };
        self.position = position.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "seek before start of media")
        })?;
        Ok(self.position)
    }
}

/// Accumulates what the sections of all segments describe.
#[derive(Default)]
struct Builder {
    geometry: Option<Geometry>,
    chunks: Vec<Chunk>,
    stored: StoredHashes,
    header: Option<Acquisition>,
    header2: Option<Acquisition>,
}

#[derive(Debug, Clone, Copy)]
struct Geometry {
    chunk_size: u64,
    bytes_per_sector: u32,
    media_size: u64,
}

impl Builder {
    fn read_segment<R: Read + Seek>(
        &mut self,
        segment: usize,
        file: &mut R,
        sections: &[Section],
    ) -> io::Result<()> {
        let mut sectors_end = None;
        for section in sections {
            match section.kind.as_str() {
                "header2" if self.header2.is_none() => {
                    self.header2 = metadata::parse(&data(file, section)?);
                }
                "header" if self.header.is_none() => {
                    self.header = metadata::parse(&data(file, section)?);
                }
                "volume" | "disk" if self.geometry.is_none() => {
                    self.geometry = Some(geometry(&data(file, section)?)?);
                }
                "sectors" => sectors_end = Some(section.data_offset + section.data_length),
                "table" => self.read_table(segment, &data(file, section)?, section, sectors_end)?,
                "hash" => self.read_hash(&data(file, section)?),
                "digest" => self.read_digest(&data(file, section)?),
                _ => {}
            }
        }
        Ok(())
    }

    /// Chunk offsets from a table; each chunk ends where the next begins,
    /// the last one at the end of the sectors data (or at the table itself).
    fn read_table(
        &mut self,
        segment: usize,
        bytes: &[u8],
        section: &Section,
        sectors_end: Option<u64>,
    ) -> io::Result<()> {
        let mut r = Reader::new(bytes);
        let count = u64::from(r.u32_le().map_err(read_error)?);
        r.skip(4).map_err(read_error)?;
        let base = r.u64_le().map_err(read_error)?;
        r.seek(TABLE_HEADER_SIZE).map_err(read_error)?;
        let count =
            common::bytes::checked_count(count, 4, MAX_CHUNKS, r.remaining(), TABLE_HEADER_SIZE)
                .map_err(read_error)?;
        let entries: Vec<(u64, bool)> = (0..count)
            .map(|_| {
                let raw = r.u32_le().map_err(read_error)?;
                Ok((
                    base + u64::from(raw & !COMPRESSED_FLAG),
                    raw & COMPRESSED_FLAG != 0,
                ))
            })
            .collect::<io::Result<_>>()?;
        let table_start = section.offset;
        for (i, &(offset, compressed)) in entries.iter().enumerate() {
            let end = entries.get(i + 1).map_or_else(
                || {
                    sectors_end
                        .filter(|&end| end > offset)
                        .unwrap_or(table_start)
                },
                |next| next.0,
            );
            let stored_size = end
                .checked_sub(offset)
                .filter(|&size| size > 0 && size <= MAX_CHUNK_SIZE + CHUNK_CHECKSUM_SIZE);
            let stored_size =
                stored_size.ok_or_else(|| invalid("impossible chunk size in table"))?;
            self.chunks.push(Chunk {
                segment,
                offset,
                stored_size,
                compressed,
            });
        }
        Ok(())
    }

    fn read_hash(&mut self, bytes: &[u8]) {
        if let Some(md5) = bytes.get(..16) {
            self.stored.md5.get_or_insert_with(|| hex::encode(md5));
        }
    }

    fn read_digest(&mut self, bytes: &[u8]) {
        if let Some(md5) = bytes.get(..16) {
            self.stored.md5 = Some(hex::encode(md5));
        }
        if let Some(sha1) = bytes.get(16..36) {
            self.stored.sha1 = Some(hex::encode(sha1));
        }
    }

    fn finish<R>(self, segments: Vec<R>) -> io::Result<Ewf<R>> {
        let geometry = self.geometry.ok_or_else(|| invalid("no volume section"))?;
        // Only the chunks the media needs: a declared count can be larger.
        let needed = geometry.media_size.div_ceil(geometry.chunk_size);
        let mut chunks = self.chunks;
        if (chunks.len() as u64) < needed {
            return Err(invalid(
                "chunk tables describe fewer chunks than the media holds",
            ));
        }
        chunks.truncate(needed as usize);
        let stored = StoredHashes {
            md5: self.stored.md5.filter(|h| !is_zero(h)),
            sha1: self.stored.sha1.filter(|h| !is_zero(h)),
        };
        Ok(Ewf {
            segments,
            chunks,
            chunk_size: geometry.chunk_size,
            media_size: geometry.media_size,
            bytes_per_sector: geometry.bytes_per_sector,
            stored,
            acquisition: self.header2.or(self.header),
            position: 0,
            cached: None,
        })
    }
}

/// Tools write all-zero hashes when none was computed.
fn is_zero(hex: &str) -> bool {
    hex.bytes().all(|b| b == b'0')
}

fn data<R: Read + Seek>(file: &mut R, section: &Section) -> io::Result<Vec<u8>> {
    read_at(file, section.data_offset, section.data_length as usize)
}

/// The EnCase `volume`/`disk` section: chunk count, sectors per chunk,
/// bytes per sector, sector count.
fn geometry(bytes: &[u8]) -> io::Result<Geometry> {
    let mut r = Reader::new(bytes);
    r.skip(4).map_err(read_error)?; // media type, padding
    let chunk_count = u64::from(r.u32_le().map_err(read_error)?);
    let sectors_per_chunk = u64::from(r.u32_le().map_err(read_error)?);
    let bytes_per_sector = r.u32_le().map_err(read_error)?;
    let sector_count = r.u64_le().map_err(read_error)?;
    let chunk_size = sectors_per_chunk * u64::from(bytes_per_sector);
    let media_size = sector_count
        .checked_mul(u64::from(bytes_per_sector))
        .ok_or_else(|| invalid("impossible media size"))?;
    let sane = matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096)
        && chunk_size > 0
        && chunk_size <= MAX_CHUNK_SIZE
        && media_size.div_ceil(chunk_size) <= chunk_count.max(1);
    if !sane {
        return Err(invalid("impossible E01 geometry"));
    }
    Ok(Geometry {
        chunk_size,
        bytes_per_sector,
        media_size,
    })
}
