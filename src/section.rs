//! Segment files and the chain of sections inside them.

use std::io::{self, Read, Seek, SeekFrom};

use common::bytes::Reader;
use common::checksum::adler32;

/// `EVF\t\r\n\xff\0`: the EWF (E01) segment signature.
const SIGNATURE: &[u8; 8] = b"EVF\x09\x0d\x0a\xff\x00";
/// Signature, fields start, segment number, fields end.
pub(crate) const FILE_HEADER_SIZE: u64 = 13;
/// Type (16), next offset (8), size (8), padding (40), checksum (4).
pub(crate) const DESCRIPTOR_SIZE: u64 = 76;
/// The descriptor checksum covers everything before it.
const DESCRIPTOR_CHECKED: usize = 72;
/// Upper bound on sections per segment (hostile chains).
const MAX_SECTIONS: usize = 1 << 20;

/// One section: its type and where its data lies in the segment file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Section {
    pub(crate) kind: String,
    /// Offset of the section's descriptor.
    pub(crate) offset: u64,
    /// Offset of the data after the descriptor.
    pub(crate) data_offset: u64,
    /// Length of that data (section size minus the descriptor).
    pub(crate) data_length: u64,
}

/// The segment number and sections of one segment file.
pub(crate) fn read_sections<R: Read + Seek>(file: &mut R) -> io::Result<(u16, Vec<Section>)> {
    let length = file.seek(SeekFrom::End(0))?;
    let header = read_at(file, 0, FILE_HEADER_SIZE as usize)?;
    if header.len() < FILE_HEADER_SIZE as usize || &header[..8] != SIGNATURE {
        return Err(invalid("not an E01 segment (bad signature)"));
    }
    let segment = u16::from_le_bytes([header[9], header[10]]);
    let mut sections = Vec::new();
    let mut offset = FILE_HEADER_SIZE;
    while sections.len() < MAX_SECTIONS {
        let bytes = read_at(file, offset, DESCRIPTOR_SIZE as usize)?;
        let section = parse_descriptor(&bytes, offset, length)?;
        let next = u64::from_le_bytes(bytes[16..24].try_into().expect("8 bytes"));
        let last = matches!(section.kind.as_str(), "done" | "next") || next == offset || next == 0;
        sections.push(section);
        if last {
            return Ok((segment, sections));
        }
        if next < offset || next >= length {
            return Err(invalid("section chain points outside the segment"));
        }
        offset = next;
    }
    Err(invalid("too many sections"))
}

fn parse_descriptor(bytes: &[u8], offset: u64, file_length: u64) -> io::Result<Section> {
    if bytes.len() < DESCRIPTOR_SIZE as usize {
        return Err(invalid("truncated section descriptor"));
    }
    let stored = u32::from_le_bytes(
        bytes[DESCRIPTOR_CHECKED..DESCRIPTOR_CHECKED + 4]
            .try_into()
            .expect("4 bytes"),
    );
    if adler32(&bytes[..DESCRIPTOR_CHECKED]) != stored {
        return Err(invalid("section descriptor checksum mismatch"));
    }
    let kind: String = bytes[..16]
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| char::from(b))
        .collect();
    let mut r = Reader::new(bytes);
    r.seek(24).map_err(read_error)?;
    let size = r.u64_le().map_err(read_error)?;
    let data_offset = offset + DESCRIPTOR_SIZE;
    // Terminal sections ("done", "next") may declare a size of 0 or 76.
    let data_length = size
        .saturating_sub(DESCRIPTOR_SIZE)
        .min(file_length.saturating_sub(data_offset));
    Ok(Section {
        kind,
        offset,
        data_offset,
        data_length,
    })
}

pub(crate) fn read_at<R: Read + Seek>(
    file: &mut R,
    offset: u64,
    length: usize,
) -> io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset))?;
    let mut buffer = Vec::with_capacity(length.min(1 << 20));
    file.take(length as u64).read_to_end(&mut buffer)?;
    Ok(buffer)
}

pub(crate) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[allow(clippy::needless_pass_by_value)] // used as a `map_err` adapter
pub(crate) fn read_error(error: common::bytes::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
