//! Acquisition metadata from the `header2` / `header` sections.
//!
//! The section holds zlib-compressed text (UTF-16 in `header2`, ASCII in
//! `header`): tab-separated lines, the third naming the fields and the
//! fourth giving their values.

use common::deflate::zlib_decompress;
use common::text;

/// Upper bound on decompressed header text.
const MAX_HEADER: usize = 1 << 20;
/// UTF-16 little-endian byte order mark.
const UTF16_BOM: [u8; 2] = [0xff, 0xfe];

/// Who acquired the image, when, and for which case, as the acquisition
/// tool recorded it. Values are as written by the examiner or tool.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Acquisition {
    /// Case number (`c`).
    pub case_number: Option<String>,
    /// Evidence number (`n`).
    pub evidence_number: Option<String>,
    /// Description (`a`).
    pub description: Option<String>,
    /// Examiner name (`e`).
    pub examiner: Option<String>,
    /// Notes (`t`).
    pub notes: Option<String>,
    /// Acquisition date as recorded (`m`).
    pub acquired: Option<String>,
    /// System date of the acquiring machine (`u`).
    pub system_date: Option<String>,
    /// Acquisition software version (`av`).
    pub software_version: Option<String>,
    /// Operating system of the acquiring machine (`ov`).
    pub operating_system: Option<String>,
}

/// Parse a compressed header section; `None` if it can't be read.
pub(crate) fn parse(compressed: &[u8]) -> Option<Acquisition> {
    let raw = zlib_decompress(compressed, MAX_HEADER).ok()?;
    let text = match raw.strip_prefix(&UTF16_BOM) {
        Some(utf16) => text::utf16le(utf16).text,
        None => raw.iter().map(|&b| char::from(b)).collect(),
    };
    let mut lines = text.lines();
    let names: Vec<&str> = lines.nth(2)?.split('\t').collect();
    let values: Vec<&str> = lines.next()?.split('\t').collect();
    let field = |key: &str| {
        let index = names.iter().position(|name| name.trim() == key)?;
        values
            .get(index)
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
    };
    Some(Acquisition {
        case_number: field("c"),
        evidence_number: field("n"),
        description: field("a"),
        examiner: field("e"),
        notes: field("t"),
        acquired: field("m"),
        system_date: field("u"),
        software_version: field("av"),
        operating_system: field("ov"),
    })
}
