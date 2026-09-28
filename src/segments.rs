//! Segment file names: `.E01` … `.E99`, then `.EAA` … `.EZZ`, `.FAA` …

use std::path::{Path, PathBuf};

/// Highest numeric segment before letters take over.
const LAST_NUMERIC: u32 = 99;
/// Letter pairs per leading letter (AA..ZZ).
const PAIRS: u32 = 26 * 26;

/// `first` and every following segment that exists next to it.
#[must_use]
pub fn segment_paths(first: &Path) -> Vec<PathBuf> {
    let Some(extension) = first.extension().and_then(|e| e.to_str()) else {
        return vec![first.to_owned()];
    };
    let Some(lead) = extension.chars().next() else {
        return vec![first.to_owned()];
    };
    let lowercase = lead.is_ascii_lowercase();
    (1u32..)
        .map_while(|number| extension_for(lead.to_ascii_uppercase(), number))
        .map(|ext| {
            first.with_extension(if lowercase {
                ext.to_ascii_lowercase()
            } else {
                ext
            })
        })
        .take_while(|path| path.exists())
        .collect()
}

/// The extension of segment `number` (1-based) for a series starting with
/// `lead` (`E` for E01 images), or `None` past the last possible name.
fn extension_for(lead: char, number: u32) -> Option<String> {
    if number <= LAST_NUMERIC {
        return Some(format!("{lead}{number:02}"));
    }
    let index = number - LAST_NUMERIC - 1;
    let first = u32::from(lead) + index / PAIRS;
    let first = char::from_u32(first).filter(char::is_ascii_uppercase)?;
    let second = char::from(b'A' + (index % PAIRS / 26) as u8);
    let third = char::from(b'A' + (index % 26) as u8);
    Some(format!("{first}{second}{third}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_then_letters() {
        assert_eq!(extension_for('E', 1).as_deref(), Some("E01"));
        assert_eq!(extension_for('E', 99).as_deref(), Some("E99"));
        assert_eq!(extension_for('E', 100).as_deref(), Some("EAA"));
        assert_eq!(extension_for('E', 101).as_deref(), Some("EAB"));
        assert_eq!(extension_for('E', 99 + 676).as_deref(), Some("EZZ"));
        assert_eq!(extension_for('E', 100 + 676).as_deref(), Some("FAA"));
        assert_eq!(extension_for('E', 100 + 676 * 22), None, "past ZZZ");
    }
}
