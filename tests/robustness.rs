//! Hostile E01 images: corrupted or truncated segments yield errors, never
//! panics.

use std::io::{Cursor, Read};

use ewf::Ewf;
use proptest::prelude::*;

const COMPRESSED: &[u8] = include_bytes!("fixtures/encase6-best.E01");
const LEGACY: &[u8] = include_bytes!("fixtures/encase5-fast.E01");
/// Section descriptors, headers, volume, the start of the chunk data, and
/// the tables near the end: where structure lives in these small images.
const HEAD: std::ops::Range<usize> = 0..4096;
/// Bytes read per case, as a consumer would budget.
const READ_BUDGET: u64 = 4 << 20;

fn exercise(bytes: Vec<u8>) {
    if let Ok(mut image) = Ewf::open(vec![Cursor::new(bytes)]) {
        let _ = image.verify();
        let _ = image.take(READ_BUDGET).read_to_end(&mut Vec::new());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn corrupted_structures_never_panic(flips in proptest::collection::vec((HEAD, any::<u8>()), 1..16)) {
        let mut bytes = COMPRESSED.to_vec();
        for (at, value) in flips {
            bytes[at] = value;
        }
        exercise(bytes);
    }

    #[test]
    fn corrupted_anywhere_never_panics(flips in proptest::collection::vec((0..LEGACY.len(), any::<u8>()), 1..16)) {
        let mut bytes = LEGACY.to_vec();
        for (at, value) in flips {
            bytes[at] = value;
        }
        exercise(bytes);
    }

    #[test]
    fn truncated_images_never_panic(len in 0..COMPRESSED.len()) {
        exercise(COMPRESSED[..len].to_vec());
    }
}
