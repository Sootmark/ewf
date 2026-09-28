//! E01 images written by libewf's `ewfacquire` from the synthetic FIN-WKS-07
//! disk (see `Sootmark/disk`). Reference values were computed independently:
//! `md5`, `shasum -a 1` and `shasum -a 256` on the raw disk; `ewfverify`
//! accepts every fixture.

use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

use common::sha256::{hex, Sha256};
use disk::{partitions, NtfsVolume};
use sootmark_ewf::Ewf;

const RAW_SHA256: &str = "67fb9a797f92d66d444a0bfcf3521f9060da3050fcfb6f37cbdc5af4dffe3ebe";
const RAW_MD5: &str = "7051d0bae80b472da82c8ff0b96a7738";
const RAW_SHA1: &str = "13ebfae8afac9c2ae214fcaf9c0772f9c1489d94";
const MEDIA_SIZE: u64 = 1_802_240;
const IMAGES: [&str; 3] = ["encase6-best.E01", "encase6-split.E01", "encase5-fast.E01"];

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn open(name: &str) -> Ewf<std::io::BufReader<std::fs::File>> {
    Ewf::open_path(&fixture(name)).expect("a readable image")
}

#[test]
fn every_variant_reads_back_the_raw_disk() {
    for name in IMAGES {
        let mut image = open(name);
        assert_eq!(image.media_size(), MEDIA_SIZE, "{name}");
        assert_eq!(image.bytes_per_sector(), 512, "{name}");
        let mut hasher = Sha256::new();
        std::io::copy(&mut image, &mut hasher).unwrap();
        assert_eq!(hex(&hasher.finalize()), RAW_SHA256, "{name}");
    }
}

#[test]
fn split_images_are_found_and_ordered() {
    let paths = sootmark_ewf::segment_paths(&fixture("encase6-split.E01"));
    let names: Vec<_> = paths
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["encase6-split.E01", "encase6-split.E02"]);
}

#[test]
fn embedded_hashes_verify() {
    // EnCase 5 images only have a `hash` section (MD5); EnCase 6 adds a
    // `digest` section with SHA-1 (confirmed with `ewfinfo`).
    for (name, sha1) in [
        ("encase6-best.E01", Some(RAW_SHA1)),
        ("encase6-split.E01", Some(RAW_SHA1)),
        ("encase5-fast.E01", None),
    ] {
        let mut image = open(name);
        assert_eq!(
            image.stored_hashes().md5.as_deref(),
            Some(RAW_MD5),
            "{name}"
        );
        assert_eq!(image.stored_hashes().sha1.as_deref(), sha1, "{name}");
        let verification = image.verify().unwrap();
        assert!(verification.verified(), "{name}: {verification:?}");
    }
}

#[test]
fn acquisition_metadata_is_read() {
    let image = open("encase6-best.E01");
    let acquisition = image.acquisition().expect("header section");
    assert_eq!(acquisition.case_number.as_deref(), Some("FIN-2026-001"));
    assert_eq!(acquisition.evidence_number.as_deref(), Some("EV01"));
    assert_eq!(acquisition.description.as_deref(), Some("FIN-WKS-07"));
    assert_eq!(acquisition.examiner.as_deref(), Some("Sootmark"));
    assert_eq!(acquisition.notes.as_deref(), Some("synthetic"));
}

#[test]
fn ntfs_works_through_the_image() {
    let mut image = open("encase6-best.E01");
    let size = image.media_size();
    let (_, parts) = partitions(&mut image, size).unwrap();
    let volume = NtfsVolume::open(&mut image, parts[1].offset, parts[1].length).unwrap();
    assert_eq!(volume.files(&mut image).unwrap().len(), 17);
}

#[test]
fn seeking_reads_the_same_bytes_as_the_raw_disk() {
    let raw = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/../../../disk/tests/fixtures/fin-wks-07.img"
    ))
    .ok();
    let Some(raw) = raw else { return };
    let mut image = open("encase6-split.E01");
    for offset in [0usize, 511, 32_767, 32_768, 1_000_000, raw.len() - 7] {
        image.seek(SeekFrom::Start(offset as u64)).unwrap();
        let mut buf = [0u8; 7];
        image.read_exact(&mut buf).unwrap();
        assert_eq!(buf, raw[offset..offset + 7], "offset {offset}");
    }
}

#[test]
fn a_tampered_chunk_is_detected() {
    // Uncompressed image: flip one byte of media data inside the first segment.
    let dir = std::env::temp_dir().join(format!("ewf-tamper-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for segment in ["encase6-split.E01", "encase6-split.E02"] {
        std::fs::copy(fixture(segment), dir.join(segment)).unwrap();
    }
    let path = dir.join("encase6-split.E01");
    let mut bytes = std::fs::read(&path).unwrap();
    let at = bytes.len() / 2;
    bytes[at] ^= 0xff;
    std::fs::write(&path, bytes).unwrap();
    let mut image = Ewf::open_path(&path).unwrap();
    let error = image.verify().unwrap_err();
    assert!(error.to_string().contains("Adler-32"), "{error}");
    std::fs::remove_dir_all(dir).unwrap();
}
