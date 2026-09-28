# ewf

Read-only E01 (Expert Witness Format) images, written from scratch. The only dependency is [`Sootmark/common`](https://github.com/Sootmark/common) (zlib, Adler-32, MD5, SHA-1).

```rust
let mut image = ewf::Ewf::open_path("FIN-WKS-07.E01".as_ref())?; // finds .E02, .E03, … itself
if let Some(acquisition) = image.acquisition() {
    println!("case {:?}, examiner {:?}", acquisition.case_number, acquisition.examiner);
}
let verification = image.verify()?; // recomputes MD5/SHA-1, compares with the embedded hashes
assert!(verification.verified());
let size = image.media_size();
let (_, partitions) = disk::partitions(&mut image, size)?; // then NTFS, like a raw disk
```

- The acquired media as a `Read + Seek` stream; segments (`.E01` … `.E99`, `.EAA` …) found and ordered automatically.
- **Every chunk is integrity-checked as it's read**: zlib Adler-32 for compressed chunks, the stored Adler-32 for uncompressed ones. Corruption is reported ("chunk Adler-32 mismatch: image corrupted or altered"), never passed through.
- **`verify()`** recomputes MD5 and SHA-1 over the whole media and compares them with the hashes the acquisition tool embedded (EnCase 6 stores both; EnCase 5 only MD5).
- **Acquisition metadata** from `header2`/`header`: case number, evidence number, description, examiner, notes, dates, tool version, OS.

Supported: EnCase 5/6-style E01 as written by EnCase, FTK Imager and libewf. Not yet: Ex01 (EWF2), L01 logical images, encrypted images, acquisition error ranges (`error2`).

## Verification

Fixtures are written by libewf's `ewfacquire` from the synthetic FIN-WKS-07 disk ([`Sootmark/disk`](https://github.com/Sootmark/disk)) and accepted by `ewfverify`:

| Check | Result |
|---|---|
| EnCase 6 compressed, EnCase 6 uncompressed split into 2 segments, EnCase 5 compressed | each reads back the raw disk byte for byte (SHA-256) |
| Embedded MD5 / SHA-1 | equal to `md5` / `shasum -a 1` on the raw disk; `verify()` passes |
| Acquisition metadata | matches `ewfinfo` |
| Partitions and NTFS through the E01 | same as on the raw disk |
| One byte of media data altered | detected (Adler-32 mismatch) |
| Corrupted or truncated segments | errors, never panics (fuzzed) |

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
