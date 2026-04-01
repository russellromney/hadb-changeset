//! HADBJ (hadb journal) format for logical replication.
//!
//! Ships opaque journal entries (rewritten queries, WAL records, etc.) with
//! per-entry CRC32C + SHA-256 chain integrity. Supports sealed/unsealed
//! lifecycle and optional zstd compression.
//!
//! The entry payload is opaque bytes. Each engine defines its own payload
//! format (e.g., graphstream uses protobuf Cypher entries).
//!
//! ## Format
//!
//! ```text
//! Header (128 bytes):
//!   magic(5) "HADBJ" | version(1) | flags(1) | compression(1)
//!   first_seq(8) | last_seq(8) | entry_count(8) | body_len(8)
//!   body_checksum(32) | prev_segment_checksum(8) | created_ms(8)
//!   reserved(32)
//!
//! Body (variable):
//!   [entry_crc32c(4) | payload_len(4) | sequence(8) | prev_hash(32) | payload(payload_len)]*
//!
//! Trailer (optional, 32 bytes when FLAG_HAS_CHAIN_HASH):
//!   chain_hash(32)   -- SHA-256 of last entry, enables O(1) recovery
//! ```

use sha2::{Digest, Sha256};

use crate::error::ChangesetError;

pub const HADBJ_MAGIC: [u8; 5] = *b"HADBJ";
pub const HADBJ_VERSION: u8 = 1;

/// Header size in bytes.
pub const HEADER_SIZE: usize = 128;
/// Per-entry fixed header: crc32c(4) + payload_len(4) + sequence(8) + prev_hash(32) = 48.
pub const ENTRY_HEADER_SIZE: usize = 48;
/// Chain hash trailer size.
pub const CHAIN_HASH_TRAILER_SIZE: usize = 32;

// Flags
pub const FLAG_SEALED: u8 = 0x04;
pub const FLAG_COMPRESSED: u8 = 0x01;
pub const FLAG_HAS_CHAIN_HASH: u8 = 0x08;

// Compression algorithms
pub const COMPRESSION_NONE: u8 = 0;
#[cfg(feature = "journal")]
pub const COMPRESSION_ZSTD: u8 = 1;

/// Zero hash (32 bytes of zeros) used as prev_hash for the first entry.
pub const ZERO_HASH: [u8; 32] = [0u8; 32];

/// Header for a journal segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalHeader {
    pub flags: u8,
    pub compression: u8,
    /// Sequence number of the first entry in this segment.
    pub first_seq: u64,
    /// Sequence number of the last entry (0 if unsealed).
    pub last_seq: u64,
    /// Number of entries (0 if unsealed).
    pub entry_count: u64,
    /// Length of the body in bytes (0 if unsealed).
    pub body_len: u64,
    /// SHA-256 of the body bytes (zeros if unsealed).
    pub body_checksum: [u8; 32],
    /// Checksum from the previous segment (for cross-segment chain verification).
    pub prev_segment_checksum: u64,
    /// Milliseconds since Unix epoch.
    pub created_ms: i64,
}

impl JournalHeader {
    /// Returns true if this segment is sealed (finalized).
    pub fn is_sealed(&self) -> bool {
        self.flags & FLAG_SEALED != 0
    }

    /// Returns true if the body is compressed.
    pub fn is_compressed(&self) -> bool {
        self.flags & FLAG_COMPRESSED != 0
    }

    /// Returns true if a chain hash trailer is present.
    pub fn has_chain_hash(&self) -> bool {
        self.flags & FLAG_HAS_CHAIN_HASH != 0
    }
}

/// A single journal entry with opaque payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEntry {
    /// Entry sequence number (1-indexed, monotonically increasing).
    pub sequence: u64,
    /// SHA-256 hash of the previous entry (zeros for the first entry).
    pub prev_hash: [u8; 32],
    /// Opaque payload bytes (engine defines the format).
    pub payload: Vec<u8>,
}

/// A complete sealed journal segment: header + entries + chain hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalSegment {
    pub header: JournalHeader,
    pub entries: Vec<JournalEntry>,
    /// SHA-256 chain hash of the last entry.
    pub chain_hash: [u8; 32],
}

// ============================================================================
// Entry-level operations
// ============================================================================

/// Compute the chain hash for an entry: SHA-256(prev_hash || payload).
pub fn compute_entry_hash(prev_hash: &[u8; 32], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash);
    hasher.update(payload);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Compute CRC32C of entry bytes (everything after the CRC32C field).
fn compute_entry_crc32c(payload_len: u32, sequence: u64, prev_hash: &[u8; 32], payload: &[u8]) -> u32 {
    let mut buf = Vec::with_capacity(4 + 8 + 32 + payload.len());
    buf.extend_from_slice(&payload_len.to_be_bytes());
    buf.extend_from_slice(&sequence.to_be_bytes());
    buf.extend_from_slice(prev_hash);
    buf.extend_from_slice(payload);
    crc32c::crc32c(&buf)
}

/// Encode a single journal entry to bytes.
pub fn encode_entry(entry: &JournalEntry) -> Vec<u8> {
    let payload_len = entry.payload.len() as u32;
    let crc = compute_entry_crc32c(payload_len, entry.sequence, &entry.prev_hash, &entry.payload);

    let mut buf = Vec::with_capacity(ENTRY_HEADER_SIZE + entry.payload.len());
    buf.extend_from_slice(&crc.to_be_bytes());
    buf.extend_from_slice(&payload_len.to_be_bytes());
    buf.extend_from_slice(&entry.sequence.to_be_bytes());
    buf.extend_from_slice(&entry.prev_hash);
    buf.extend_from_slice(&entry.payload);
    buf
}

/// Decode a single journal entry from bytes at the given offset.
/// Returns the entry and the number of bytes consumed.
pub fn decode_entry(data: &[u8], offset: usize) -> Result<(JournalEntry, usize), ChangesetError> {
    if offset + ENTRY_HEADER_SIZE > data.len() {
        return Err(ChangesetError::Truncated {
            needed: offset + ENTRY_HEADER_SIZE,
            available: data.len(),
        });
    }

    let pos = offset;
    let stored_crc = u32::from_be_bytes(data[pos..pos + 4].try_into().expect("4 bytes"));
    let payload_len = u32::from_be_bytes(data[pos + 4..pos + 8].try_into().expect("4 bytes"));
    let sequence = u64::from_be_bytes(data[pos + 8..pos + 16].try_into().expect("8 bytes"));

    let mut prev_hash = [0u8; 32];
    prev_hash.copy_from_slice(&data[pos + 16..pos + 48]);

    let payload_start = pos + ENTRY_HEADER_SIZE;
    let payload_end = payload_start + payload_len as usize;

    if payload_end > data.len() {
        return Err(ChangesetError::Truncated {
            needed: payload_end,
            available: data.len(),
        });
    }

    let payload = data[payload_start..payload_end].to_vec();

    // Verify CRC32C
    let computed_crc = compute_entry_crc32c(payload_len, sequence, &prev_hash, &payload);
    if computed_crc != stored_crc {
        return Err(ChangesetError::ChecksumMismatch {
            expected: stored_crc as u64,
            actual: computed_crc as u64,
        });
    }

    let entry = JournalEntry {
        sequence,
        prev_hash,
        payload,
    };
    let consumed = ENTRY_HEADER_SIZE + payload_len as usize;
    Ok((entry, consumed))
}

// ============================================================================
// Segment-level operations
// ============================================================================

/// Encode a header to bytes.
pub fn encode_header(header: &JournalHeader) -> [u8; HEADER_SIZE] {
    let mut buf = [0u8; HEADER_SIZE];
    buf[0..5].copy_from_slice(&HADBJ_MAGIC);
    buf[5] = HADBJ_VERSION;
    buf[6] = header.flags;
    buf[7] = header.compression;
    // 8-11: reserved (zeros)
    buf[12..20].copy_from_slice(&header.first_seq.to_be_bytes());
    buf[20..28].copy_from_slice(&header.last_seq.to_be_bytes());
    buf[28..36].copy_from_slice(&header.entry_count.to_be_bytes());
    buf[36..44].copy_from_slice(&header.body_len.to_be_bytes());
    buf[44..76].copy_from_slice(&header.body_checksum);
    buf[76..84].copy_from_slice(&header.prev_segment_checksum.to_be_bytes());
    buf[84..92].copy_from_slice(&header.created_ms.to_be_bytes());
    // 92-127: reserved (zeros)
    buf
}

/// Decode a header from bytes.
pub fn decode_header(data: &[u8]) -> Result<JournalHeader, ChangesetError> {
    if data.len() < HEADER_SIZE {
        return Err(ChangesetError::Truncated {
            needed: HEADER_SIZE,
            available: data.len(),
        });
    }

    if &data[0..5] != &HADBJ_MAGIC {
        return Err(ChangesetError::InvalidMagic);
    }
    if data[5] != HADBJ_VERSION {
        return Err(ChangesetError::UnsupportedVersion(data[5]));
    }

    let flags = data[6];
    let compression = data[7];

    let first_seq = u64::from_be_bytes(data[12..20].try_into().expect("8 bytes"));
    let last_seq = u64::from_be_bytes(data[20..28].try_into().expect("8 bytes"));
    let entry_count = u64::from_be_bytes(data[28..36].try_into().expect("8 bytes"));
    let body_len = u64::from_be_bytes(data[36..44].try_into().expect("8 bytes"));

    let mut body_checksum = [0u8; 32];
    body_checksum.copy_from_slice(&data[44..76]);

    let prev_segment_checksum = u64::from_be_bytes(data[76..84].try_into().expect("8 bytes"));
    let created_ms = i64::from_be_bytes(data[84..92].try_into().expect("8 bytes"));

    Ok(JournalHeader {
        flags,
        compression,
        first_seq,
        last_seq,
        entry_count,
        body_len,
        body_checksum,
        prev_segment_checksum,
        created_ms,
    })
}

/// Create a new sealed journal segment from entries.
///
/// Entries must be provided in sequence order. The chain hash is computed
/// by walking the entries and verifying/computing prev_hash for each.
///
/// `prev_hash` is the chain hash from the previous segment (or ZERO_HASH for the first).
/// `prev_segment_checksum` is the truncated checksum from the previous segment (or 0).
pub fn seal(
    entries: Vec<JournalEntry>,
    prev_segment_checksum: u64,
) -> JournalSegment {
    assert!(!entries.is_empty(), "cannot seal an empty journal segment");

    let first_seq = entries[0].sequence;
    let last_seq = entries[entries.len() - 1].sequence;
    let entry_count = entries.len() as u64;

    // Encode raw body
    let mut body = Vec::new();
    for entry in &entries {
        body.extend_from_slice(&encode_entry(entry));
    }

    // Compute body checksum
    let body_checksum = {
        let mut hasher = Sha256::new();
        hasher.update(&body);
        let result = hasher.finalize();
        let mut cs = [0u8; 32];
        cs.copy_from_slice(&result);
        cs
    };

    // Chain hash is the last entry's hash
    let chain_hash = compute_entry_hash(
        &entries[entries.len() - 1].prev_hash,
        &entries[entries.len() - 1].payload,
    );

    let created_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);

    let header = JournalHeader {
        flags: FLAG_SEALED | FLAG_HAS_CHAIN_HASH,
        compression: COMPRESSION_NONE,
        first_seq,
        last_seq,
        entry_count,
        body_len: body.len() as u64,
        body_checksum,
        prev_segment_checksum,
        created_ms,
    };

    JournalSegment {
        header,
        entries,
        chain_hash,
    }
}

/// Encode a sealed journal segment to bytes.
pub fn encode(segment: &JournalSegment) -> Vec<u8> {
    let mut body = Vec::new();
    for entry in &segment.entries {
        body.extend_from_slice(&encode_entry(entry));
    }

    let total = HEADER_SIZE + body.len() + CHAIN_HASH_TRAILER_SIZE;
    let mut buf = Vec::with_capacity(total);

    buf.extend_from_slice(&encode_header(&segment.header));
    buf.extend_from_slice(&body);
    buf.extend_from_slice(&segment.chain_hash);

    buf
}

/// Encode a sealed journal segment with zstd compression.
#[cfg(feature = "journal")]
pub fn encode_compressed(segment: &JournalSegment, zstd_level: i32) -> Vec<u8> {
    let mut raw_body = Vec::new();
    for entry in &segment.entries {
        raw_body.extend_from_slice(&encode_entry(entry));
    }

    let compressed = zstd::encode_all(raw_body.as_slice(), zstd_level)
        .expect("zstd compression should not fail");

    let body_checksum = {
        let mut hasher = Sha256::new();
        hasher.update(&compressed);
        let result = hasher.finalize();
        let mut cs = [0u8; 32];
        cs.copy_from_slice(&result);
        cs
    };

    let mut header = segment.header.clone();
    header.flags |= FLAG_COMPRESSED;
    header.compression = COMPRESSION_ZSTD;
    header.body_len = compressed.len() as u64;
    header.body_checksum = body_checksum;

    let total = HEADER_SIZE + compressed.len() + CHAIN_HASH_TRAILER_SIZE;
    let mut buf = Vec::with_capacity(total);

    buf.extend_from_slice(&encode_header(&header));
    buf.extend_from_slice(&compressed);
    buf.extend_from_slice(&segment.chain_hash);

    buf
}

/// Decode a sealed journal segment from bytes.
///
/// Handles both raw and compressed bodies. Verifies body checksum,
/// per-entry CRC32C, and SHA-256 chain.
pub fn decode(data: &[u8]) -> Result<JournalSegment, ChangesetError> {
    let header = decode_header(data)?;

    if !header.is_sealed() {
        return Err(ChangesetError::InvalidFlags(header.flags));
    }

    let body_start = HEADER_SIZE;
    let body_end = body_start + header.body_len as usize;

    if body_end > data.len() {
        return Err(ChangesetError::Truncated {
            needed: body_end,
            available: data.len(),
        });
    }

    let body_bytes = &data[body_start..body_end];

    // Verify body checksum
    let computed_body_checksum = {
        let mut hasher = Sha256::new();
        hasher.update(body_bytes);
        let result = hasher.finalize();
        let mut cs = [0u8; 32];
        cs.copy_from_slice(&result);
        cs
    };
    if computed_body_checksum != header.body_checksum {
        return Err(ChangesetError::ChecksumMismatch {
            expected: u64::from_be_bytes(header.body_checksum[0..8].try_into().expect("8 bytes")),
            actual: u64::from_be_bytes(computed_body_checksum[0..8].try_into().expect("8 bytes")),
        });
    }

    // Decompress if needed
    let raw_body: Vec<u8> = if header.is_compressed() {
        #[cfg(feature = "journal")]
        {
            zstd::decode_all(body_bytes)
                .map_err(|e| ChangesetError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?
        }
        #[cfg(not(feature = "journal"))]
        {
            return Err(ChangesetError::InvalidFlags(header.flags));
        }
    } else {
        body_bytes.to_vec()
    };

    // Decode entries
    let mut entries = Vec::with_capacity(header.entry_count as usize);
    let mut offset = 0;
    while offset < raw_body.len() {
        let (entry, consumed) = decode_entry(&raw_body, offset)?;
        entries.push(entry);
        offset += consumed;
    }

    if entries.len() as u64 != header.entry_count {
        return Err(ChangesetError::Truncated {
            needed: header.entry_count as usize,
            available: entries.len(),
        });
    }

    // Verify chain: walk entries and check prev_hash linkage
    let mut running_hash = if !entries.is_empty() {
        entries[0].prev_hash
    } else {
        ZERO_HASH
    };

    for entry in &entries {
        if entry.prev_hash != running_hash {
            return Err(ChangesetError::ChainBroken {
                expected: u64::from_be_bytes(running_hash[0..8].try_into().expect("8 bytes")),
                changeset_prev: u64::from_be_bytes(entry.prev_hash[0..8].try_into().expect("8 bytes")),
            });
        }
        running_hash = compute_entry_hash(&entry.prev_hash, &entry.payload);
    }

    // Read chain hash trailer if present
    let chain_hash = if header.has_chain_hash() {
        let trailer_start = body_end;
        let trailer_end = trailer_start + CHAIN_HASH_TRAILER_SIZE;
        if trailer_end > data.len() {
            return Err(ChangesetError::Truncated {
                needed: trailer_end,
                available: data.len(),
            });
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[trailer_start..trailer_end]);

        // Verify trailer matches computed chain
        if hash != running_hash {
            return Err(ChangesetError::ChecksumMismatch {
                expected: u64::from_be_bytes(hash[0..8].try_into().expect("8 bytes")),
                actual: u64::from_be_bytes(running_hash[0..8].try_into().expect("8 bytes")),
            });
        }
        hash
    } else {
        running_hash
    };

    Ok(JournalSegment {
        header,
        entries,
        chain_hash,
    })
}

/// Build a chain of journal entries from opaque payloads.
///
/// Given a starting prev_hash and a sequence of (seq, payload) pairs,
/// constructs JournalEntry values with correct prev_hash linkage.
pub fn build_entry_chain(
    start_prev_hash: [u8; 32],
    payloads: Vec<(u64, Vec<u8>)>,
) -> Vec<JournalEntry> {
    let mut entries = Vec::with_capacity(payloads.len());
    let mut prev_hash = start_prev_hash;

    for (seq, payload) in payloads {
        let entry = JournalEntry {
            sequence: seq,
            prev_hash,
            payload: payload.clone(),
        };
        prev_hash = compute_entry_hash(&prev_hash, &payload);
        entries.push(entry);
    }

    entries
}

/// Truncate a SHA-256 hash to u64 (for prev_segment_checksum compatibility).
pub fn hash_to_u64(hash: &[u8; 32]) -> u64 {
    u64::from_be_bytes(hash[0..8].try_into().expect("32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_payloads(count: u64) -> Vec<(u64, Vec<u8>)> {
        (1..=count)
            .map(|seq| (seq, format!("query_{}", seq).into_bytes()))
            .collect()
    }

    // --- Entry encode/decode ---

    #[test]
    fn test_entry_roundtrip() {
        let entry = JournalEntry {
            sequence: 42,
            prev_hash: ZERO_HASH,
            payload: b"CREATE TABLE foo (id INT)".to_vec(),
        };

        let encoded = encode_entry(&entry);
        let (decoded, consumed) = decode_entry(&encoded, 0).unwrap();

        assert_eq!(decoded, entry);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_entry_crc_detects_corruption() {
        let entry = JournalEntry {
            sequence: 1,
            prev_hash: ZERO_HASH,
            payload: b"hello".to_vec(),
        };

        let mut encoded = encode_entry(&entry);
        // Corrupt a payload byte
        let last = encoded.len() - 1;
        encoded[last] ^= 0xFF;

        let result = decode_entry(&encoded, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_entry_truncated() {
        let entry = JournalEntry {
            sequence: 1,
            prev_hash: ZERO_HASH,
            payload: b"data".to_vec(),
        };

        let encoded = encode_entry(&entry);
        let result = decode_entry(&encoded[..ENTRY_HEADER_SIZE - 1], 0);
        assert!(matches!(result, Err(ChangesetError::Truncated { .. })));
    }

    #[test]
    fn test_entry_empty_payload() {
        let entry = JournalEntry {
            sequence: 1,
            prev_hash: ZERO_HASH,
            payload: vec![],
        };

        let encoded = encode_entry(&entry);
        let (decoded, _) = decode_entry(&encoded, 0).unwrap();
        assert_eq!(decoded.payload.len(), 0);
    }

    // --- Chain hash ---

    #[test]
    fn test_chain_hash_deterministic() {
        let h1 = compute_entry_hash(&ZERO_HASH, b"hello");
        let h2 = compute_entry_hash(&ZERO_HASH, b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_chain_hash_different_data() {
        let h1 = compute_entry_hash(&ZERO_HASH, b"hello");
        let h2 = compute_entry_hash(&ZERO_HASH, b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_chain_hash_different_prev() {
        let h1 = compute_entry_hash(&ZERO_HASH, b"hello");
        let other_prev = compute_entry_hash(&ZERO_HASH, b"seed");
        let h2 = compute_entry_hash(&other_prev, b"hello");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_chain_linkage() {
        let entries = build_entry_chain(ZERO_HASH, make_payloads(3));

        assert_eq!(entries[0].prev_hash, ZERO_HASH);
        let h0 = compute_entry_hash(&ZERO_HASH, &entries[0].payload);
        assert_eq!(entries[1].prev_hash, h0);
        let h1 = compute_entry_hash(&h0, &entries[1].payload);
        assert_eq!(entries[2].prev_hash, h1);
    }

    // --- Segment seal/encode/decode ---

    #[test]
    fn test_segment_roundtrip() {
        let entries = build_entry_chain(ZERO_HASH, make_payloads(5));
        let segment = seal(entries, 0);

        assert_eq!(segment.header.first_seq, 1);
        assert_eq!(segment.header.last_seq, 5);
        assert_eq!(segment.header.entry_count, 5);
        assert!(segment.header.is_sealed());
        assert!(segment.header.has_chain_hash());

        let encoded = encode(&segment);
        let decoded = decode(&encoded).unwrap();

        assert_eq!(decoded.header.first_seq, segment.header.first_seq);
        assert_eq!(decoded.header.last_seq, segment.header.last_seq);
        assert_eq!(decoded.header.entry_count, segment.header.entry_count);
        assert_eq!(decoded.entries.len(), 5);
        assert_eq!(decoded.chain_hash, segment.chain_hash);

        for (orig, dec) in segment.entries.iter().zip(decoded.entries.iter()) {
            assert_eq!(orig.sequence, dec.sequence);
            assert_eq!(orig.payload, dec.payload);
            assert_eq!(orig.prev_hash, dec.prev_hash);
        }
    }

    #[test]
    fn test_segment_single_entry() {
        let entries = build_entry_chain(ZERO_HASH, vec![(1, b"single".to_vec())]);
        let segment = seal(entries, 0);
        let decoded = decode(&encode(&segment)).unwrap();
        assert_eq!(decoded.entries.len(), 1);
        assert_eq!(decoded.header.first_seq, 1);
        assert_eq!(decoded.header.last_seq, 1);
    }

    #[test]
    fn test_segment_large_payloads() {
        let payloads: Vec<(u64, Vec<u8>)> = (1..=10)
            .map(|seq| (seq, vec![seq as u8; 10_000]))
            .collect();
        let entries = build_entry_chain(ZERO_HASH, payloads);
        let segment = seal(entries, 0);
        let decoded = decode(&encode(&segment)).unwrap();
        assert_eq!(decoded.entries.len(), 10);
        for (i, entry) in decoded.entries.iter().enumerate() {
            assert_eq!(entry.payload.len(), 10_000);
            assert_eq!(entry.payload[0], (i + 1) as u8);
        }
    }

    #[test]
    fn test_segment_prev_segment_checksum() {
        let entries = build_entry_chain(ZERO_HASH, make_payloads(3));
        let segment = seal(entries, 0xDEADBEEF);
        assert_eq!(segment.header.prev_segment_checksum, 0xDEADBEEF);

        let decoded = decode(&encode(&segment)).unwrap();
        assert_eq!(decoded.header.prev_segment_checksum, 0xDEADBEEF);
    }

    #[test]
    fn test_segment_chain_across_segments() {
        // Segment 1: entries 1-3
        let entries1 = build_entry_chain(ZERO_HASH, make_payloads(3));
        let seg1 = seal(entries1, 0);

        // Segment 2: entries 4-6, chained from segment 1
        let payloads2: Vec<(u64, Vec<u8>)> = (4..=6)
            .map(|seq| (seq, format!("query_{}", seq).into_bytes()))
            .collect();
        let entries2 = build_entry_chain(seg1.chain_hash, payloads2);
        let seg2 = seal(entries2, hash_to_u64(&seg1.chain_hash));

        assert_eq!(seg2.header.prev_segment_checksum, hash_to_u64(&seg1.chain_hash));
        assert_eq!(seg2.entries[0].prev_hash, seg1.chain_hash);

        // Both decode independently
        let dec1 = decode(&encode(&seg1)).unwrap();
        let dec2 = decode(&encode(&seg2)).unwrap();
        assert_eq!(dec1.chain_hash, seg1.chain_hash);
        assert_eq!(dec2.entries[0].prev_hash, dec1.chain_hash);
    }

    // --- Negative tests ---

    #[test]
    fn test_decode_bad_magic() {
        let entries = build_entry_chain(ZERO_HASH, make_payloads(1));
        let segment = seal(entries, 0);
        let mut encoded = encode(&segment);
        encoded[0] = b'X';
        assert!(matches!(decode(&encoded), Err(ChangesetError::InvalidMagic)));
    }

    #[test]
    fn test_decode_bad_version() {
        let entries = build_entry_chain(ZERO_HASH, make_payloads(1));
        let segment = seal(entries, 0);
        let mut encoded = encode(&segment);
        encoded[5] = 99;
        assert!(matches!(decode(&encoded), Err(ChangesetError::UnsupportedVersion(99))));
    }

    #[test]
    fn test_decode_truncated_header() {
        assert!(matches!(
            decode(&[0u8; 10]),
            Err(ChangesetError::Truncated { .. })
        ));
    }

    #[test]
    fn test_decode_truncated_body() {
        let entries = build_entry_chain(ZERO_HASH, make_payloads(1));
        let segment = seal(entries, 0);
        let encoded = encode(&segment);
        // Cut off body
        assert!(matches!(
            decode(&encoded[..HEADER_SIZE + 5]),
            Err(ChangesetError::Truncated { .. })
        ));
    }

    #[test]
    fn test_decode_corrupted_body() {
        let entries = build_entry_chain(ZERO_HASH, make_payloads(1));
        let segment = seal(entries, 0);
        let mut encoded = encode(&segment);
        // Corrupt a byte in the body
        encoded[HEADER_SIZE + 10] ^= 0xFF;
        assert!(matches!(
            decode(&encoded),
            Err(ChangesetError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn test_decode_corrupted_chain_trailer() {
        let entries = build_entry_chain(ZERO_HASH, make_payloads(1));
        let segment = seal(entries, 0);
        let mut encoded = encode(&segment);
        // Corrupt last byte (chain hash trailer)
        let last = encoded.len() - 1;
        encoded[last] ^= 0xFF;
        assert!(matches!(
            decode(&encoded),
            Err(ChangesetError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn test_decode_broken_entry_chain() {
        // Manually create entries with broken chain
        let entry1 = JournalEntry {
            sequence: 1,
            prev_hash: ZERO_HASH,
            payload: b"first".to_vec(),
        };
        let entry2 = JournalEntry {
            sequence: 2,
            prev_hash: ZERO_HASH, // Wrong! Should be hash of entry1
            payload: b"second".to_vec(),
        };

        // Build raw body manually (bypass seal which would compute correct hashes)
        let mut body = Vec::new();
        body.extend_from_slice(&encode_entry(&entry1));
        body.extend_from_slice(&encode_entry(&entry2));

        let body_checksum = {
            let mut hasher = Sha256::new();
            hasher.update(&body);
            let result = hasher.finalize();
            let mut cs = [0u8; 32];
            cs.copy_from_slice(&result);
            cs
        };

        let header = JournalHeader {
            flags: FLAG_SEALED,
            compression: COMPRESSION_NONE,
            first_seq: 1,
            last_seq: 2,
            entry_count: 2,
            body_len: body.len() as u64,
            body_checksum,
            prev_segment_checksum: 0,
            created_ms: 0,
        };

        let mut buf = Vec::new();
        buf.extend_from_slice(&encode_header(&header));
        buf.extend_from_slice(&body);

        assert!(matches!(
            decode(&buf),
            Err(ChangesetError::ChainBroken { .. })
        ));
    }

    #[test]
    #[should_panic(expected = "cannot seal an empty journal segment")]
    fn test_seal_empty_panics() {
        seal(vec![], 0);
    }

    // --- Compression tests (feature-gated) ---

    #[cfg(feature = "journal")]
    #[test]
    fn test_compressed_roundtrip() {
        let entries = build_entry_chain(ZERO_HASH, make_payloads(20));
        let segment = seal(entries, 0);

        let compressed = encode_compressed(&segment, 3);
        let raw = encode(&segment);

        // Compressed should be smaller (repetitive payloads compress well)
        assert!(compressed.len() < raw.len());

        let decoded = decode(&compressed).unwrap();
        assert_eq!(decoded.entries.len(), 20);
        assert_eq!(decoded.chain_hash, segment.chain_hash);
        assert!(decoded.header.is_compressed());
    }

    #[cfg(feature = "journal")]
    #[test]
    fn test_compressed_large_payloads() {
        let payloads: Vec<(u64, Vec<u8>)> = (1..=50)
            .map(|seq| (seq, vec![0xAA; 1000]))
            .collect();
        let entries = build_entry_chain(ZERO_HASH, payloads);
        let segment = seal(entries, 0);

        let compressed = encode_compressed(&segment, 3);
        let decoded = decode(&compressed).unwrap();
        assert_eq!(decoded.entries.len(), 50);
    }

    // --- build_entry_chain ---

    #[test]
    fn test_build_entry_chain_empty() {
        let entries = build_entry_chain(ZERO_HASH, vec![]);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_build_entry_chain_custom_start_hash() {
        let custom_hash = compute_entry_hash(&ZERO_HASH, b"seed");
        let entries = build_entry_chain(custom_hash, make_payloads(2));
        assert_eq!(entries[0].prev_hash, custom_hash);
    }

    // --- hash_to_u64 ---

    #[test]
    fn test_hash_to_u64() {
        let hash = compute_entry_hash(&ZERO_HASH, b"test");
        let val = hash_to_u64(&hash);
        assert_ne!(val, 0);
        // Deterministic
        assert_eq!(val, hash_to_u64(&hash));
    }
}
