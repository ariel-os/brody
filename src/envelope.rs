//! Parses/patches the top-level `SUIT_Envelope` CBOR map, independent of taylor's crate.

use ciborium::value::Value;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::error::Error;

/// Map key for `suit-authentication-wrapper` within `SUIT_Envelope`.
const SUIT_AUTHENTICATION_WRAPPER: i128 = 2;
/// Map key for `suit-manifest` within `SUIT_Envelope`.
const SUIT_MANIFEST: u64 = 3;

/// COSE hash algorithm IDs (RFC 9054) accepted in `SUIT_Digest`.
const COSE_ALG_SHA_256: i64 = -16;
const COSE_ALG_SHA_384: i64 = -43;
const COSE_ALG_SHA_512: i64 = -44;

/// Reads `bytes` as a `SUIT_Envelope` map and returns the raw `SUIT_Authentication` array
/// bytes (the bstr under key 2, already CBOR-decoded one level).
pub fn extract_authentication(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let value: Value = ciborium::de::from_reader(bytes)
        .map_err(|e| Error::InvalidEnvelope(format!("failed to decode CBOR: {e}")))?;
    let map = envelope_map(&value)?;
    match find_entry(map) {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        Some(_) => Err(Error::InvalidEnvelope(
            "suit-authentication-wrapper (key 2) is not a bstr".into(),
        )),
        None => Err(Error::InvalidEnvelope(
            "missing suit-authentication-wrapper (key 2)".into(),
        )),
    }
}

/// Returns `bytes` with the `suit-authentication-wrapper` (key 2) replaced by
/// `new_auth_wrapper` (an already bstr-wrapped `SUIT_Authentication` array).
pub fn replace_authentication(bytes: &[u8], new_auth_wrapper: &[u8]) -> Result<Vec<u8>, Error> {
    let mut value: Value = ciborium::de::from_reader(bytes)
        .map_err(|e| Error::InvalidEnvelope(format!("failed to decode CBOR: {e}")))?;
    {
        let map = envelope_map_mut(&mut value)?;
        let entry = map
            .iter_mut()
            .find(|(k, _)| *k == Value::from(SUIT_AUTHENTICATION_WRAPPER))
            .ok_or_else(|| {
                Error::InvalidEnvelope("missing suit-authentication-wrapper (key 2)".into())
            })?;
        entry.1 = Value::Bytes(new_auth_wrapper.to_vec());
    }
    let mut out = Vec::new();
    ciborium::ser::into_writer(&value, &mut out)
        .map_err(|e| Error::InvalidEnvelope(format!("failed to encode CBOR: {e}")))?;
    Ok(out)
}

/// Borrows the `SUIT_Envelope`'s top-level map, unwrapping a leading CBOR tag if present.
fn envelope_map(value: &Value) -> Result<&Vec<(Value, Value)>, Error> {
    match value {
        Value::Map(m) => Ok(m),
        Value::Tag(_, inner) => envelope_map(inner),
        _ => Err(Error::InvalidEnvelope("top-level CBOR item is not a map".into())),
    }
}

/// Mutably borrows the `SUIT_Envelope`'s top-level map, unwrapping a leading tag if present.
fn envelope_map_mut(value: &mut Value) -> Result<&mut Vec<(Value, Value)>, Error> {
    match value {
        Value::Map(m) => Ok(m),
        Value::Tag(_, inner) => envelope_map_mut(inner),
        _ => Err(Error::InvalidEnvelope("top-level CBOR item is not a map".into())),
    }
}

/// Finds the value for key `2` (`suit-authentication-wrapper`) in a decoded map.
fn find_entry(map: &[(Value, Value)]) -> Option<&Value> {
    map.iter()
        .find(|(k, _)| *k == Value::from(SUIT_AUTHENTICATION_WRAPPER))
        .map(|(_, v)| v)
}

/// Returns the first element (the `SUIT_Digest` bstr) of a decoded `SUIT_Authentication`
/// array (as returned by [`extract_authentication`]).
pub fn digest_from_authentication(auth_array_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let value: Value = ciborium::de::from_reader(auth_array_bytes)
        .map_err(|e| Error::InvalidEnvelope(format!("failed to decode SUIT_Authentication: {e}")))?;
    match value {
        Value::Array(elements) => match elements.first() {
            Some(Value::Bytes(b)) => Ok(b.clone()),
            Some(_) => Err(Error::InvalidEnvelope("SUIT_Authentication[0] is not a bstr".into())),
            None => Err(Error::InvalidEnvelope("SUIT_Authentication array is empty".into())),
        },
        _ => Err(Error::InvalidEnvelope("SUIT_Authentication is not an array".into())),
    }
}

/// Checks that `digest_bstr` (the `SUIT_Digest` bstr from `SUIT_Authentication[0]`) matches
/// the bstr-wrapped manifest at key 3 of `envelope_bytes`.
/// Signers MUST perform this check before signing.
/// (--> https://www.ietf.org/archive/id/draft-ietf-suit-manifest-37.html#section-8.3)
pub fn verify_manifest_digest(envelope_bytes: &[u8], digest_bstr: &[u8]) -> Result<(), Error> {
    let (alg_id, expected) = parse_suit_digest(digest_bstr)?;
    let manifest_bstr = manifest_bstr_bytes(envelope_bytes)?;
    let computed = hash_with(alg_id, manifest_bstr)?;
    if computed != expected {
        return Err(Error::DigestMismatch(format!(
            "SUIT_Digest is {}, but the manifest hashes to {}",
            hex::encode(&expected),
            hex::encode(&computed)
        )));
    }
    Ok(())
}

/// Decodes a `SUIT_Digest` (`[suit-digest-algorithm-id, suit-digest-bytes, * extensions]`)
/// into its algorithm ID and digest bytes.
fn parse_suit_digest(digest_bstr: &[u8]) -> Result<(i64, Vec<u8>), Error> {
    let value: Value = ciborium::de::from_reader(digest_bstr)
        .map_err(|e| Error::InvalidEnvelope(format!("failed to decode SUIT_Digest: {e}")))?;
    match value.as_array().map(Vec::as_slice) {
        Some([Value::Integer(alg), Value::Bytes(digest), ..]) => {
            let alg = i64::try_from(*alg).map_err(|_| {
                Error::InvalidEnvelope("SUIT_Digest algorithm id is out of range".into())
            })?;
            Ok((alg, digest.clone()))
        }
        _ => Err(Error::InvalidEnvelope(
            "SUIT_Digest must be [algorithm id (int), digest (bstr), ...]".into(),
        )),
    }
}

/// Hashes `data` with the COSE hash algorithm `alg_id`.
fn hash_with(alg_id: i64, data: &[u8]) -> Result<Vec<u8>, Error> {
    match alg_id {
        COSE_ALG_SHA_256 => Ok(Sha256::digest(data).to_vec()),
        COSE_ALG_SHA_384 => Ok(Sha384::digest(data).to_vec()),
        COSE_ALG_SHA_512 => Ok(Sha512::digest(data).to_vec()),
        other => Err(Error::InvalidEnvelope(format!(
            "unsupported SUIT_Digest algorithm id {other}"
        ))),
    }
}

/// Returns the bytes of the `suit-manifest` (key 3) bstr exactly as encoded in `bytes`,
/// including its CBOR header, since that is what `SUIT_Digest` covers. Re-encoding the
/// decoded value could change the header, so the raw slice is located and borrowed instead.
fn manifest_bstr_bytes(bytes: &[u8]) -> Result<&[u8], Error> {
    let (mut major, mut pair_count, mut pos) = read_head(bytes, 0)?;
    while major == 6 {
        // Skip tags wrapping the envelope
        (major, pair_count, pos) = read_head(bytes, pos)?;
    }
    if major != 5 {
        return Err(Error::InvalidEnvelope(
            "top-level CBOR item is not a map".into(),
        ));
    }

    for _ in 0..pair_count {
        let (key_major, key_arg, _) = read_head(bytes, pos)?;
        let value_start = skip_item(bytes, pos)?;
        if key_major == 0 && key_arg == SUIT_MANIFEST {
            let (value_major, len, content_start) = read_head(bytes, value_start)?;
            if value_major != 2 {
                return Err(Error::InvalidEnvelope(
                    "suit-manifest (key 3) is not a bstr".into(),
                ));
            }
            let end = end_offset(bytes, content_start, len)?;
            return Ok(&bytes[value_start..end]);
        }
        pos = skip_item(bytes, value_start)?;
    }
    Err(Error::InvalidEnvelope(
        "missing suit-manifest (key 3)".into(),
    ))
}

/// Reads the initial byte and argument of the CBOR data item at `pos`. Returns the major
/// type, the argument, and the offset of the first byte after the item head.
fn read_head(bytes: &[u8], pos: usize) -> Result<(u8, u64, usize), Error> {
    let initial = *bytes.get(pos).ok_or_else(truncated)?;
    let info = initial & 0x1f;
    let extra = match info {
        0..=23 => 0,
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => {
            return Err(Error::InvalidEnvelope(
                "indefinite-length and reserved CBOR encodings are not supported".into(),
            ));
        }
    };
    let head_end = pos + 1 + extra;
    let arg_bytes = bytes.get(pos + 1..head_end).ok_or_else(truncated)?;
    let arg = if extra == 0 {
        u64::from(info)
    } else {
        arg_bytes
            .iter()
            .fold(0u64, |acc, b| (acc << 8) | u64::from(*b))
    };
    Ok((initial >> 5, arg, head_end))
}

/// Returns the offset just past the CBOR data item starting at `start`, without decoding it.
fn skip_item(bytes: &[u8], start: usize) -> Result<usize, Error> {
    // Items still to skip. Each iteration consumes at least one byte, so saturating counts
    // cannot loop forever on truncated input: `read_head` eventually fails.
    let mut pending: u64 = 1;
    let mut pos = start;
    while pending > 0 {
        let (major, arg, body) = read_head(bytes, pos)?;
        pos = body;
        pending -= 1;
        match major {
            // byte string | text string
            2 | 3 => pos = end_offset(bytes, body, arg)?,
            // array
            4 => pending = pending.saturating_add(arg),
            // map
            5 => pending = pending.saturating_add(arg.saturating_mul(2)),
            // tag
            6 => pending = pending.saturating_add(1),
            _ => {}
        }
    }
    Ok(pos)
}

/// Returns the offset `len` bytes after `start`, or an error if that runs past `bytes`.
fn end_offset(bytes: &[u8], start: usize, len: u64) -> Result<usize, Error> {
    usize::try_from(len)
        .ok()
        .and_then(|len| start.checked_add(len))
        .filter(|end| *end <= bytes.len())
        .ok_or_else(truncated)
}

fn truncated() -> Error {
    Error::InvalidEnvelope("truncated CBOR data".into())
}

/// Appends `block_bytes` (a single serialized CBOR item, e.g. from `cose::sign_digest`) as a
/// new element of a decoded `SUIT_Authentication` array, and re-encodes the whole array.
pub fn append_authentication_block(
    auth_array_bytes: &[u8],
    block_bytes: &[u8],
) -> Result<Vec<u8>, Error> {
    let value: Value = ciborium::de::from_reader(auth_array_bytes)
        .map_err(|e| Error::InvalidEnvelope(format!("failed to decode SUIT_Authentication: {e}")))?;
    let mut elements = match value {
        Value::Array(elements) => elements,
        _ => return Err(Error::InvalidEnvelope("SUIT_Authentication is not an array".into())),
    };

    let block: Value = ciborium::de::from_reader(block_bytes)
        .map_err(|e| Error::InvalidEnvelope(format!("failed to decode authentication block: {e}")))?;
    elements.push(block);

    let mut out = Vec::new();
    ciborium::ser::into_writer(&Value::Array(elements), &mut out)
        .map_err(|e| Error::InvalidEnvelope(format!("failed to encode SUIT_Authentication: {e}")))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_envelope(auth_bytes: &[u8], manifest_bytes: &[u8]) -> Vec<u8> {
        let map = Value::Map(vec![
            (Value::from(2i64), Value::Bytes(auth_bytes.to_vec())),
            (Value::from(3i64), Value::Bytes(manifest_bytes.to_vec())),
        ]);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&map, &mut out).unwrap();
        out
    }

    fn extract_manifest(bytes: &[u8]) -> Vec<u8> {
        let value: Value = ciborium::de::from_reader(bytes).unwrap();
        let map = envelope_map(&value).unwrap();
        map.iter()
            .find(|(k, _)| *k == Value::from(3i64))
            .map(|(_, v)| match v {
                Value::Bytes(b) => b.clone(),
                _ => panic!("expected bytes"),
            })
            .unwrap()
    }

    #[test]
    fn extract_returns_key_2_bytes() {
        let bytes = build_envelope(b"digest-bytes", b"manifest-bytes");
        let auth = extract_authentication(&bytes).unwrap();
        assert_eq!(auth, b"digest-bytes");
    }

    #[test]
    fn extract_errors_on_missing_key() {
        let map = Value::Map(vec![(Value::from(3i64), Value::Bytes(b"manifest".to_vec()))]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&map, &mut bytes).unwrap();
        assert!(extract_authentication(&bytes).is_err());
    }

    #[test]
    fn extract_errors_on_non_map_top_level() {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&Value::Integer(1.into()), &mut bytes).unwrap();
        assert!(extract_authentication(&bytes).is_err());
    }

    #[test]
    fn replace_round_trip_is_byte_identical_for_same_wrapper() {
        let original = build_envelope(b"digest-bytes", b"manifest-bytes");
        let auth = extract_authentication(&original).unwrap();
        let replaced = replace_authentication(&original, &auth).unwrap();
        assert_eq!(replaced, original);
    }

    #[test]
    fn replace_only_touches_key_2() {
        let original = build_envelope(b"digest-bytes", b"manifest-bytes");
        let replaced = replace_authentication(&original, b"new-auth-block").unwrap();
        assert_eq!(extract_manifest(&replaced), extract_manifest(&original));
        assert_eq!(extract_authentication(&replaced).unwrap(), b"new-auth-block");
    }

    #[test]
    fn replace_errors_on_missing_key() {
        let map = Value::Map(vec![(Value::from(3i64), Value::Bytes(b"manifest".to_vec()))]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&map, &mut bytes).unwrap();
        assert!(replace_authentication(&bytes, b"auth").is_err());
    }

    fn build_auth_array(digest: &[u8]) -> Vec<u8> {
        let array = Value::Array(vec![Value::Bytes(digest.to_vec())]);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&array, &mut out).unwrap();
        out
    }

    #[test]
    fn digest_from_authentication_returns_first_element() {
        let auth_array_bytes = build_auth_array(b"the-digest");
        let digest = digest_from_authentication(&auth_array_bytes).unwrap();
        assert_eq!(digest, b"the-digest");
    }

    #[test]
    fn digest_from_authentication_errors_on_empty_array() {
        let array = Value::Array(vec![]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&array, &mut bytes).unwrap();
        assert!(digest_from_authentication(&bytes).is_err());
    }

    #[test]
    fn append_authentication_block_adds_element() {
        let auth_array_bytes = build_auth_array(b"the-digest");
        let mut block_bytes = Vec::new();
        ciborium::ser::into_writer(&Value::Bytes(b"a-block".to_vec()), &mut block_bytes).unwrap();

        let new_array_bytes = append_authentication_block(&auth_array_bytes, &block_bytes).unwrap();
        let value: Value = ciborium::de::from_reader(new_array_bytes.as_slice()).unwrap();
        let elements = match value {
            Value::Array(e) => e,
            other => panic!("expected array, got {other:?}"),
        };
        assert_eq!(elements.len(), 2);
        assert_eq!(elements[0], Value::Bytes(b"the-digest".to_vec()));
        assert_eq!(elements[1], Value::Bytes(b"a-block".to_vec()));
    }

    /// Builds a `SUIT_Digest` bstr `[alg, hash(bstr-wrapped manifest)]` for `manifest`.
    fn suit_digest_for(alg: i64, manifest: &[u8]) -> Vec<u8> {
        let mut manifest_bstr = Vec::new();
        ciborium::ser::into_writer(&Value::Bytes(manifest.to_vec()), &mut manifest_bstr).unwrap();
        let digest = match alg {
            -16 => Sha256::digest(&manifest_bstr).to_vec(),
            -43 => Sha384::digest(&manifest_bstr).to_vec(),
            -44 => Sha512::digest(&manifest_bstr).to_vec(),
            other => panic!("test helper does not support alg {other}"),
        };
        let suit_digest = Value::Array(vec![Value::from(alg), Value::Bytes(digest)]);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&suit_digest, &mut out).unwrap();
        out
    }

    #[test]
    fn manifest_bstr_bytes_keeps_non_minimal_header() {
        // #6.107({2: h'aa', 3: h'58 03 616263'}) where key 3 uses a 1-byte length header for
        // a 3-byte bstr, which is not minimal. The digest must cover those exact bytes.
        let bytes = [
            0xd8, 0x6b, // tag 107
            0xa2, // map(2)
            0x02, 0x41, 0xaa, // 2: h'aa'
            0x03, 0x58, 0x03, b'a', b'b', b'c', // 3: non-minimal bstr "abc"
        ];
        assert_eq!(
            manifest_bstr_bytes(&bytes).unwrap(),
            &[0x58, 0x03, b'a', b'b', b'c']
        );
    }

    #[test]
    fn verify_manifest_digest_accepts_matching_digest_for_each_alg() {
        let manifest = b"manifest-for-digest-check";
        let envelope = build_envelope(&[], manifest);
        for alg in [-16, -43, -44] {
            let digest = suit_digest_for(alg, manifest);
            verify_manifest_digest(&envelope, &digest)
                .unwrap_or_else(|e| panic!("alg {alg} should verify: {e}"));
        }
    }

    #[test]
    fn verify_manifest_digest_rejects_mismatch() {
        let envelope = build_envelope(&[], b"tampered-manifest");
        let digest = suit_digest_for(-16, b"original-manifest");
        let err = verify_manifest_digest(&envelope, &digest).unwrap_err();
        assert!(matches!(err, Error::DigestMismatch(_)), "got {err:?}");
    }

    #[test]
    fn verify_manifest_digest_rejects_unsupported_alg() {
        let manifest = b"manifest-for-digest-check";
        let envelope = build_envelope(&[], manifest);
        // -18 is cose-alg-shake128, which brody does not implement.
        let digest = Value::Array(vec![Value::from(-18i64), Value::Bytes(vec![0; 32])]);
        let mut digest_bytes = Vec::new();
        ciborium::ser::into_writer(&digest, &mut digest_bytes).unwrap();
        let err = verify_manifest_digest(&envelope, &digest_bytes).unwrap_err();
        assert!(matches!(err, Error::InvalidEnvelope(_)), "got {err:?}");
    }
}
