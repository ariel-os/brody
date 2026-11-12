//! Parses/patches the top-level `SUIT_Envelope` CBOR map, independent of taylor's crate.

use ciborium::value::Value;

use crate::error::Error;

/// Map key for `suit-authentication-wrapper` within `SUIT_Envelope`.
const SUIT_AUTHENTICATION_WRAPPER: i128 = 2;

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
        _ => Err(Error::InvalidEnvelope(
            "top-level CBOR item is not a map".into(),
        )),
    }
}

/// Mutably borrows the `SUIT_Envelope`'s top-level map, unwrapping a leading tag if present.
fn envelope_map_mut(value: &mut Value) -> Result<&mut Vec<(Value, Value)>, Error> {
    match value {
        Value::Map(m) => Ok(m),
        Value::Tag(_, inner) => envelope_map_mut(inner),
        _ => Err(Error::InvalidEnvelope(
            "top-level CBOR item is not a map".into(),
        )),
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
    let value: Value = ciborium::de::from_reader(auth_array_bytes).map_err(|e| {
        Error::InvalidEnvelope(format!("failed to decode SUIT_Authentication: {e}"))
    })?;
    match value {
        Value::Array(elements) => match elements.first() {
            Some(Value::Bytes(b)) => Ok(b.clone()),
            Some(_) => Err(Error::InvalidEnvelope(
                "SUIT_Authentication[0] is not a bstr".into(),
            )),
            None => Err(Error::InvalidEnvelope(
                "SUIT_Authentication array is empty".into(),
            )),
        },
        _ => Err(Error::InvalidEnvelope(
            "SUIT_Authentication is not an array".into(),
        )),
    }
}

/// Appends `block_bytes` (a single serialized CBOR item, e.g. from `cose::sign_digest`) as a
/// new element of a decoded `SUIT_Authentication` array, and re-encodes the whole array.
pub fn append_authentication_block(
    auth_array_bytes: &[u8],
    block_bytes: &[u8],
) -> Result<Vec<u8>, Error> {
    let value: Value = ciborium::de::from_reader(auth_array_bytes).map_err(|e| {
        Error::InvalidEnvelope(format!("failed to decode SUIT_Authentication: {e}"))
    })?;
    let mut elements = match value {
        Value::Array(elements) => elements,
        _ => {
            return Err(Error::InvalidEnvelope(
                "SUIT_Authentication is not an array".into(),
            ));
        }
    };

    let block: Value = ciborium::de::from_reader(block_bytes).map_err(|e| {
        Error::InvalidEnvelope(format!("failed to decode authentication block: {e}"))
    })?;
    elements.push(block);

    let mut out = Vec::new();
    ciborium::ser::into_writer(&Value::Array(elements), &mut out).map_err(|e| {
        Error::InvalidEnvelope(format!("failed to encode SUIT_Authentication: {e}"))
    })?;
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
        let map = Value::Map(vec![(
            Value::from(3i64),
            Value::Bytes(b"manifest".to_vec()),
        )]);
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
        assert_eq!(
            extract_authentication(&replaced).unwrap(),
            b"new-auth-block"
        );
    }

    #[test]
    fn replace_errors_on_missing_key() {
        let map = Value::Map(vec![(
            Value::from(3i64),
            Value::Bytes(b"manifest".to_vec()),
        )]);
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
}
