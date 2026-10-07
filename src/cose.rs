//! Builds a `COSE_Sign1` structure over an existing `SUIT_Digest` bstr and returns the
//! bstr-wrapped, tagged block ready to append to `SUIT_Authentication`.

use ciborium::value::Value;

use crate::{error::Error, keys::Signer};

/// CBOR tag number for `COSE_Sign1_Tagged` (RFC 9052 Section 4.2).
const COSE_SIGN1_TAG: u64 = 18;

/// Builds the CBOR-encoded `Sig_structure` ("Signature1") for `protected` + `payload`.
fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let structure = Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(Vec::new()), // external_aad: always empty for SUIT signing
        Value::Bytes(payload.to_vec()),
    ]);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&structure, &mut out)
        .expect("encoding a hand-built Sig_structure Value cannot fail");
    out
}

/// Signs `digest_bstr` (the exact bytes of the existing `bstr .cbor SUIT_Digest`) with
/// `signer` and returns a `bstr`-wrapped detached-payload `COSE_Sign1_Tagged`
/// (`#6.18(...)`) block.
pub fn sign_digest(digest_bstr: &[u8], signer: &Signer) -> Result<Vec<u8>, Error> {
    let protected_header = Value::Map(vec![(Value::from(1i64), Value::from(signer.alg_id() as i64))]);
    let mut protected = Vec::new();
    ciborium::ser::into_writer(&protected_header, &mut protected)
        .map_err(|e| Error::InvalidEnvelope(format!("failed to encode protected header: {e}")))?;

    let signature = signer.sign(&sig_structure(&protected, digest_bstr));

    let cose_sign1 = Value::Array(vec![
        Value::Bytes(protected),
        Value::Map(Vec::new()), // unprotected header: empty, no `kid` for v1
        Value::Null, // SUIT uses detached payload mode; digest_bstr is supplied externally
        Value::Bytes(signature),
    ]);

    let mut tagged = Vec::new();
    ciborium::ser::into_writer(&Value::Tag(COSE_SIGN1_TAG, Box::new(cose_sign1)), &mut tagged)
        .map_err(|e| Error::InvalidEnvelope(format!("failed to encode COSE_Sign1: {e}")))?;

    let mut wrapped = Vec::new();
    ciborium::ser::into_writer(&Value::Bytes(tagged), &mut wrapped)
        .map_err(|e| Error::InvalidEnvelope(format!("failed to bstr-wrap COSE_Sign1: {e}")))?;
    Ok(wrapped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Algorithm;

    const ES256_PKCS8_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmszCRujRlOLiEywZ
h5wBh+Hzz3S/N9v/isf0zgmnbh2hRANCAAQ00s4XENy+WZ5ISICdRcSuwCaQ1WUA
WXSFBkWRMYSvj7UfvonsDFML67YB2F6MR5LrF+FGHh7yFSCekjzRCwQ5
-----END PRIVATE KEY-----";

    #[test]
    fn sig_structure_matches_known_answer() {
        // Fixed protected header bytes for alg -7 (ES256): {1: -7}.
        let protected = [0xa1, 0x01, 0x26];
        let payload = b"fixed-digest-bytes";
        let got = sig_structure(&protected, payload);

        // ["Signature1", h'A10126', h'', h'6669786564...'] built by hand via ciborium.
        let expected = Value::Array(vec![
            Value::Text("Signature1".into()),
            Value::Bytes(protected.to_vec()),
            Value::Bytes(Vec::new()),
            Value::Bytes(payload.to_vec()),
        ]);
        let mut expected_bytes = Vec::new();
        ciborium::ser::into_writer(&expected, &mut expected_bytes).unwrap();
        assert_eq!(got, expected_bytes);
    }

    #[test]
    fn sign_digest_is_deterministic_for_same_inputs() {
        let signer = Signer::from_pem(ES256_PKCS8_PEM, Algorithm::Es256).unwrap();
        let digest = b"a-fixed-suit-digest-bstr-content";
        let a = sign_digest(digest, &signer).unwrap();
        let b = sign_digest(digest, &signer).unwrap();
        // ECDSA here is deterministic (RFC 6979), so byte-exact reproducibility is expected.
        assert_eq!(a, b);
    }

    #[test]
    fn sign_digest_decodes_as_tagged_cose_sign1() {
        let signer = Signer::from_pem(ES256_PKCS8_PEM, Algorithm::Es256).unwrap();
        let digest = b"another-fixed-suit-digest-bstr";
        let wrapped = sign_digest(digest, &signer).unwrap();

        // Outer layer: a bstr whose contents decode to Tag(18, [protected, {}, null, sig]).
        let outer: Value = ciborium::de::from_reader(wrapped.as_slice()).unwrap();
        let inner_bytes = match outer {
            Value::Bytes(b) => b,
            other => panic!("expected outer bstr, got {other:?}"),
        };
        let inner: Value = ciborium::de::from_reader(inner_bytes.as_slice()).unwrap();
        let (tag, array) = match inner {
            Value::Tag(tag, boxed) => (tag, *boxed),
            other => panic!("expected Tag(18, ..), got {other:?}"),
        };
        assert_eq!(tag, COSE_SIGN1_TAG);

        let elements = match array {
            Value::Array(elements) => elements,
            other => panic!("expected 4-element array, got {other:?}"),
        };
        assert_eq!(elements.len(), 4);
        assert_eq!(elements[2], Value::Null);
        match &elements[3] {
            Value::Bytes(sig) => assert_eq!(sig.len(), 64), // ES256: r||s = 64 bytes
            other => panic!("expected signature bstr, got {other:?}"),
        }
    }
}
