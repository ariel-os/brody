//! brody: library for signing `SUIT_Envelope` CBOR manifests with a `COSE_Sign1`
//! authentication block (ES256/ES384), for use as a dependency by other Rust projects.
//!
//! For most use cases, [`sign_envelope`] is the only entry point needed. The `cose`,
//! `envelope`, and `keys` modules are public for callers that need finer-grained control
//! over individual pipeline steps (e.g. inspecting the digest before signing).

pub mod cose;
pub mod envelope;
pub mod error;
pub mod keys;

pub use error::Error;
pub use keys::{Algorithm, Signer};

/// Signs `envelope_bytes` (a full `SUIT_Envelope` CBOR blob) with `signer`: extracts the
/// existing `SUIT_Digest`, signs it, and appends a new `COSE_Sign1_Tagged` authentication
/// block, returning the re-encoded envelope bytes.
pub fn sign_envelope(envelope_bytes: &[u8], signer: &Signer) -> Result<Vec<u8>, Error> {
    let auth_array_bytes = envelope::extract_authentication(envelope_bytes)?;
    let digest_bstr = envelope::digest_from_authentication(&auth_array_bytes)?;
    let auth_block = cose::sign_digest(&digest_bstr, signer)?;
    let new_auth_array_bytes =
        envelope::append_authentication_block(&auth_array_bytes, &auth_block)?;
    envelope::replace_authentication(envelope_bytes, &new_auth_array_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Value;

    // Throwaway P-256 test key (PKCS8 PEM), generated solely for this test via:
    // `openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt`
    const ES256_PKCS8_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmszCRujRlOLiEywZ
h5wBh+Hzz3S/N9v/isf0zgmnbh2hRANCAAQ00s4XENy+WZ5ISICdRcSuwCaQ1WUA
WXSFBkWRMYSvj7UfvonsDFML67YB2F6MR5LrF+FGHh7yFSCekjzRCwQ5
-----END PRIVATE KEY-----";

    fn build_test_envelope(digest: &[u8], manifest: &[u8]) -> Vec<u8> {
        let auth_array = Value::Array(vec![Value::Bytes(digest.to_vec())]);
        let mut auth_array_bytes = Vec::new();
        ciborium::ser::into_writer(&auth_array, &mut auth_array_bytes).unwrap();

        let envelope = Value::Map(vec![
            (Value::from(2i64), Value::Bytes(auth_array_bytes)),
            (Value::from(3i64), Value::Bytes(manifest.to_vec())),
        ]);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&envelope, &mut out).unwrap();
        out
    }

    #[test]
    fn sign_envelope_appends_block_and_preserves_manifest() {
        let digest = b"fixed-digest-for-lib-test".to_vec();
        let manifest = b"fixed-manifest-for-lib-test".to_vec();
        let envelope_bytes = build_test_envelope(&digest, &manifest);

        let signer = Signer::from_pem(ES256_PKCS8_PEM, Algorithm::Es256).unwrap();
        let signed = sign_envelope(&envelope_bytes, &signer).unwrap();

        let auth_array_bytes = envelope::extract_authentication(&signed).unwrap();
        let value: Value = ciborium::de::from_reader(auth_array_bytes.as_slice()).unwrap();
        let elements = match value {
            Value::Array(e) => e,
            other => panic!("expected array, got {other:?}"),
        };
        assert_eq!(
            elements.len(),
            2,
            "expected original digest + one appended auth block"
        );
        assert_eq!(elements[0], Value::Bytes(digest));

        match &elements[1] {
            Value::Bytes(block) => {
                let tagged: Value = ciborium::de::from_reader(block.as_slice()).unwrap();
                assert!(
                    matches!(tagged, Value::Tag(18, _)),
                    "expected COSE_Sign1_Tagged"
                );
            }
            other => panic!("expected bstr, got {other:?}"),
        }
    }

    #[test]
    fn sign_envelope_errors_on_malformed_input() {
        let signer = Signer::from_pem(ES256_PKCS8_PEM, Algorithm::Es256).unwrap();
        assert!(sign_envelope(b"not a cbor envelope", &signer).is_err());
    }
}
