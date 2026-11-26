//! Verifies `COSE_Sign1` authentication blocks in a `SUIT_Envelope` using a PEM-encoded
//! ECDSA public key (P-256/ES256 or P-384/ES384).

use ciborium::value::Value;

use crate::{cose, envelope, error::Error};

/// A loaded ECDSA public key, ready to verify `COSE_Sign1` signatures.
#[derive(Debug, Clone)]
pub enum Verifier {
    /// ES256 (COSE alg -7), NIST P-256.
    Es256(p256::ecdsa::VerifyingKey),
    /// ES384 (COSE alg -35), NIST P-384.
    Es384(p384::ecdsa::VerifyingKey),
}

impl Verifier {
    /// Loads a verifying key from a PEM-encoded SPKI public key (`-----BEGIN PUBLIC KEY-----`),
    /// automatically detecting NIST P-256 (ES256) or NIST P-384 (ES384).
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        use p256::pkcs8::DecodePublicKey as _;

        if let Ok(key) = p256::ecdsa::VerifyingKey::from_public_key_pem(pem) {
            return Ok(Self::Es256(key));
        }
        if let Ok(key) = p384::ecdsa::VerifyingKey::from_public_key_pem(pem) {
            return Ok(Self::Es384(key));
        }
        Err(Error::InvalidKey(
            "failed to parse PEM public key (expected P-256 or P-384 SPKI PEM)".into(),
        ))
    }

    /// COSE algorithm identifier: ES256 = -7, ES384 = -35.
    pub fn alg_id(&self) -> i8 {
        match self {
            Verifier::Es256(_) => -7,
            Verifier::Es384(_) => -35,
        }
    }

    /// Verifies a raw `r || s` ECDSA signature over `msg`.
    pub fn verify(&self, msg: &[u8], sig_bytes: &[u8]) -> Result<(), Error> {
        use signature::Verifier as _;

        match self {
            Verifier::Es256(key) => {
                let sig = p256::ecdsa::Signature::from_slice(sig_bytes).map_err(|e| {
                    Error::VerificationFailed(format!("invalid ES256 signature encoding: {e}"))
                })?;
                key.verify(msg, &sig)
                    .map_err(|e| Error::VerificationFailed(format!("ES256 signature mismatch: {e}")))
            }
            Verifier::Es384(key) => {
                let sig = p384::ecdsa::Signature::from_slice(sig_bytes).map_err(|e| {
                    Error::VerificationFailed(format!("invalid ES384 signature encoding: {e}"))
                })?;
                key.verify(msg, &sig)
                    .map_err(|e| Error::VerificationFailed(format!("ES384 signature mismatch: {e}")))
            }
        }
    }
}

/// Verifies that `envelope_bytes` contains at least one valid `COSE_Sign1_Tagged`
/// authentication block over its `SUIT_Digest` signed by `verifier`.
///
/// Note: this verifies the COSE signature over the `SUIT_Digest` bstr in
/// `suit-authentication-wrapper`; it does not recompute the digest over `suit-manifest`.
pub fn verify_envelope(envelope_bytes: &[u8], verifier: &Verifier) -> Result<(), Error> {
    let auth_array_bytes = envelope::extract_authentication(envelope_bytes)?;
    let value: Value = ciborium::de::from_reader(auth_array_bytes.as_slice())
        .map_err(|e| Error::InvalidEnvelope(format!("failed to decode SUIT_Authentication: {e}")))?;

    let elements = match value {
        Value::Array(elements) => elements,
        _ => {
            return Err(Error::InvalidEnvelope(
                "SUIT_Authentication is not an array".into(),
            ));
        }
    };

    let digest_bstr = match elements.first() {
        Some(Value::Bytes(b)) => b,
        Some(_) => {
            return Err(Error::InvalidEnvelope(
                "SUIT_Authentication[0] is not a bstr".into(),
            ));
        }
        None => {
            return Err(Error::InvalidEnvelope(
                "SUIT_Authentication array is empty".into(),
            ));
        }
    };

    let auth_blocks = &elements[1..];
    if auth_blocks.is_empty() {
        return Err(Error::VerificationFailed(
            "SUIT_Authentication contains no authentication blocks".into(),
        ));
    }

    let mut last_err = None;
    for block in auth_blocks {
        let block_bytes = match block {
            Value::Bytes(b) => b,
            _ => {
                last_err = Some(Error::InvalidEnvelope(
                    "SUIT_Authentication block is not a bstr".into(),
                ));
                continue;
            }
        };

        match verify_cose_sign1_block(block_bytes, digest_bstr, verifier) {
            Ok(()) => return Ok(()),
            Err(err) => last_err = Some(err),
        }
    }

    Err(last_err.unwrap_or_else(|| {
        Error::VerificationFailed("no matching COSE_Sign1 signature verified".into())
    }))
}

/// Convenience wrapper that parses `public_key_pem` and verifies `envelope_bytes`.
pub fn verify_envelope_pem(envelope_bytes: &[u8], public_key_pem: &str) -> Result<(), Error> {
    let verifier = Verifier::from_pem(public_key_pem)?;
    verify_envelope(envelope_bytes, &verifier)
}

/// Verifies a single `bstr`-unwrapped `COSE_Sign1_Tagged` block against `digest_bstr`.
fn verify_cose_sign1_block(
    block_bytes: &[u8],
    digest_bstr: &[u8],
    verifier: &Verifier,
) -> Result<(), Error> {
    let tagged: Value = ciborium::de::from_reader(block_bytes)
        .map_err(|e| Error::VerificationFailed(format!("failed to decode COSE block: {e}")))?;

    let inner = match tagged {
        Value::Tag(tag, inner) if tag == cose::COSE_SIGN1_TAG => *inner,
        Value::Tag(tag, _) => {
            return Err(Error::VerificationFailed(format!(
                "unsupported COSE tag {tag} (expected COSE_Sign1 tag 18)"
            )));
        }
        _ => {
            return Err(Error::VerificationFailed(
                "authentication block is not a tagged COSE structure".into(),
            ));
        }
    };

    let fields = match inner {
        Value::Array(fields) if fields.len() == 4 => fields,
        _ => {
            return Err(Error::VerificationFailed(
                "COSE_Sign1 must be a 4-element array".into(),
            ));
        }
    };

    let protected = match &fields[0] {
        Value::Bytes(b) => b,
        _ => {
            return Err(Error::VerificationFailed(
                "COSE_Sign1 protected header must be a bstr".into(),
            ));
        }
    };

    check_protected_alg(protected, verifier.alg_id())?;

    // SUIT uses detached payload mode (null); also reject mismatched embedded payloads.
    match &fields[2] {
        Value::Null => {}
        Value::Bytes(p) if p.as_slice() == digest_bstr => {}
        _ => {
            return Err(Error::VerificationFailed(
                "COSE_Sign1 payload does not match SUIT_Digest".into(),
            ));
        }
    }

    let sig_bytes = match &fields[3] {
        Value::Bytes(b) => b,
        _ => {
            return Err(Error::VerificationFailed(
                "COSE_Sign1 signature must be a bstr".into(),
            ));
        }
    };

    let to_be_signed = cose::sig_structure(protected, digest_bstr);
    verifier.verify(&to_be_signed, sig_bytes)
}

/// Checks that the CBOR-encoded `protected` header map declares `alg` (key 1) matching `expected_alg`.
fn check_protected_alg(protected: &[u8], expected_alg: i8) -> Result<(), Error> {
    let header: Value = ciborium::de::from_reader(protected)
        .map_err(|e| Error::VerificationFailed(format!("invalid COSE protected header: {e}")))?;
    let map = match header {
        Value::Map(m) => m,
        _ => {
            return Err(Error::VerificationFailed(
                "COSE protected header is not a map".into(),
            ));
        }
    };

    let alg_val = map
        .iter()
        .find(|(k, _)| *k == Value::from(1i64))
        .map(|(_, v)| v)
        .ok_or_else(|| {
            Error::VerificationFailed("COSE protected header missing alg (key 1)".into())
        })?;

    if *alg_val != Value::from(expected_alg as i64) {
        return Err(Error::VerificationFailed(format!(
            "COSE alg mismatch: expected {expected_alg}, got {alg_val:?}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Algorithm, Signer, sign_envelope};
    use p256::pkcs8::EncodePublicKey as _;

    // Throwaway P-256 test key (PKCS8 PEM).
    const ES256_PKCS8_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmszCRujRlOLiEywZ
h5wBh+Hzz3S/N9v/isf0zgmnbh2hRANCAAQ00s4XENy+WZ5ISICdRcSuwCaQ1WUA
WXSFBkWRMYSvj7UfvonsDFML67YB2F6MR5LrF+FGHh7yFSCekjzRCwQ5
-----END PRIVATE KEY-----";

    // Throwaway P-384 test key (PKCS8 PEM).
    const ES384_PKCS8_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDc6n3cQcnvjGgYfof7
d3Vw278SpRBcyffiJstQDLM8D5Lz25TRU6oLE/7n3V04tyahZANiAASLFpnYpkzx
pKQELulH6b4ROlsHPP12tVBNOhNUPn0AMlR18qJqG/VhDiTHy12cpzTn7Fb1NmbM
001mH2Jpsd9pmZCnXN7waUX7aGPUBYM3Wwz3Um/FSQS+s6yO+v/rhDE=
-----END PRIVATE KEY-----";

    fn pub_pem_from_signer(signer: &Signer) -> String {
        match signer {
            Signer::Es256(k) => k
                .verifying_key()
                .to_public_key_pem(p256::pkcs8::LineEnding::LF)
                .unwrap(),
            Signer::Es384(k) => k
                .verifying_key()
                .to_public_key_pem(p384::pkcs8::LineEnding::LF)
                .unwrap(),
        }
    }

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
    fn verifies_es256_signed_envelope() {
        let signer = Signer::from_pem(ES256_PKCS8_PEM, Algorithm::Es256).unwrap();
        let pub_pem = pub_pem_from_signer(&signer);
        let envelope = build_test_envelope(b"es256-digest", b"manifest");
        let signed = sign_envelope(&envelope, &signer).unwrap();

        verify_envelope_pem(&signed, &pub_pem).unwrap();
    }

    #[test]
    fn verifies_es384_signed_envelope() {
        let signer = Signer::from_pem(ES384_PKCS8_PEM, Algorithm::Es384).unwrap();
        let pub_pem = pub_pem_from_signer(&signer);
        let envelope = build_test_envelope(b"es384-digest", b"manifest");
        let signed = sign_envelope(&envelope, &signer).unwrap();

        verify_envelope_pem(&signed, &pub_pem).unwrap();
    }

    #[test]
    fn rejects_wrong_public_key() {
        let es256_signer = Signer::from_pem(ES256_PKCS8_PEM, Algorithm::Es256).unwrap();
        let es384_signer = Signer::from_pem(ES384_PKCS8_PEM, Algorithm::Es384).unwrap();
        let wrong_pub_pem = pub_pem_from_signer(&es384_signer);

        let envelope = build_test_envelope(b"digest", b"manifest");
        let signed = sign_envelope(&envelope, &es256_signer).unwrap();

        assert!(matches!(
            verify_envelope_pem(&signed, &wrong_pub_pem),
            Err(Error::VerificationFailed(_))
        ));
    }

    #[test]
    fn rejects_unsigned_envelope() {
        let signer = Signer::from_pem(ES256_PKCS8_PEM, Algorithm::Es256).unwrap();
        let pub_pem = pub_pem_from_signer(&signer);
        let unsigned = build_test_envelope(b"digest", b"manifest");

        assert!(matches!(
            verify_envelope_pem(&unsigned, &pub_pem),
            Err(Error::VerificationFailed(_))
        ));
    }

    #[test]
    fn rejects_tampered_signature() {
        let signer = Signer::from_pem(ES256_PKCS8_PEM, Algorithm::Es256).unwrap();
        let pub_pem = pub_pem_from_signer(&signer);
        let envelope = build_test_envelope(b"digest", b"manifest");
        let mut signed = sign_envelope(&envelope, &signer).unwrap();

        // Flip a byte inside the authentication wrapper's signature region.
        let auth_bytes = envelope::extract_authentication(&signed).unwrap();
        let mut auth_val: Value = ciborium::de::from_reader(auth_bytes.as_slice()).unwrap();
        if let Value::Array(ref mut elems) = auth_val
            && let Value::Bytes(ref mut cose_bytes) = elems[1]
        {
            let last = cose_bytes.len() - 1;
            cose_bytes[last] ^= 0xff;
        }
        let mut tampered_auth = Vec::new();
        ciborium::ser::into_writer(&auth_val, &mut tampered_auth).unwrap();
        signed = envelope::replace_authentication(&signed, &tampered_auth).unwrap();

        assert!(matches!(
            verify_envelope_pem(&signed, &pub_pem),
            Err(Error::VerificationFailed(_))
        ));
    }

    #[test]
    fn verifies_when_multiple_auth_blocks_present() {
        let es256_signer = Signer::from_pem(ES256_PKCS8_PEM, Algorithm::Es256).unwrap();
        let es384_signer = Signer::from_pem(ES384_PKCS8_PEM, Algorithm::Es384).unwrap();
        let es384_pub = pub_pem_from_signer(&es384_signer);

        let envelope = build_test_envelope(b"multi-sig-digest", b"manifest");
        let signed_once = sign_envelope(&envelope, &es256_signer).unwrap();
        let signed_twice = sign_envelope(&signed_once, &es384_signer).unwrap();

        verify_envelope_pem(&signed_twice, &es384_pub).unwrap();
    }

    #[test]
    fn rejects_invalid_pem_public_key() {
        assert!(matches!(
            Verifier::from_pem("not a pem key"),
            Err(Error::InvalidKey(_))
        ));
    }
}
