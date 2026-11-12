//! Loads ECDSA signing keys (P-256/ES256 or P-384/ES384) from PEM, raw scalar bytes, or an HSM.

use std::path::Path;

use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, KeyType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    types::AuthPin,
};
use sha2::{Digest, Sha256, Sha384};

use crate::error::Error;

/// Which curve/algorithm to sign with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// ES256 (COSE alg -7), NIST P-256.
    Es256,
    /// ES384 (COSE alg -35), NIST P-384.
    Es384,
}

/// A loaded signing key, ready to sign.
pub enum Signer {
    /// ES256 (COSE alg -7), NIST P-256.
    Es256(p256::ecdsa::SigningKey),
    /// ES384 (COSE alg -35), NIST P-384.
    Es384(p384::ecdsa::SigningKey),
    /// An EC private key accessed through a logged-in PKCS#11 session.
    Hsm(HsmSigner),
}

/// PKCS#11 session and key handle used for HSM signing.
#[doc(hidden)]
pub struct HsmSigner {
    session: Session,
    _pkcs11: Pkcs11,
    private_key: ObjectHandle,
    algorithm: Algorithm,
}

// Manual Debug: never print key material, even accidentally via `{:?}` in logs/panics.
impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Signer::Es256(_) => write!(f, "Signer::Es256(<redacted>)"),
            Signer::Es384(_) => write!(f, "Signer::Es384(<redacted>)"),
            Signer::Hsm(_) => write!(f, "Signer::Hsm(<redacted>)"),
        }
    }
}

impl Signer {
    /// Loads a signing key from a PEM-encoded PKCS8 or SEC1 private key.
    pub fn from_pem(pem: &str, algorithm: Algorithm) -> Result<Self, Error> {
        match algorithm {
            Algorithm::Es256 => parse_es256_pem(pem).map(Signer::Es256),
            Algorithm::Es384 => parse_es384_pem(pem).map(Signer::Es384),
        }
    }

    /// Loads a signing key from raw scalar bytes (32 bytes for P-256, 48 for P-384).
    pub fn from_raw_bytes(bytes: &[u8], algorithm: Algorithm) -> Result<Self, Error> {
        match algorithm {
            Algorithm::Es256 => p256::ecdsa::SigningKey::try_from(bytes)
                .map(Signer::Es256)
                .map_err(|e| Error::InvalidKey(format!("invalid P-256 scalar bytes: {e}"))),
            Algorithm::Es384 => p384::ecdsa::SigningKey::try_from(bytes)
                .map(Signer::Es384)
                .map_err(|e| Error::InvalidKey(format!("invalid P-384 scalar bytes: {e}"))),
        }
    }

    /// Opens a PKCS#11 module, logs in to the token with the given label, and locates the
    /// private key with the given label and ID.
    pub fn from_hsm(
        module_path: &Path,
        pin: &str,
        token_label: &str,
        key_label: &str,
        key_id: &[u8],
        algorithm: Algorithm,
    ) -> Result<Self, Error> {
        let pkcs11 = Pkcs11::new(module_path.to_string_lossy().into_owned())
            .map_err(|e| Error::Hsm(format!("could not load PKCS#11 module: {e}")))?;
        pkcs11
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| Error::Hsm(format!("could not initialize PKCS#11 module: {e}")))?;

        let slots = pkcs11
            .get_slots_with_token()
            .map_err(|e| Error::Hsm(format!("could not list token slots: {e}")))?;
        let mut matching_slots = Vec::new();
        for slot in slots {
            let info = pkcs11
                .get_token_info(slot)
                .map_err(|e| Error::Hsm(format!("could not read token info: {e}")))?;
            if info.label() == token_label {
                matching_slots.push(slot);
            }
        }
        let slot = match matching_slots.as_slice() {
            [slot] => *slot,
            [] => {
                return Err(Error::Hsm(format!(
                    "no token found with label {token_label}"
                )));
            }
            _ => {
                return Err(Error::Hsm(format!(
                    "multiple tokens found with label {token_label}"
                )));
            }
        };

        let session = pkcs11
            .open_rw_session(slot)
            .map_err(|e| Error::Hsm(format!("could not open token session: {e}")))?;
        let user_pin = AuthPin::new(pin.to_owned().into());
        session
            .login(UserType::User, Some(&user_pin))
            .map_err(|e| Error::Hsm(format!("could not log in to token: {e}")))?;

        let key_template = [
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(KeyType::EC),
            Attribute::Label(key_label.as_bytes().to_vec()),
            Attribute::Id(key_id.to_vec()),
            Attribute::Sign(true),
        ];
        let keys = session
            .find_objects(&key_template)
            .map_err(|e| Error::Hsm(format!("could not find signing key: {e}")))?;
        let private_key = match keys.as_slice() {
            [key] => *key,
            [] => {
                return Err(Error::Hsm(format!(
                    "no private key found with label {key_label} and ID {}",
                    hex::encode(key_id)
                )));
            }
            _ => {
                return Err(Error::Hsm(format!(
                    "multiple private keys found with label {key_label} and ID {}",
                    hex::encode(key_id)
                )));
            }
        };

        Ok(Signer::Hsm(HsmSigner {
            session,
            _pkcs11: pkcs11,
            private_key,
            algorithm,
        }))
    }

    /// COSE algorithm identifier: ES256 = -7, ES384 = -35.
    pub fn alg_id(&self) -> i8 {
        match self {
            Signer::Es256(_) => -7,
            Signer::Es384(_) => -35,
            Signer::Hsm(signer) => match signer.algorithm {
                Algorithm::Es256 => -7,
                Algorithm::Es384 => -35,
            },
        }
    }

    /// Signs `msg`, returning raw `r || s` signature bytes (not DER).
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        use signature::Signer as _;
        match self {
            Signer::Es256(key) => {
                let sig: p256::ecdsa::Signature = key.sign(msg);
                Ok(sig.to_bytes().to_vec())
            }
            Signer::Es384(key) => {
                let sig: p384::ecdsa::Signature = key.sign(msg);
                Ok(sig.to_bytes().to_vec())
            }
            Signer::Hsm(signer) => signer.sign(msg),
        }
    }
}

impl HsmSigner {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let digest = match self.algorithm {
            Algorithm::Es256 => Sha256::digest(msg).to_vec(),
            Algorithm::Es384 => Sha384::digest(msg).to_vec(),
        };
        let signature = self
            .session
            .sign(&Mechanism::Ecdsa, self.private_key, &digest)
            .map_err(|e| Error::Hsm(format!("ECDSA signing failed: {e}")))?;
        let expected_len = match self.algorithm {
            Algorithm::Es256 => 64,
            Algorithm::Es384 => 96,
        };
        if signature.len() != expected_len {
            return Err(Error::Hsm(format!(
                "expected a {expected_len}-byte raw ECDSA signature, got {} bytes",
                signature.len()
            )));
        }
        Ok(signature)
    }
}

/// Parses a P-256 signing key from PEM, trying PKCS8 first, then SEC1.
fn parse_es256_pem(pem: &str) -> Result<p256::ecdsa::SigningKey, Error> {
    use p256::pkcs8::DecodePrivateKey as _;
    if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_pem(pem) {
        return Ok(key);
    }
    p256::SecretKey::from_sec1_pem(pem)
        .map(p256::ecdsa::SigningKey::from)
        .map_err(|e| {
            Error::InvalidKey(format!(
                "failed to parse P-256 PEM key (tried PKCS8 and SEC1): {e}"
            ))
        })
}

/// Parses a P-384 signing key from PEM, trying PKCS8 first, then SEC1.
fn parse_es384_pem(pem: &str) -> Result<p384::ecdsa::SigningKey, Error> {
    use p384::pkcs8::DecodePrivateKey as _;
    if let Ok(key) = p384::ecdsa::SigningKey::from_pkcs8_pem(pem) {
        return Ok(key);
    }
    p384::SecretKey::from_sec1_pem(pem)
        .map(p384::ecdsa::SigningKey::from)
        .map_err(|e| {
            Error::InvalidKey(format!(
                "failed to parse P-384 PEM key (tried PKCS8 and SEC1): {e}"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Throwaway P-256 test key (PKCS8 PEM), generated solely for these unit tests via:
    // `openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt`
    const ES256_PKCS8_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmszCRujRlOLiEywZ
h5wBh+Hzz3S/N9v/isf0zgmnbh2hRANCAAQ00s4XENy+WZ5ISICdRcSuwCaQ1WUA
WXSFBkWRMYSvj7UfvonsDFML67YB2F6MR5LrF+FGHh7yFSCekjzRCwQ5
-----END PRIVATE KEY-----";

    // Throwaway P-384 test key (PKCS8 PEM), generated solely for these unit tests via:
    // `openssl ecparam -name secp384r1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt`
    const ES384_PKCS8_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDc6n3cQcnvjGgYfof7
d3Vw278SpRBcyffiJstQDLM8D5Lz25TRU6oLE/7n3V04tyahZANiAASLFpnYpkzx
pKQELulH6b4ROlsHPP12tVBNOhNUPn0AMlR18qJqG/VhDiTHy12cpzTn7Fb1NmbM
001mH2Jpsd9pmZCnXN7waUX7aGPUBYM3Wwz3Um/FSQS+s6yO+v/rhDE=
-----END PRIVATE KEY-----";

    #[test]
    fn from_pem_parses_es256_pkcs8() {
        let signer = Signer::from_pem(ES256_PKCS8_PEM, Algorithm::Es256).unwrap();
        assert_eq!(signer.alg_id(), -7);
    }

    #[test]
    fn from_pem_rejects_wrong_algorithm() {
        assert!(Signer::from_pem(ES256_PKCS8_PEM, Algorithm::Es384).is_err());
    }

    #[test]
    fn from_raw_bytes_round_trips_public_key() {
        let signer = Signer::from_pem(ES256_PKCS8_PEM, Algorithm::Es256).unwrap();
        let raw = match &signer {
            Signer::Es256(key) => key.to_bytes(),
            Signer::Es384(_) | Signer::Hsm(_) => unreachable!(),
        };
        let reloaded = Signer::from_raw_bytes(&raw, Algorithm::Es256).unwrap();
        match (signer, reloaded) {
            (Signer::Es256(a), Signer::Es256(b)) => {
                assert_eq!(a.verifying_key(), b.verifying_key())
            }
            _ => panic!("expected Es256"),
        }
    }

    #[test]
    fn from_raw_bytes_rejects_wrong_length() {
        // P-384 raw bytes are 48 bytes long, too long for a P-256 scalar (32 bytes).
        let bytes = [0u8; 48];
        assert!(Signer::from_raw_bytes(&bytes, Algorithm::Es256).is_err());
    }

    #[test]
    fn sign_es256_produces_64_byte_signature() {
        let signer = Signer::from_pem(ES256_PKCS8_PEM, Algorithm::Es256).unwrap();
        let sig = signer.sign(b"test message").unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn sign_es384_produces_96_byte_signature() {
        let signer = Signer::from_pem(ES384_PKCS8_PEM, Algorithm::Es384).unwrap();
        let sig = signer.sign(b"test message").unwrap();
        assert_eq!(sig.len(), 96);
    }
}
