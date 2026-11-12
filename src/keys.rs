//! Loads ECDSA signing keys (P-256/ES256 or P-384/ES384) from PEM or raw scalar bytes.

use crate::error::Error;

/// Which curve/algorithm to sign with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// ES256 (COSE alg -7), NIST P-256.
    Es256,
    /// ES384 (COSE alg -35), NIST P-384.
    Es384,
}

/// A loaded private key, ready to sign. Wraps `p256`/`p384`'s `ecdsa::SigningKey`.
pub enum Signer {
    /// ES256 (COSE alg -7), NIST P-256.
    Es256(p256::ecdsa::SigningKey),
    /// ES384 (COSE alg -35), NIST P-384.
    Es384(p384::ecdsa::SigningKey),
}

// Manual Debug: never print key material, even accidentally via `{:?}` in logs/panics.
impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Signer::Es256(_) => write!(f, "Signer::Es256(<redacted>)"),
            Signer::Es384(_) => write!(f, "Signer::Es384(<redacted>)"),
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

    /// COSE algorithm identifier: ES256 = -7, ES384 = -35.
    pub fn alg_id(&self) -> i8 {
        match self {
            Signer::Es256(_) => -7,
            Signer::Es384(_) => -35,
        }
    }

    /// Signs `msg`, returning the raw `r || s` signature bytes (not DER).
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        use signature::Signer as _;
        match self {
            Signer::Es256(key) => {
                let sig: p256::ecdsa::Signature = key.sign(msg);
                sig.to_bytes().to_vec()
            }
            Signer::Es384(key) => {
                let sig: p384::ecdsa::Signature = key.sign(msg);
                sig.to_bytes().to_vec()
            }
        }
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
            Signer::Es384(_) => unreachable!(),
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
        let sig = signer.sign(b"test message");
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn sign_es384_produces_96_byte_signature() {
        let signer = Signer::from_pem(ES384_PKCS8_PEM, Algorithm::Es384).unwrap();
        let sig = signer.sign(b"test message");
        assert_eq!(sig.len(), 96);
    }
}
