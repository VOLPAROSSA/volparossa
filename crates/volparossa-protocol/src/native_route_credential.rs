//! RFC 9180 delivery of one route-scoped native authentication bearer.

use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::X25519HkdfSha256, single_shot_open, single_shot_seal_with_rng,
};
use rand_chacha_10::{ChaCha20Rng, rand_core::SeedableRng};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    MAX_CONTROL_PAYLOAD_SIZE, NativeRouteCredentialDelivery, NativeRouteCredentialScope,
    ProtocolError, encode_canonical, native_route_auth_commitment,
};

type CredentialKem = X25519HkdfSha256;
type CredentialKdf = HkdfSha256;
type CredentialAead = ChaCha20Poly1305;

const CREDENTIAL_INFO: &[u8] = b"volparossa/native-route-credential/rfc9180/v1";
const AEAD_TAG_LENGTH: usize = 16;

/// RFC 9180 X25519 recipient and encapsulated-key length.
pub const NATIVE_ROUTE_CREDENTIAL_HPKE_KEY_LENGTH: usize = 32;
/// Exact encapsulated-key length for the fixed HPKE suite.
pub const NATIVE_ROUTE_CREDENTIAL_ENCAPSULATED_KEY_LENGTH: usize = 32;
/// Exact ciphertext length: the 43-byte bearer plus the ChaCha20-Poly1305 tag.
pub const NATIVE_ROUTE_CREDENTIAL_CIPHERTEXT_LENGTH: usize =
    crate::NATIVE_ROUTE_AUTH_BEARER_LENGTH + AEAD_TAG_LENGTH;

/// One non-cloneable, route-scoped RFC 9180 recipient keypair.
#[must_use = "the route credential recipient key must remain owned until delivery or expiry"]
pub struct NativeRouteCredentialKeyPair {
    private_key: Zeroizing<[u8; NATIVE_ROUTE_CREDENTIAL_HPKE_KEY_LENGTH]>,
    public_key: [u8; NATIVE_ROUTE_CREDENTIAL_HPKE_KEY_LENGTH],
}

impl NativeRouteCredentialKeyPair {
    /// Generate one fresh DHKEM(X25519, HKDF-SHA256) recipient keypair.
    ///
    /// # Errors
    ///
    /// Returns an error when the operating system cannot supply CSPRNG seed material.
    pub fn generate() -> Result<Self, NativeRouteCredentialError> {
        let mut rng = fresh_rng()?;
        let (private_key, public_key) = CredentialKem::gen_keypair_with_rng(&mut rng);
        let private_key = fixed(private_key.to_bytes().as_slice())?;
        let public_key = fixed(public_key.to_bytes().as_slice())?;
        Ok(Self {
            private_key: Zeroizing::new(private_key),
            public_key,
        })
    }

    /// Public route-scoped recipient key signed into the Exit reservation.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; NATIVE_ROUTE_CREDENTIAL_HPKE_KEY_LENGTH] {
        &self.public_key
    }

    /// Open one exact signed-delivery payload after its signature and replay checks pass.
    ///
    /// # Errors
    ///
    /// Rejects malformed keys, altered associated data/ciphertext, or a bearer whose standard
    /// commitment differs from the signed route identity.
    pub fn open(
        &self,
        delivery: &NativeRouteCredentialDelivery,
    ) -> Result<Zeroizing<[u8; crate::NATIVE_ROUTE_AUTH_BEARER_LENGTH]>, NativeRouteCredentialError>
    {
        let scope = delivery
            .scope
            .as_ref()
            .ok_or(NativeRouteCredentialError::InvalidScope)?;
        scope.validate_fields()?;
        if scope.credential_hpke_public_key.as_slice() != self.public_key {
            return Err(NativeRouteCredentialError::InvalidScope);
        }
        let private_key = <CredentialKem as KemTrait>::PrivateKey::from_bytes(&*self.private_key)
            .map_err(|_| NativeRouteCredentialError::InvalidKey)?;
        let encapsulated_key =
            <CredentialKem as KemTrait>::EncappedKey::from_bytes(&delivery.encapsulated_key)
                .map_err(|_| NativeRouteCredentialError::InvalidKey)?;
        let aad = credential_aad(scope)?;
        let plaintext = Zeroizing::new(
            single_shot_open::<CredentialAead, CredentialKdf, CredentialKem>(
                &OpModeR::Base,
                &private_key,
                &encapsulated_key,
                CREDENTIAL_INFO,
                &delivery.ciphertext,
                &aad,
            )
            .map_err(|_| NativeRouteCredentialError::Open)?,
        );
        let bearer = fixed(plaintext.as_slice())?;
        let expected = native_route_auth_commitment(&bearer)?;
        if expected.ct_eq(scope.auth_commitment.as_slice()).unwrap_u8() != 1 {
            return Err(NativeRouteCredentialError::Commitment);
        }
        Ok(Zeroizing::new(bearer))
    }
}

/// Opaque HPKE output safe for an untrusted forwarding Relay to carry.
pub struct SealedNativeRouteCredential {
    encapsulated_key: [u8; NATIVE_ROUTE_CREDENTIAL_ENCAPSULATED_KEY_LENGTH],
    ciphertext: [u8; NATIVE_ROUTE_CREDENTIAL_CIPHERTEXT_LENGTH],
}

impl SealedNativeRouteCredential {
    /// RFC 9180 encapsulated key.
    #[must_use]
    pub const fn encapsulated_key(&self) -> &[u8; NATIVE_ROUTE_CREDENTIAL_ENCAPSULATED_KEY_LENGTH] {
        &self.encapsulated_key
    }

    /// Authenticated ciphertext; it contains no plaintext bearer bytes.
    #[must_use]
    pub const fn ciphertext(&self) -> &[u8; NATIVE_ROUTE_CREDENTIAL_CIPHERTEXT_LENGTH] {
        &self.ciphertext
    }
}

/// Seal one exact route bearer to the signed, route-scoped Exit recipient key.
///
/// # Errors
///
/// Rejects malformed scope/key material or operating-system randomness failure.
pub fn seal_native_route_credential(
    scope: &NativeRouteCredentialScope,
    bearer: &[u8; crate::NATIVE_ROUTE_AUTH_BEARER_LENGTH],
) -> Result<SealedNativeRouteCredential, NativeRouteCredentialError> {
    scope.validate_fields()?;
    let public_key =
        <CredentialKem as KemTrait>::PublicKey::from_bytes(&scope.credential_hpke_public_key)
            .map_err(|_| NativeRouteCredentialError::InvalidKey)?;
    let aad = credential_aad(scope)?;
    let mut rng = fresh_rng()?;
    let (encapsulated_key, ciphertext) =
        single_shot_seal_with_rng::<CredentialAead, CredentialKdf, CredentialKem>(
            &OpModeS::Base,
            &public_key,
            CREDENTIAL_INFO,
            bearer,
            &aad,
            &mut rng,
        )
        .map_err(|_| NativeRouteCredentialError::Seal)?;
    Ok(SealedNativeRouteCredential {
        encapsulated_key: fixed(encapsulated_key.to_bytes().as_slice())?,
        ciphertext: fixed(&ciphertext)?,
    })
}

fn credential_aad(
    scope: &NativeRouteCredentialScope,
) -> Result<Vec<u8>, NativeRouteCredentialError> {
    encode_canonical(scope, MAX_CONTROL_PAYLOAD_SIZE).map_err(Into::into)
}

fn fresh_rng() -> Result<ChaCha20Rng, NativeRouteCredentialError> {
    let mut seed = Zeroizing::new([0_u8; 32]);
    getrandom::fill(&mut *seed).map_err(|_| NativeRouteCredentialError::Random)?;
    let rng = ChaCha20Rng::from_seed(*seed);
    seed.zeroize();
    Ok(rng)
}

fn fixed<const LENGTH: usize>(value: &[u8]) -> Result<[u8; LENGTH], NativeRouteCredentialError> {
    value
        .try_into()
        .map_err(|_| NativeRouteCredentialError::InvalidKey)
}

/// Fail-closed RFC 9180 credential-delivery error.
#[derive(Debug, Error)]
pub enum NativeRouteCredentialError {
    /// Operating-system CSPRNG material was unavailable.
    #[error("native route credential randomness is unavailable")]
    Random,
    /// Public associated data was absent or malformed.
    #[error("native route credential scope is invalid")]
    InvalidScope,
    /// An RFC 9180 key had the wrong representation.
    #[error("native route credential HPKE key is invalid")]
    InvalidKey,
    /// RFC 9180 could not seal the bearer.
    #[error("native route credential HPKE seal failed")]
    Seal,
    /// RFC 9180 authentication or decryption failed.
    #[error("native route credential HPKE open failed")]
    Open,
    /// Decrypted bearer did not match the Exit-signed commitment.
    #[error("native route credential commitment mismatch")]
    Commitment,
    /// Canonical scope encoding or validation failed.
    #[error("native route credential protocol failed: {0}")]
    Protocol(#[from] ProtocolError),
}

#[cfg(test)]
mod tests {
    use crate::{NATIVE_ROUTE_AUTH_BEARER_LENGTH, native_route_auth_commitment};

    use super::*;

    fn scope(
        key: &[u8; 32],
        bearer: &[u8; NATIVE_ROUTE_AUTH_BEARER_LENGTH],
    ) -> NativeRouteCredentialScope {
        let client_key = [6; 32];
        NativeRouteCredentialScope {
            reservation_id: vec![1; 16],
            route_context_id: vec![2; 16],
            finalize_id: vec![3; 16],
            exit_node_id: vec![4; 32],
            client_session_id: crate::node_id_from_public_key(&client_key).to_vec(),
            client_session_public_key: client_key.to_vec(),
            auth_commitment: native_route_auth_commitment(bearer)
                .expect("commitment")
                .to_vec(),
            certificate_sha256: vec![7; 32],
            spki_sha256: vec![8; 32],
            masque_context_id: 9,
            client_native_instance_id: vec![10; 32],
            exit_native_instance_id: vec![11; 32],
            credential_hpke_public_key: key.to_vec(),
            created_at_ms: 1_900_000_000_000,
            expires_at_ms: 1_900_000_060_000,
            nonce: vec![12; 32],
        }
    }

    #[test]
    fn standard_hpke_round_trip_binds_every_scope_byte() {
        let key = NativeRouteCredentialKeyPair::generate().expect("recipient key");
        let bearer = *b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let scope = scope(key.public_key(), &bearer);
        let sealed = seal_native_route_credential(&scope, &bearer).expect("seal");
        assert!(
            !sealed
                .ciphertext()
                .windows(bearer.len())
                .any(|part| part == bearer)
        );
        let delivery = NativeRouteCredentialDelivery {
            scope: Some(scope.clone()),
            encapsulated_key: sealed.encapsulated_key().to_vec(),
            ciphertext: sealed.ciphertext().to_vec(),
        };
        assert_eq!(&*key.open(&delivery).expect("open"), &bearer);

        let mut altered = delivery;
        altered.scope.as_mut().expect("scope").route_context_id[0] ^= 1;
        assert!(matches!(
            key.open(&altered),
            Err(NativeRouteCredentialError::Open)
        ));
    }
}
