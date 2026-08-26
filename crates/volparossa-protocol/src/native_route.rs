//! Canonical authentication commitment for one signed native-route identity.

use sha2::{Digest, Sha256};

use crate::ProtocolError;

/// Domain separating the v4 native-route bearer commitment from every other digest.
pub const NATIVE_ROUTE_AUTH_COMMITMENT_DOMAIN: &[u8] =
    b"VOLPAROSSA-NATIVE-ROUTE-AUTH-COMMITMENT-V4\0";

/// Exact unpadded base64url length of one encoded 256-bit route bearer.
pub const NATIVE_ROUTE_AUTH_BEARER_LENGTH: usize = 43;

/// Hash one exact canonical unpadded base64url encoding of a 256-bit route bearer.
///
/// The returned SHA-256 digest commits to the exact 43 transmitted ASCII bytes. The final
/// character restriction proves that the unused low two bits of the final base64url sextet are
/// zero, so alternate encodings of the same 32 bearer bytes are rejected.
///
/// # Errors
///
/// Returns an invalid-field error for any wrong length, alphabet, padding, or non-canonical final
/// character.
pub fn native_route_auth_commitment(bearer: &[u8]) -> Result<[u8; 32], ProtocolError> {
    if bearer.len() != NATIVE_ROUTE_AUTH_BEARER_LENGTH
        || !bearer
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
        || !bearer
            .last()
            .is_some_and(|byte| b"AEIMQUYcgkosw048".contains(byte))
    {
        return Err(ProtocolError::InvalidField(
            "native route authentication bearer",
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(NATIVE_ROUTE_AUTH_COMMITMENT_DOMAIN);
    hasher.update(bearer);
    Ok(hasher.finalize().into())
}
