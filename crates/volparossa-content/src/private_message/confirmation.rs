//! Fixed random-probe use of the already pinned RFC 9180 single-shot profile.
//! No publication/cache access, caller plaintext, arbitrary info/AAD or key export.

use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use zeroize::Zeroizing;

use super::{
    MessageAead, MessageKdf, MessageKem, PrivateMessageError, RecipientKeyPair, fresh_rng,
    single_shot_open, single_shot_seal_with_rng,
};

const INFO: &[u8] = b"VOLPAROSSA/compute-key-confirmation/rfc9180/v1\0";

pub(crate) struct SealedProbe {
    pub(crate) encapsulated: [u8; 32],
    pub(crate) ciphertext: [u8; 48],
    pub(crate) expected: Zeroizing<[u8; 32]>,
}

pub(crate) fn seal(
    recipient: &[u8; 32],
    context: &[u8; 32],
) -> Result<SealedProbe, PrivateMessageError> {
    let public = <MessageKem as KemTrait>::PublicKey::from_bytes(recipient)
        .map_err(|_| PrivateMessageError::InvalidKey)?;
    let mut expected = Zeroizing::new([0; 32]);
    getrandom::fill(expected.as_mut()).map_err(|_| PrivateMessageError::Random)?;
    let mut rng = fresh_rng()?;
    let (encapsulated, ciphertext) =
        single_shot_seal_with_rng::<MessageAead, MessageKdf, MessageKem>(
            &OpModeS::Base,
            &public,
            INFO,
            expected.as_slice(),
            context,
            &mut rng,
        )
        .map_err(|_| PrivateMessageError::Seal)?;
    Ok(SealedProbe {
        encapsulated: encapsulated
            .to_bytes()
            .as_slice()
            .try_into()
            .map_err(|_| PrivateMessageError::InvalidKey)?,
        ciphertext: ciphertext
            .as_slice()
            .try_into()
            .map_err(|_| PrivateMessageError::Seal)?,
        expected,
    })
}

impl RecipientKeyPair {
    pub(crate) fn open_confirmation_probe(
        &self,
        context: &[u8; 32],
        encapsulated: &[u8; 32],
        ciphertext: &[u8; 48],
    ) -> Result<Zeroizing<[u8; 32]>, PrivateMessageError> {
        let secret = <MessageKem as KemTrait>::PrivateKey::from_bytes(&*self.private_key)
            .map_err(|_| PrivateMessageError::InvalidKey)?;
        let encapsulated = <MessageKem as KemTrait>::EncappedKey::from_bytes(encapsulated)
            .map_err(|_| PrivateMessageError::InvalidKey)?;
        let opened = Zeroizing::new(
            single_shot_open::<MessageAead, MessageKdf, MessageKem>(
                &OpModeR::Base,
                &secret,
                &encapsulated,
                INFO,
                ciphertext,
                context,
            )
            .map_err(|_| PrivateMessageError::Open)?,
        );
        Ok(Zeroizing::new(
            opened
                .as_slice()
                .try_into()
                .map_err(|_| PrivateMessageError::Open)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_hpke_roundtrip_has_exact_fixed_lengths_and_fresh_random_probes() {
        let key = RecipientKeyPair::generate().unwrap();
        let first = seal(key.public_key(), &[1; 32]).unwrap();
        let second = seal(key.public_key(), &[1; 32]).unwrap();
        assert!(*first.expected != *second.expected);
        assert!(first.encapsulated != second.encapsulated);
        let opened = key
            .open_confirmation_probe(&[1; 32], &first.encapsulated, &first.ciphertext)
            .unwrap();
        assert!(*opened == *first.expected);
    }

    #[test]
    fn different_recipient_and_context_and_ciphertext_are_rejected() {
        let key = RecipientKeyPair::generate().unwrap();
        let wrong = RecipientKeyPair::generate().unwrap();
        let mut sealed = seal(key.public_key(), &[1; 32]).unwrap();
        assert!(
            wrong
                .open_confirmation_probe(&[1; 32], &sealed.encapsulated, &sealed.ciphertext)
                .is_err()
        );
        assert!(
            key.open_confirmation_probe(&[2; 32], &sealed.encapsulated, &sealed.ciphertext)
                .is_err()
        );
        sealed.ciphertext[0] ^= 1;
        assert!(
            key.open_confirmation_probe(&[1; 32], &sealed.encapsulated, &sealed.ciphertext)
                .is_err()
        );
    }

    #[test]
    fn low_order_recipient_and_invalid_encapsulation_fail_closed() {
        assert!(seal(&[0; 32], &[1; 32]).is_err());
        let key = RecipientKeyPair::generate().unwrap();
        let sealed = seal(key.public_key(), &[1; 32]).unwrap();
        assert!(
            key.open_confirmation_probe(&[1; 32], &[0; 32], &sealed.ciphertext)
                .is_err()
        );
    }
}
