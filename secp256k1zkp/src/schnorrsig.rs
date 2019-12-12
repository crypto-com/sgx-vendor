//! # Schnorr signatures compliant with BIP-schnorr

use super::{Error, from_hex, ffi, Signing, Verification, Secp256k1, Message, key};
use core::{fmt, str, ptr};

/// A Schnorr signature
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(not(feature = "zeroize"), derive(Copy))]
pub struct SchnorrSignature(ffi::SchnorrSignature);

impl fmt::Debug for SchnorrSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for SchnorrSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let v = self.serialize_default();
        for ch in &v[..] {
            write!(f, "{:02x}", *ch)?;
        }
        Ok(())
    }
}

impl str::FromStr for SchnorrSignature {
    type Err = Error;
    fn from_str(s: &str) -> Result<SchnorrSignature, Error> {
        let mut res = [0; 64];
        match from_hex(s, &mut res) {
            Ok(x) => SchnorrSignature::from_default(&res[0..x]),
            _ => Err(Error::InvalidSignature),
        }
    }
}

/// Creates a new signature from a FFI signature
impl From<ffi::SchnorrSignature> for SchnorrSignature {
    #[inline]
    fn from(sig: ffi::SchnorrSignature) -> SchnorrSignature {
        SchnorrSignature(sig)
    }
}

#[cfg(feature = "serde")]
impl ::serde::Serialize for SchnorrSignature {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.serialize_default())
    }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for SchnorrSignature {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<SchnorrSignature, D::Error> {
        use ::serde::de::Error;

        let sl: &[u8] = ::serde::Deserialize::deserialize(d)?;
        SchnorrSignature::from_default(sl).map_err(D::Error::custom)
    }
}

impl SchnorrSignature {
    #[inline]
    /// Converts the default encoded byte slice to a Schnorr signature
    pub fn from_default(data: &[u8]) -> Result<SchnorrSignature, Error> {
        let mut ret = unsafe { ffi::SchnorrSignature::blank() };
        if data.len() != 64 {
            return Err(Error::InvalidSignature)
        }

        unsafe {
            if ffi::secp256k1_schnorrsig_parse(
                ffi::secp256k1_context_no_precomp,
                &mut ret,
                data.as_ptr(),
            ) == 1
            {
                Ok(SchnorrSignature(ret))
            } else {
                Err(Error::InvalidSignature)
            }
        }
    }

    /// Obtains a raw pointer suitable for use with FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::SchnorrSignature {
        &self.0 as *const _
    }

    #[inline]
    /// Serializes the Schnorr signature in the default format
    pub fn serialize_default(&self) -> [u8; 64] {
        let mut ret = [0; 64];
        unsafe {
            let err = ffi::secp256k1_schnorrsig_serialize(
                ffi::secp256k1_context_no_precomp,
                ret.as_mut_ptr(),
                self.as_ptr(),
            );
            debug_assert!(err == 1);
        }
        ret
    }
}

/// Denotes if the algorithm negated the nonce
pub type NonceIsNegated = bool;

/// Constructs a Schnorr signature for `msg` using the secret key `sk` and BIP Schnorr nonce.
/// Requires a signing-capable context.
pub fn schnorr_sign<C: Signing>(secp: &Secp256k1<C>, msg: &Message, sk: &key::SecretKey)
                    -> (SchnorrSignature, NonceIsNegated) {

    let mut ret = unsafe { ffi::SchnorrSignature::blank() };
    // std::os::raw::c_int
    // WARNING: upstream API may be different: https://github.com/bitcoin-core/secp256k1/pull/589
    let mut nonce_is_negated: i32 = 0;

    unsafe {
        // We can assume the return value because it's not possible to construct
        // an invalid signature from a valid `Message` and `SecretKey`
        assert_eq!(ffi::secp256k1_schnorrsig_sign(secp.ctx, &mut ret, &mut nonce_is_negated, msg.as_ptr(),
                                                sk.as_ptr(), Option::None, ptr::null()), 1);
    }

    (SchnorrSignature::from(ret), nonce_is_negated != 0)
}

/// Checks that `sig` is a valid Schnorr signature for `msg` using the public
/// key `pubkey`. Returns `Ok(true)` on success.
/// Requires a verify-capable context.
/// TODO: batch verification
#[inline]
pub fn schnorr_verify<C: Verification>(secp: &Secp256k1<C>, 
                                       msg: &Message,
                                       sig: &SchnorrSignature,
                                       pk: &key::PublicKey)
                                       -> Result<(), Error> {
    unsafe {
        if ffi::secp256k1_schnorrsig_verify(secp.ctx, sig.as_ptr(), msg.as_ptr(), pk.as_ptr()) == 0 {
            Err(Error::IncorrectSignature)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::{RngCore, thread_rng};
    use super::{Secp256k1, SchnorrSignature, schnorr_verify, schnorr_sign, Message,
    key::{SecretKey, PublicKey}, NonceIsNegated};

    #[test]
    fn schnorr_capabilities() {
        let sign = Secp256k1::signing_only();
        let vrfy = Secp256k1::verification_only();
        let full = Secp256k1::new();

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        // Try key generation
        let (sk, pk) = full.generate_keypair(&mut thread_rng());

        // Try signing
        assert_eq!(schnorr_sign(&sign, &msg, &sk), schnorr_sign(&full, &msg, &sk));
        let sig = schnorr_sign(&full, &msg, &sk).0;

        // Try verifying
        assert!(schnorr_verify(&vrfy, &msg, &sig, &pk).is_ok());
        assert!(schnorr_verify(&full, &msg, &sig, &pk).is_ok());
    }

    fn schnorr_bip_vectors_check(sk_serialized: &[u8; 32], pk_serialized: &[u8; 33], 
        msg: &[u8; 32], expected_sig_serialized: &[u8; 64], expected_nonce_is_negated: NonceIsNegated) {
            let secp = Secp256k1::new();
            let sk = SecretKey::from_slice(&sk_serialized[..]).expect("failed to parse secret key");
            let msg32 = Message::from_slice(&msg[..]).expect("failed to parse message");
            let expected_sig = SchnorrSignature::from_default(&expected_sig_serialized[..])
                .expect("failed to parse Schnorr sig");
            let (sig, nonce_is_negated) = schnorr_sign(&secp, &msg32, &sk);
            assert_eq!(sig, expected_sig);
            assert_eq!(nonce_is_negated, expected_nonce_is_negated);
            let serialized_sig = sig.serialize_default();
            assert!(serialized_sig.iter().zip(expected_sig_serialized.iter()).all(|(a,b)| a == b), 
                "Serializaed signatures are not equal");
            let pk = PublicKey::from_slice(&pk_serialized[..]).expect("failed to parse public key");
            assert!(schnorr_verify(&secp, &msg32, &sig, &pk).is_ok());
    }

    #[test]
    fn schnorr_bip_vectors() {
        // Test vector 2
        let sk2 = [
            0xB7, 0xE1, 0x51, 0x62, 0x8A, 0xED, 0x2A, 0x6A,
            0xBF, 0x71, 0x58, 0x80, 0x9C, 0xF4, 0xF3, 0xC7,
            0x62, 0xE7, 0x16, 0x0F, 0x38, 0xB4, 0xDA, 0x56,
            0xA7, 0x84, 0xD9, 0x04, 0x51, 0x90, 0xCF, 0xEF
        ];
        let pk2 = [
            0x02, 0xDF, 0xF1, 0xD7, 0x7F, 0x2A, 0x67, 0x1C,
            0x5F, 0x36, 0x18, 0x37, 0x26, 0xDB, 0x23, 0x41,
            0xBE, 0x58, 0xFE, 0xAE, 0x1D, 0xA2, 0xDE, 0xCE,
            0xD8, 0x43, 0x24, 0x0F, 0x7B, 0x50, 0x2B, 0xA6,
            0x59
        ];
        let msg2 = [
            0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3,
            0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x44,
            0xA4, 0x09, 0x38, 0x22, 0x29, 0x9F, 0x31, 0xD0,
            0x08, 0x2E, 0xFA, 0x98, 0xEC, 0x4E, 0x6C, 0x89
        ];
        let sig2 = [
            0x2A, 0x29, 0x8D, 0xAC, 0xAE, 0x57, 0x39, 0x5A,
            0x15, 0xD0, 0x79, 0x5D, 0xDB, 0xFD, 0x1D, 0xCB,
            0x56, 0x4D, 0xA8, 0x2B, 0x0F, 0x26, 0x9B, 0xC7,
            0x0A, 0x74, 0xF8, 0x22, 0x04, 0x29, 0xBA, 0x1D,
            0x1E, 0x51, 0xA2, 0x2C, 0xCE, 0xC3, 0x55, 0x99,
            0xB8, 0xF2, 0x66, 0x91, 0x22, 0x81, 0xF8, 0x36,
            0x5F, 0xFC, 0x2D, 0x03, 0x5A, 0x23, 0x04, 0x34,
            0xA1, 0xA6, 0x4D, 0xC5, 0x9F, 0x70, 0x13, 0xFD
        ];
        schnorr_bip_vectors_check(&sk2, &pk2, &msg2, &sig2, false);
        // Test vector 3
        let sk3 = [
            0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
            0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
            0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
            0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x14, 0xE5, 0xC7
        ];
        let pk3 = [
            0x03, 0xFA, 0xC2, 0x11, 0x4C, 0x2F, 0xBB, 0x09,
            0x15, 0x27, 0xEB, 0x7C, 0x64, 0xEC, 0xB1, 0x1F,
            0x80, 0x21, 0xCB, 0x45, 0xE8, 0xE7, 0x80, 0x9D,
            0x3C, 0x09, 0x38, 0xE4, 0xB8, 0xC0, 0xE5, 0xF8,
            0x4B
        ];
        let msg3 = [
            0x5E, 0x2D, 0x58, 0xD8, 0xB3, 0xBC, 0xDF, 0x1A,
            0xBA, 0xDE, 0xC7, 0x82, 0x90, 0x54, 0xF9, 0x0D,
            0xDA, 0x98, 0x05, 0xAA, 0xB5, 0x6C, 0x77, 0x33,
            0x30, 0x24, 0xB9, 0xD0, 0xA5, 0x08, 0xB7, 0x5C
        ];
        let sig3 = [
            0x00, 0xDA, 0x9B, 0x08, 0x17, 0x2A, 0x9B, 0x6F,
            0x04, 0x66, 0xA2, 0xDE, 0xFD, 0x81, 0x7F, 0x2D,
            0x7A, 0xB4, 0x37, 0xE0, 0xD2, 0x53, 0xCB, 0x53,
            0x95, 0xA9, 0x63, 0x86, 0x6B, 0x35, 0x74, 0xBE,
            0x00, 0x88, 0x03, 0x71, 0xD0, 0x17, 0x66, 0x93,
            0x5B, 0x92, 0xD2, 0xAB, 0x4C, 0xD5, 0xC8, 0xA2,
            0xA5, 0x83, 0x7E, 0xC5, 0x7F, 0xED, 0x76, 0x60,
            0x77, 0x3A, 0x05, 0xF0, 0xDE, 0x14, 0x23, 0x80
        ];
        schnorr_bip_vectors_check(&sk3, &pk3, &msg3, &sig3, false);        
    }

}