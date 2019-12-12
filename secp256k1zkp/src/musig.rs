//! # MuSig - Rogue-Key-Resistant Multisignatures Module

use super::{ffi, Secp256k1, key::PublicKey,
    key::SecretKey, key::PublicKeyHash, constants, Message, 
    schnorrsig::{NonceIsNegated, SchnorrSignature}};
use std::{fmt, error, ptr};
#[cfg(any(test, feature = "rand"))] use rand::Rng;
#[cfg(any(test, feature = "rand"))] use super::key;
#[cfg(feature = "zeroize")] use zeroize::Zeroize;

/// A MuSig error
#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    /// wrong session id (wrong size...)
    InvalidSessionID,
    /// musig session could not be initialized (secret key or secret nonce overflow)
    SessionInitFailed,
    /// musig public nonce could not be retrieved (signer data is missing commitments
    /// or session isn't initialized for signing)
    SessionPublicNonceFailed,
    /// signer's nonce does not match its public commitment
    /// (if this happens, abort the protocol and start a new session with a fresh session ID)
    NonceDoesNotMatchCommitment,
    /// signer's nonce missing during combination
    SignerNonceMissing,
    /// incorrect or inconsistent session state
    PartialSignatureConstructionFailed,
    /// invalid signature or bad data
    PartialSignatureVerificationFailed,
    /// r/s values out of range
    PartialSignatureCombinationFailed
}

// Passthrough Debug to Display, since errors should be user-visible
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.write_str(error::Error::description(self))
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> { None }

    fn description(&self) -> &str {
        match *self {
            Error::InvalidSessionID =>  "secp musig: invalid session id",
            Error::SessionInitFailed =>  "secp musig: session initalization failed",
            Error::SessionPublicNonceFailed =>  "secp musig: musig public nonce could not be retrieved",
            Error::NonceDoesNotMatchCommitment =>  "secp musig: nonce does not match its 
                                                    signer's nonce commitment (abort the protocol!)",
            Error::SignerNonceMissing => "secp musig: signer nonce missing",
            Error::PartialSignatureConstructionFailed => "secp musig: partial signature could not be 
                                            constructed due to incorrect or inconsistent session state",
            Error::PartialSignatureVerificationFailed => "secp musig: partial signature verification failed
                                                          (invalid signature or bad data)",
            Error::PartialSignatureCombinationFailed => "secp musig: failed to combine partial signatures"                                                         
        }
    }
}

/// Nonce commitment in MuSig sessions
pub struct MuSigNonceCommitment([u8; constants::COMMITMENT_SIZE]);
impl_array_newtype!(MuSigNonceCommitment, u8, constants::COMMITMENT_SIZE);
impl_pretty_debug!(MuSigNonceCommitment);

impl MuSigNonceCommitment {
    /// Serializes nonce commitment into array
    #[inline]
    pub fn serialize(&self) -> [u8; constants::COMMITMENT_SIZE] {
        self.0
    }

    /// Deserializes array into nonce commitment
    #[inline]
    pub fn deserialize_from(array: [u8; constants::COMMITMENT_SIZE]) -> Self {
        Self(array)
    }
}

/// *unique* session ID in MuSig sessions
pub struct MuSigSessionID([u8; constants::SESSION_ID_SIZE]);
impl_array_newtype!(MuSigSessionID, u8, constants::SESSION_ID_SIZE);
impl_pretty_debug!(MuSigSessionID);

#[cfg(feature = "zeroize")]
impl Drop for MuSigSessionID {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A MuSig partial signature
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(feature = "zeroize"), derive(Copy))]
pub struct MuSigPartialSignature(ffi::MuSigPartialSignature);

impl MuSigPartialSignature {
    /// Serializes multi-sig partial signature into array
    pub fn serialize(&self) -> [u8; constants::MUSIG_PARTIAL_SIGNATURE_SIZE] {
        let mut ret = [0; constants::MUSIG_PARTIAL_SIGNATURE_SIZE];

        unsafe {
            let err = ffi::secp256k1_musig_partial_signature_serialize(
                ffi::secp256k1_context_no_precomp,
                ret.as_mut_ptr(),
                &self.0 as *const ffi::MuSigPartialSignature,
            );
            debug_assert_eq!(err, 1);
        }

        ret
    }

    /// Deserializes array into multi-sig partial signature
    pub fn deserialize_from(array: [u8; constants::MUSIG_PARTIAL_SIGNATURE_SIZE]) -> Result<Self, Error> {
        let mut sig = unsafe { ffi::MuSigPartialSignature::blank() };

        unsafe {
            if ffi::secp256k1_musig_partial_signature_parse(
                ffi::secp256k1_context_no_precomp,
                &mut sig,
                array.as_ptr(),
            ) == 1 {
                Ok(Self(sig))
            } else {
                Err(Error::PartialSignatureConstructionFailed)
            }
        }
    }
}

impl MuSigSessionID {
    /// Creates a new random session ID. Requires compilation with the "rand" feature.
    #[inline]
    #[cfg(any(test, feature = "rand"))]
    pub fn new<R: Rng>(rng: &mut R) -> MuSigSessionID {
        let mut data = key::random_32_bytes(rng);
        unsafe {
            while ffi::secp256k1_ec_seckey_verify(
                ffi::secp256k1_context_no_precomp,
                data.as_ptr(),
            ) == 0
            {
                data = key::random_32_bytes(rng);
            }
        }
        MuSigSessionID(data)
    }

    /// Converts a `SESSION_ID_SIZE`-byte slice to a session id
    #[inline]
    pub fn from_slice(data: &[u8])-> Result<MuSigSessionID, Error> {
        match data.len() {
            constants::SESSION_ID_SIZE => {
                let mut ret = [0; constants::SESSION_ID_SIZE];
                unsafe {
                    if ffi::secp256k1_ec_seckey_verify(
                        ffi::secp256k1_context_no_precomp,
                        data.as_ptr(),
                    ) == 0
                    {
                        return Err(Error::InvalidSessionID);
                    }
                }
                ret[..].copy_from_slice(data);
                Ok(MuSigSessionID(ret))
            }
            _ => Err(Error::InvalidSessionID)
        }
    }
}

/// The secp256k1 musig session
/// TODO: verifier-only session
/// TODO: adaptor signatures
pub struct MuSigSession<'a, C> {
    secp: &'a Secp256k1<C>,
    session: ffi::MuSigSession,
    signers: Vec<ffi::MuSigSessionSignerData>,
    nonce_commitments: Vec<MuSigNonceCommitment>,
    my_index: usize
}

impl<'a, C> MuSigSession<'a, C> {
    /// Initializes a new MuSig signing session: takes secp256k1 context with signing capabilities,
    /// a *unique* session_id, message to sign on, combined public key, the number of signers,
    /// the signer's position in the signers' array (my_index), and the signer's secret key.
    pub fn new(secp: &'a Secp256k1<C>,
           session_id: MuSigSessionID, 
           message: &Message,
           combined_pk: &PublicKey,
           combined_pk_hash: &PublicKeyHash,
           signers_len: usize,
           my_index: usize,
           signer_secret_key: &SecretKey)
           -> Result<MuSigSession<'a, C>, Error> {
        let mut session = ffi::MuSigSession::new();
        let mut nonce_commitment = [0; constants::COMMITMENT_SIZE];
        let mut nonce_commitments = vec![MuSigNonceCommitment(nonce_commitment); signers_len];
        let mut signers: Vec<ffi::MuSigSessionSignerData> = 
            vec![ffi::MuSigSessionSignerData::new(); signers_len];

        unsafe {
            let res = ffi::secp256k1_musig_session_initialize(
                secp.ctx,
                &mut session,
                &mut signers[0],
                nonce_commitment.as_mut_ptr(),
                session_id.0.as_ptr(),
                message.as_ptr(),
                combined_pk.as_ptr(),
                combined_pk_hash.as_ptr(),
                signers_len,
                my_index,
                signer_secret_key.as_ptr());
            if res == 1 {
                nonce_commitments[my_index] = MuSigNonceCommitment(nonce_commitment);
                Ok(MuSigSession {secp, session, signers, nonce_commitments, my_index})
            } else {
                Err(Error::SessionInitFailed)
            }
        }
    }

    /// Retrieves the signer's nonce commitment (available after initialization)
    pub fn get_my_nonce_commitment(&self) -> MuSigNonceCommitment {
        self.nonce_commitments[self.my_index].clone()
    }

    /// Sets all nonce commitments (during the nonce commitment exchange phase)
    pub fn set_nonce_commitments(&mut self, nonce_commitments: Vec<MuSigNonceCommitment>) {
        self.nonce_commitments = nonce_commitments;
    }

    /// Sets one signer's nonce commitments (during the nonce commitment exchange phase)
    pub fn set_nonce_commitment(&mut self, nonce_commitment: MuSigNonceCommitment, index: usize) {
        self.nonce_commitments[index] = nonce_commitment;
    }

    /// Gets the signer's public nonce (after all signers' nonce commitments were set)
    pub fn get_public_nonce(&self) -> Result<PublicKey, Error> {
        let commitments: Vec<*const u8> = self.nonce_commitments.iter().map(|x| x.as_ptr()).collect();
        unsafe {
            let mut nonce = ffi::PublicKey::blank();
            let ret = ffi::secp256k1_musig_session_get_public_nonce(
                self.secp.ctx,
                &self.session,
                &self.signers[0],
                &mut nonce,
                commitments.as_ptr(),
                commitments.len(),
                ptr::null()
            );
            if ret == 1 {
                Ok(PublicKey::from(nonce))
            } else {
                Err(Error::SessionPublicNonceFailed)
            }
        }
    }

    /// Checks one signer's public nonce against its commitment and sets it if they match.
    /// WARNING: abort the protocol if this fails; if you want to make another attempt
    /// at finishing the protocol, create a new session (with a fresh session ID!).
    pub fn set_nonce(&mut self, signer_index: usize, signer_nonce: PublicKey) -> Result<(), Error> {
        unsafe {
            let ret = ffi::secp256k1_musig_set_nonce(
                self.secp.ctx,
                &mut self.signers[signer_index],
                signer_nonce.as_ptr()
            );
            if ret == 1 {
                Ok(())
            } else {
                Err(Error::NonceDoesNotMatchCommitment)
            }
        }
    }

    /// Updates a session with the combined public nonce of all signers
    /// (after all signers' nonces are successfully set).
    /// The combined public nonce is the sum of every signer's public nonce.
    pub fn combine_nonces(&mut self) -> Result<NonceIsNegated, Error> {
        unsafe {
            let mut nonce_is_negated: std::os::raw::c_int = 0;
            let ret = ffi::secp256k1_musig_session_combine_nonces(
                self.secp.ctx,
                &self.session,
                &self.signers[0],
                self.signers.len(),
                &mut nonce_is_negated,
                ptr::null_mut()
            );
            if ret == 1 {
                Ok(nonce_is_negated != 0)
            } else {
                Err(Error::NonceDoesNotMatchCommitment)
            }
        }
    }

    /// Produces a partial signature
    /// (after the combined public nonce is computed).
    pub fn partial_sign(&self) -> Result<MuSigPartialSignature, Error> {
        unsafe {
            let mut signature = ffi::MuSigPartialSignature::blank();
            let ret = ffi::secp256k1_musig_partial_sign(
                self.secp.ctx,
                &self.session,
                &mut signature
            );
            if ret == 1 {
                Ok(MuSigPartialSignature(signature))
            } else {
                Err(Error::PartialSignatureConstructionFailed)
            }
        }
    }

    /// Checks that an individual partial signature verifies.
    /// NOTE: this is not essential for regular MuSig's sessions,
    /// as the combined signature will also not verify.
    /// This function allows determining the specific party
    /// who produced an invalid signature, so that signing 
    /// can be restarted without them.
    pub fn partial_sig_verify(&self,
                              signature: &MuSigPartialSignature,
                              signer_index: usize,
                              signer_pk: &PublicKey)
                              -> Result<(), Error> {
        unsafe {
            let ret = ffi::secp256k1_musig_partial_sig_verify(
                self.secp.ctx,
                &self.session,
                &self.signers[signer_index],
                &signature.0,
                signer_pk.as_ptr()
            );
            if ret == 1 {
                Ok(())
            } else {
                Err(Error::PartialSignatureVerificationFailed)
            }
        }
    }

    /// Combines partial signatures
    /// into a single regular Schnorr signature
    pub fn partial_sig_combine(&self,
                              signatures: &[MuSigPartialSignature])
                              -> Result<SchnorrSignature, Error> {
        let sigs: Vec<ffi::MuSigPartialSignature> = signatures.iter().map(|x| x.0.clone()).collect();
        unsafe {
            let mut sig = ffi::SchnorrSignature::blank();
            let ret = ffi::secp256k1_musig_partial_sig_combine(
                self.secp.ctx,
                &self.session,
                &mut sig,
                &sigs[0],
                sigs.len(),
                ptr::null() // TODO: ec_pubkey_tweak_add
            );
            if ret == 1 {
                Ok(SchnorrSignature::from(sig))
            } else {
                Err(Error::PartialSignatureCombinationFailed)
            }
        }
    }

}

#[cfg(feature = "zeroize")]
impl<'a, C> Drop for MuSigSession<'a, C> {
    fn drop(&mut self) {
        self.session.zeroize();
        // TODO: call musig ffi destructs when available
    }
}

#[cfg(test)]
mod tests {
    use rand::{RngCore, thread_rng};
    use key::pubkey_combine;
    use schnorrsig::schnorr_verify;
    use super::{Secp256k1, MuSigSessionID, MuSigSession, 
        MuSigNonceCommitment, MuSigPartialSignature, Message, PublicKey, Error};

    #[test]
    fn pk_combine_works() {
        let vrfy = Secp256k1::verification_only();
        let full = Secp256k1::new();
        let (_, pk1) = full.generate_keypair(&mut thread_rng());
        let (_, pk2) = full.generate_keypair(&mut thread_rng());
        let (_, pk3) = full.generate_keypair(&mut thread_rng());

        assert!(pubkey_combine(&vrfy, &vec![pk1, pk2, pk3]).is_ok());
        assert_eq!(pubkey_combine(&vrfy, &vec![pk1, pk2, pk3]), pubkey_combine(&full, &vec![pk1, pk2, pk3]));
    }

    #[test]
    fn musig_example_works() {
        let full = Secp256k1::new();
        let signers = [full.generate_keypair(&mut thread_rng()), 
                        full.generate_keypair(&mut thread_rng()), 
                        full.generate_keypair(&mut thread_rng())];
        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();
        let pks: Vec<PublicKey> = signers.iter().map(|x| x.1).collect();
        let mut sessions = Vec::new();
        // Initialize session
        for i in 0..signers.len() {
            let signer = signers[i];
            let pksc = pubkey_combine(&full, &pks);
            let session_id = MuSigSessionID::new(&mut thread_rng());
            assert!(pksc.is_ok());
            if let Ok((pk, pk_hash)) = pksc {
                let session = 
                    MuSigSession::new(&full, session_id, &msg, &pk, &pk_hash, signers.len(), i, &signer.0);
                assert!(session.is_ok());
                sessions.push(session.unwrap());
            }
        }
        // Communication round 1: exchange nonce commitments
        let commitments: Vec<MuSigNonceCommitment> = 
            sessions.iter().map(|x| x.get_my_nonce_commitment()).collect();
        for session in sessions.iter_mut() {
            session.set_nonce_commitments(commitments.clone());
        }

        let nonces: Vec<Result<PublicKey, Error>> = 
            sessions.iter().map(|x| x.get_public_nonce()).collect();
        for nonce in nonces.iter() {
            assert!(nonce.is_ok());
        }
        // Communication round 2: exchange nonces
        for i in 0..sessions.len() {
            let session = &mut sessions[i];
            for j in 0..nonces.len() {
                println!("session: {} nonce: {}", i, j);
                let nonce = nonces[j].unwrap();
                assert!(session.set_nonce(j, nonce).is_ok());
            }
            assert!(session.combine_nonces().is_ok());
        }

        // Communication round 3: exchange partial signatures
        let partial_sigs: Vec<Result<MuSigPartialSignature, Error>> = 
            sessions.iter().map(|x| x.partial_sign()).collect();
        for signature in partial_sigs.iter() {
            assert!(signature.is_ok());
        }
        let signatures: Vec<MuSigPartialSignature> = 
            partial_sigs.iter().map(|x| x.unwrap()).collect();

        let new_signature = MuSigPartialSignature::deserialize_from(signatures[0].serialize()).unwrap();
        assert_eq!(signatures[0], new_signature);
        
        let combined_pk = pubkey_combine(&full, &pks).unwrap().0;
        for session in sessions.iter() {
            for i in 0..signatures.len() {
                let signature = &signatures[i];
                let pk = pks[i];
                assert!(session.partial_sig_verify(signature, i, &pk).is_ok());
            }
            let sig = session.partial_sig_combine(&signatures);
            assert!(sig.is_ok());
            assert!(schnorr_verify(&full, &msg, &sig.unwrap(), &combined_pk).is_ok());
        }

    }
}