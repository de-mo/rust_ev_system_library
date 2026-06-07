use rust_ev_crypto_primitives::{
    ByteArray, ByteArrayError, EncodeTrait, HashError, HashableMessage, RecursiveHashTrait,
    argon2::{Argon2Error, Argon2id, Argon2idParameters},
};
use thiserror::Error;

/// Enum representing the errors during the algorithms in voter authentification
#[derive(Error, Debug)]
#[error(transparent)]
pub struct VoterAuthenticationError(#[from] VoterAuthenticationErrorRepr);

#[derive(Error, Debug)]
enum VoterAuthenticationErrorRepr {
    #[error("Error hashing: {reason}")]
    ErrorHashing { reason: String, source: HashError },
    #[error("Error ByteArray: {reason}")]
    ErrorByteArray {
        reason: String,
        source: ByteArrayError,
    },
    #[error("Error in argon2id: {reason}")]
    ErrorArgon2id { reason: String, source: Argon2Error },
    #[error("Domain error: {reason}")]
    DomainError { reason: String },
}

/// Algorithm 3.19 DeriveCredentialId
///
/// # inputs
/// - `ee_id`: The election event identifier
/// - `svk_id`: The start voting key
pub fn derive_credential_id(ee_id: &str, svk_id: &str) -> Result<String, VoterAuthenticationError> {
    derive_credential_id_impl(ee_id, svk_id).map_err(VoterAuthenticationError::from)
}

fn derive_credential_id_impl(
    ee_id: &str,
    svk_id: &str,
) -> Result<String, VoterAuthenticationErrorRepr> {
    let salt = HashableMessage::from(vec![
        HashableMessage::from(ee_id),
        HashableMessage::from("credentialId"),
    ])
    .recursive_hash()
    .map_err(|e| VoterAuthenticationErrorRepr::ErrorHashing {
        reason: "Calculating salt".to_string(),
        source: e,
    })?
    .cut_bit_length(128)
    .map_err(|e| VoterAuthenticationErrorRepr::ErrorByteArray {
        reason: "calculating salt".to_string(),
        source: e,
    })?;
    let bcredential_id_id = Argon2id::new(Argon2idParameters::Less)
        .get_argon2id(&ByteArray::from(svk_id), &salt)
        .map_err(|e| VoterAuthenticationErrorRepr::ErrorArgon2id {
            reason: "Calculating credentialId".to_string(),
            source: e,
        })?;
    let bcredential_id = bcredential_id_id
        .cut_bit_length(128)
        .map_err(|e| VoterAuthenticationErrorRepr::ErrorByteArray {
            reason: "calculating bcredential_id".to_string(),
            source: e,
        })?
        .base16_encode()
        .unwrap();
    Ok(bcredential_id)
}

/// Context for the algorithm 3.20 DeriveBaseAuthenticationChallenge
pub struct DeriveBaseAuthenticationChallengeContext<'a> {
    /// The election event identifier
    pub ee_id: &'a str,
    /// The character length of the extended authentificator
    pub char_length_of_ea: usize,
}

/// Input for the algorithm 3.20 DeriveBaseAuthenticationChallenge
pub struct DeriveBaseAuthenticationChallengeInput<'a> {
    /// The start voting key
    pub svk_id: &'a str,
    /// The extended authentificator
    pub ea_id: &'a str,
}

impl<'a> DeriveBaseAuthenticationChallengeInput<'a> {
    /// Algorithm 3.20 DeriveBaseAuthenticationChallenge
    pub fn derive_base_authentication_challenge(
        &self,
        context: &DeriveBaseAuthenticationChallengeContext,
    ) -> Result<String, VoterAuthenticationError> {
        self.derive_base_authentication_challenge_impl(context)
            .map_err(VoterAuthenticationError::from)
    }

    fn derive_base_authentication_challenge_impl(
        &self,
        context: &DeriveBaseAuthenticationChallengeContext,
    ) -> Result<String, VoterAuthenticationErrorRepr> {
        if self.ea_id.len() != context.char_length_of_ea {
            return Err(VoterAuthenticationErrorRepr::DomainError {
                reason: format!(
                    "ea_id has length {}, expected {}",
                    self.ea_id.len(),
                    context.char_length_of_ea
                ),
            });
        };
        let salt = HashableMessage::from(vec![
            HashableMessage::from(context.ee_id),
            HashableMessage::from("hAuth"),
        ])
        .recursive_hash()
        .map_err(|e| VoterAuthenticationErrorRepr::ErrorHashing {
            reason: "Calculating salt".to_string(),
            source: e,
        })?
        .cut_bit_length(128)
        .map_err(|e| VoterAuthenticationErrorRepr::ErrorByteArray {
            reason: "calculating salt".to_string(),
            source: e,
        })?;
        let k = ByteArray::from(self.ea_id)
            .new_append(&ByteArray::from("Auth"))
            .new_append(&ByteArray::from(self.svk_id));
        let bh_auth_id = Argon2id::new(Argon2idParameters::Less)
            .get_argon2id(&k, &salt)
            .map_err(|e| VoterAuthenticationErrorRepr::ErrorArgon2id {
                reason: "Calculating bh_auth_id".to_string(),
                source: e,
            })?;
        let h_auth_id = bh_auth_id
            .cut_bit_length(128)
            .map_err(|e| VoterAuthenticationErrorRepr::ErrorByteArray {
                reason: "calculating h_auth_id".to_string(),
                source: e,
            })?
            .base64_encode()
            .unwrap();
        Ok(h_auth_id)
    }
}
