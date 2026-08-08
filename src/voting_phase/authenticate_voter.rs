// Copyright © 2026 Denis Morel

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License and
// a copy of the GNU General Public License along with this program. If not, see
// <https://www.gnu.org/licenses/>.

use crate::preliminaries::{
    AgreementError, DeriveBaseAuthenticationChallengeContext,
    DeriveBaseAuthenticationChallengeInput, ElectoralModelContext, GetHashContextContext, PTable,
    VoterAuthenticationError, derive_credential_id, get_hash_context,
};
use rust_ev_crypto_primitives::argon2::{Argon2Error, Argon2id, Argon2idParameters};
use rust_ev_crypto_primitives::elgamal::EncryptionParameters;
use rust_ev_crypto_primitives::random::RandomError;
use rust_ev_crypto_primitives::symmetric_authenticated_encryption::{
    AuthenticatedEncryptionDecrypt, SymAuthenticatedEncryptionError, get_symmetric_ciphertext_parts,
};
use rust_ev_crypto_primitives::{
    ByteArray, ByteArrayError, DecodeTrait, EncodeTrait, HashError, HashableMessage,
    RecursiveHashTrait, ToByteArryTrait,
};
use rust_ev_crypto_primitives::{ConstantsTrait, Integer, ops::Pow, random::gen_random_integer};
use std::fmt::Display;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

const NONCE_LENGTH: usize = 12;
const SALT_LENGTH: usize = 32;

/// Errors during the algorithms for Authenticate Voter
#[derive(Error, Debug)]
#[error(transparent)]
pub struct AuthenticateVoterError(#[from] AuthenticateVoterErrorRepr);

// enum representing the errors during the algorithms for Authenticate Voter
#[derive(Error, Debug)]
enum AuthenticateVoterErrorRepr {
    #[error("{msg}")]
    VoterAuthenticationError {
        msg: String,
        source: Box<VoterAuthenticationError>,
    },
    #[error("Error collecting system time")]
    SystemTimeError { source: std::time::SystemTimeError },
    #[error("Error generating random nonce")]
    RandomError { source: RandomError },
    #[error("Error hashing: {reason}")]
    ErrorHashing { reason: String, source: HashError },
    #[error("Error ByteArray: {reason}")]
    ErrorByteArray {
        reason: String,
        source: ByteArrayError,
    },
    #[error("Error in argon2id: {reason}")]
    ErrorArgon2id { reason: String, source: Argon2Error },
    #[error("Agreement error: {reason}")]
    AgreementError {
        reason: String,
        source: AgreementError,
    },
    #[error("Symmetric decryption error: {reason}")]
    SymAuthenticatedEncryptionError {
        reason: String,
        source: SymAuthenticatedEncryptionError,
    },
}

/// Authentication Steps of the voting phase
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthStep {
    /// Step 1: Authenticate Voter
    AuthenticateVoter,
    /// Step 2: Send Vote
    SendVote,
    /// Step 3: Confirm Vote
    ConfirmVote,
}

impl Display for AuthStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthStep::AuthenticateVoter => write!(f, "authenticateVoter"),
            AuthStep::SendVote => write!(f, "sendVote"),
            AuthStep::ConfirmVote => write!(f, "confirmVote"),
        }
    }
}

/// Context for the algorithm 5.1 GetAuthenticationChallenge
pub struct GetAuthenticationChallengeContext<'a> {
    /// The election event identifier
    pub ee_id: &'a str,
    /// The character length of the extended authentificator
    pub char_length_of_ea: usize,
}

/// Input for the algorithm 5.1 GetAuthenticationChallenge
pub struct GetAuthenticationChallengeInput<'a> {
    /// The authentication step
    pub auth_step: AuthStep,
    /// The start voting key
    pub svk_id: &'a str,
    /// The extended authentificator
    pub ea_id: &'a str,
}

pub struct GetAuthenticationChallengeOutput {
    /// Derived voter identifier
    pub credential_id_id: String,
    /// Derived authentication challenge
    pub hh_auth_id: String,
    /// Authentication nonce
    pub nonce: Integer,
}

impl<'a> GetAuthenticationChallengeInput<'a> {
    /// Algorithm 5.1 GetAuthenticationChallenge
    pub fn get_authentication_challenge(
        &self,
        context: &GetAuthenticationChallengeContext,
    ) -> Result<GetAuthenticationChallengeOutput, AuthenticateVoterError> {
        self.get_authentication_challenge_impl(context)
            .map_err(AuthenticateVoterError::from)
    }

    fn get_authentication_challenge_impl(
        &self,
        context: &GetAuthenticationChallengeContext,
    ) -> Result<GetAuthenticationChallengeOutput, AuthenticateVoterErrorRepr> {
        let credential_id_id = derive_credential_id(context.ee_id, self.svk_id).map_err(|e| {
            AuthenticateVoterErrorRepr::VoterAuthenticationError {
                msg: "Error deriving credential ID".to_string(),
                source: Box::new(e),
            }
        })?;
        let h_auth_id = DeriveBaseAuthenticationChallengeInput::from(self)
            .derive_base_authentication_challenge(&DeriveBaseAuthenticationChallengeContext::from(
                context,
            ))
            .map_err(|e| AuthenticateVoterErrorRepr::VoterAuthenticationError {
                msg: "Error deriving authentication challenge".to_string(),
                source: Box::new(e),
            })?;
        let nonce = gen_random_integer(&(Integer::from(Integer::two().pow(256))))
            .map_err(|e| AuthenticateVoterErrorRepr::RandomError { source: e })?;
        let ts = Integer::from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| AuthenticateVoterErrorRepr::SystemTimeError { source: e })?
                .as_secs(),
        );
        let t: Integer = ts / 300;
        let salt_id = HashableMessage::from(vec![
            HashableMessage::from(context.ee_id),
            HashableMessage::from("dAuth"),
            HashableMessage::from(self.auth_step.to_string()),
            HashableMessage::from(&nonce),
        ])
        .recursive_hash()
        .map_err(|e| AuthenticateVoterErrorRepr::ErrorHashing {
            reason: "Error hashing salt ID".to_string(),
            source: e,
        })?
        .cut_bit_length(128)
        .map_err(|e| AuthenticateVoterErrorRepr::ErrorByteArray {
            reason: "Error calculating salt_id".to_string(),
            source: e,
        })?;
        let k = ByteArray::from(h_auth_id.as_bytes())
            .new_append(&ByteArray::from("Auth"))
            .new_append(&t.to_byte_array().unwrap());
        let bh_auth_id = Argon2id::new(Argon2idParameters::Less)
            .get_argon2id(&k, &salt_id)
            .map_err(|e| AuthenticateVoterErrorRepr::ErrorArgon2id {
                reason: "Calculating bh_auth_id".to_string(),
                source: e,
            })?;
        let hh_auth_id = bh_auth_id.base64_encode().unwrap();
        Ok(GetAuthenticationChallengeOutput {
            credential_id_id,
            hh_auth_id,
            nonce,
        })
    }
}

impl<'a> From<&GetAuthenticationChallengeContext<'a>>
    for DeriveBaseAuthenticationChallengeContext<'a>
{
    fn from(context: &GetAuthenticationChallengeContext<'a>) -> Self {
        Self {
            ee_id: context.ee_id,
            char_length_of_ea: context.char_length_of_ea,
        }
    }
}

impl<'a> From<&GetAuthenticationChallengeInput<'a>> for DeriveBaseAuthenticationChallengeInput<'a> {
    fn from(input: &GetAuthenticationChallengeInput<'a>) -> Self {
        Self {
            svk_id: input.svk_id,
            ea_id: input.ea_id,
        }
    }
}

/// Context for the algorithm 5.3 GetKey
pub struct GetKeyContext<'a> {
    pub encryption_parameters: &'a EncryptionParameters,
    pub ee: &'a str,
    pub vcs: &'a str,
    pub vc_id: &'a str,
    pub p_table: &'a PTable,
    pub upper_lambda: &'a ElectoralModelContext,
    pub el_pk: &'a [&'a Integer],
    pub pk_ccr: &'a [&'a Integer],
}

/// Input for the algorithm 5.3 GetKey
pub struct GetKeyInput<'a> {
    pub svk_id: &'a str,
    pub vcks_id: &'a str,
}

impl<'a> GetKeyInput<'a> {
    /// Algorithm 5.3 GetKey
    pub fn get_key(&self, context: &GetKeyContext) -> Result<Integer, AuthenticateVoterError> {
        self.get_key_impl(context)
            .map_err(AuthenticateVoterError::from)
    }

    fn get_key_impl(&self, context: &GetKeyContext) -> Result<Integer, AuthenticateVoterErrorRepr> {
        let i_aux = [
            "getKey".to_string(),
            get_hash_context(&GetHashContextContext::from(context)).map_err(|e| {
                AuthenticateVoterErrorRepr::AgreementError {
                    reason: "Error calculating i_aux".to_string(),
                    source: e,
                }
            })?,
        ];
        let (vcks_id_ciphertext, vcks_id_nonce, vcks_id_salt) =
            get_symmetric_ciphertext_parts(self.vcks_id).map_err(|e| {
                AuthenticateVoterErrorRepr::SymAuthenticatedEncryptionError {
                    reason: "Error getting symmetric ciphertext parts".to_string(),
                    source: e,
                }
            })?;
        let dsvk_id = Argon2id::new(Argon2idParameters::Less)
            .get_argon2id(&ByteArray::from(self.svk_id), &vcks_id_salt)
            .map_err(|e| AuthenticateVoterErrorRepr::ErrorArgon2id {
                reason: "Calculating dsvk_id".to_string(),
                source: e,
            })?;
        let kskey_id = HashableMessage::from(vec![
            HashableMessage::from("VerificationCardKeystore"),
            HashableMessage::from(context.ee),
            HashableMessage::from(context.vcs),
            HashableMessage::from(context.vc_id),
            HashableMessage::from(&dsvk_id),
        ])
        .recursive_hash()
        .map_err(|e| AuthenticateVoterErrorRepr::ErrorHashing {
            reason: "Error calculating KSkeyid".to_string(),
            source: e,
        })?;
        let mut decrpyter =
            AuthenticatedEncryptionDecrypt::new(&kskey_id, &vcks_id_nonce, i_aux.as_slice())
                .map_err(
                    |e| AuthenticateVoterErrorRepr::SymAuthenticatedEncryptionError {
                        reason: "Error creating decrypter".to_string(),
                        source: e,
                    },
                )?;
        let k_id_bytes = decrpyter
            .get_plaintext_symmetric(&vcks_id_ciphertext)
            .map_err(
                |e| AuthenticateVoterErrorRepr::SymAuthenticatedEncryptionError {
                    reason: "Error decrypting vcks_id".to_string(),
                    source: e,
                },
            )?;
        let k_id = k_id_bytes.into_integer();
        Ok(k_id)
    }
}

impl<'a> From<&'a GetKeyContext<'a>> for GetHashContextContext<'a> {
    fn from(context: &'a GetKeyContext) -> Self {
        Self {
            encryption_parameters: context.encryption_parameters,
            ee: context.ee,
            vcs: context.vcs,
            p_table: context.p_table,
            upper_lambda: context.upper_lambda,
            el_pk: context.el_pk,
            pk_ccr: context.pk_ccr,
        }
    }
}
