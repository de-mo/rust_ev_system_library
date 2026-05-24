use rust_ev_crypto_primitives::{
    HashError, Integer, ModExponentiateError, OperationsTrait, ParseIntegerError,
    elgamal::EncryptionParameters, hash_and_square,
};
use thiserror::Error;

/// Errors during the algorithms for Confirm Vote
#[derive(Error, Debug)]
#[error(transparent)]
pub struct ConfirmVoteError(#[from] ConfirmVoteErrorRepr);

// enum representing the errors during the algorithms for Confirm Vote
#[derive(Error, Debug)]
enum ConfirmVoteErrorRepr {
    #[error("Error hashing: {reason}")]
    Hashing { reason: String, source: HashError },
    #[error("Error parsing integer: {reason}")]
    ParsingInteger {
        reason: String,
        source: ParseIntegerError,
    },
    #[error("Error in modular exponentiation: {reason}")]
    ModularExponentiation {
        reason: String,
        source: ModExponentiateError,
    },
}

/// Context for the algorithm 5.10 CreateConfirmMessage
pub struct CreateConfirmMessageContext<'a> {
    pub encryption_parameters: &'a EncryptionParameters,
}

/// Input for the algorithm 5.10 CreateConfirmMessage
pub struct CreateConfirmMessageInput<'a> {
    /// The ballot casting key
    pub bck_id: &'a str,
    /// The key identifier of the voter
    pub k_id: &'a Integer,
}

impl<'a> CreateConfirmMessageInput<'a> {
    pub fn create_confirm_message(
        &self,
        context: &CreateConfirmMessageContext,
    ) -> Result<Integer, ConfirmVoteError> {
        self.create_confirm_message_impl(context)
            .map_err(ConfirmVoteError::from)
    }

    fn create_confirm_message_impl(
        &self,
        context: &CreateConfirmMessageContext,
    ) -> Result<Integer, ConfirmVoteErrorRepr> {
        let h_bckid = hash_and_square(
            context.encryption_parameters.p(),
            context.encryption_parameters.q(),
            &Integer::from_str_radix(self.bck_id, 10).map_err(|e| {
                ConfirmVoteErrorRepr::ParsingInteger {
                    reason: "Invalid BCK ID".to_string(),
                    source: e,
                }
            })?,
        )
        .map_err(|e| ConfirmVoteErrorRepr::Hashing {
            reason: "Error calculating hBCKid".to_string(),
            source: e,
        })?;
        let ck_id = h_bckid
            .mod_exponentiate(self.k_id, context.encryption_parameters.p())
            .map_err(|e| ConfirmVoteErrorRepr::ModularExponentiation {
                reason: "Error calculating ckId".to_string(),
                source: e,
            })?;
        Ok(ck_id)
    }
}
