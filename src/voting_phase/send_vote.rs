use crate::{
    MAX_LENGTH_WRITE_IN_FIELD,
    preliminaries::{
        AgreementError, ElectoralModelContext, ElectoralModelError, GetHashContextContext, PTable,
        PTableTrait, WriteInsError, encode_write_ins, get_hash_context,
    },
};
use rust_ev_crypto_primitives::{
    ConstantsTrait, ConvertStringTait, Integer, ModExponentiateError, OperationsTrait,
    VerifyDomainTrait,
    elgamal::{Ciphertext, ElgamalError, EncryptionParameters},
    random::{RandomError, gen_random_integer},
    zero_knowledge_proofs::{
        ExponentiationProofError, PlaintextProofError, gen_exponentiation_proof,
        gen_plaintext_equality_proof,
    },
};
use std::iter;
use thiserror::Error;

/// Errors during the algorithms for Send Vote
#[derive(Error, Debug)]
#[error(transparent)]
pub struct SendVoteError(#[from] SendVoteErrorRepr);

// enum representing the errors during the algorithms for Send Vote
#[derive(Error, Debug)]
enum SendVoteErrorRepr {
    #[error("Error in modular exponentiation: {reason}")]
    ModularExponentiation {
        reason: String,
        source: ModExponentiateError,
    },
    #[error("Domain verification failed")]
    DomainVerificationFailed { errors: Vec<SendVoteError> },
    #[error("Electoral model error: {msg}")]
    ElectoralModelError {
        msg: String,
        source: ElectoralModelError,
    },
    #[error("Write-ins error: {msg}")]
    WriteInsError { msg: String, source: WriteInsError },
    #[error("Random error: {msg}")]
    RandomError { msg: String, source: RandomError },
    #[error("error: {msg}")]
    ElgamalError { msg: String, source: ElgamalError },
    #[error("Error calculating GetHashContext")]
    HashContext { source: AgreementError },
    #[error("Error calculating exponentiation proof pi_exp")]
    ExpProofError { source: ExponentiationProofError },
    #[error("Error calculating plaintext equality proof pi_eq_enc")]
    PlaintextEqualityProofError { source: PlaintextProofError },
    #[error("{msg}")]
    DomainError { msg: String },
}

/// Context for the algorithm 5.4 CreateVote
pub struct CreateVoteContext<'a> {
    pub encryption_parameters: &'a EncryptionParameters,
    /// The election event identifier
    pub ee_id: &'a str,
    /// The voting card set identifier
    pub vcs_id: &'a str,
    /// The voting card identifier
    pub vc_id: &'a str,
    /// The pTable
    pub p_table: &'a PTable,
    // The Electoral model context
    pub upper_lambda: &'a ElectoralModelContext,
    /// The Election public key
    pub el_pk: &'a [Integer],
    /// The Choice Return Codes encryption public key
    pub pk_ccr: &'a [Integer],
}

/// Input for the algorithm 5.4 CreateVote
pub struct CreateVoteInput<'a> {
    /// The Selected actual voting options
    pub v_tilde_id: &'a [&'a str],
    /// Selected write-ins
    pub s_tilde_id: &'a [&'a str],
    /// Verification card secret key
    pub k_id: &'a Integer,
}

/// Output for the algorithm 5.4 CreateVote
pub struct CreateVoteOutput {
    pub upper_e_1: Vec<Integer>,
    pub upper_e_2: Vec<Integer>,
    pub upper_e_1_tilde: (Integer, Integer),
    pub pi_exp: (Integer, Integer),
    pub pi_eq_enc: (Integer, (Integer, Integer)),
}

impl<'a> CreateVoteInput<'a> {
    pub fn create_vote(
        &self,
        context: &CreateVoteContext,
    ) -> Result<CreateVoteOutput, SendVoteError> {
        self.create_vote_impl(context).map_err(SendVoteError::from)
    }

    fn create_vote_impl(
        &self,
        context: &CreateVoteContext,
    ) -> Result<CreateVoteOutput, SendVoteErrorRepr> {
        let domain_res = self.verifiy_domain(context);
        if !domain_res.is_empty() {
            return Err(SendVoteErrorRepr::DomainVerificationFailed { errors: domain_res });
        }

        let p_hat = context
            .p_table
            .get_encoded_voting_options(self.v_tilde_id)
            .map_err(|e| SendVoteErrorRepr::ElectoralModelError {
                msg: "Error getting encoded voting options".to_string(),
                source: e,
            })?;

        let w_id = encode_write_ins(
            context.encryption_parameters,
            context.p_table.get_delta(),
            self.s_tilde_id,
        )
        .map_err(|e| SendVoteErrorRepr::WriteInsError {
            msg: "Error calculating w_id".to_string(),
            source: e,
        })?;

        let rho = p_hat.iter().fold(Integer::from(1), |acc, &p_tilde_i| {
            acc.mod_multiply(&Integer::from(p_tilde_i), context.encryption_parameters.p())
        });
        let r = gen_random_integer(context.encryption_parameters.q()).map_err(|e| {
            SendVoteErrorRepr::RandomError {
                msg: "Error generating random r".to_string(),
                source: e,
            }
        })?;

        let vec_for_e_upper_1 = iter::once(rho).chain(w_id).collect::<Vec<_>>();
        let e_upper_1 = Ciphertext::get_ciphertext(
            context.encryption_parameters,
            &vec_for_e_upper_1,
            &r,
            context.el_pk,
        )
        .map_err(|e| SendVoteErrorRepr::ElgamalError {
            msg: "Error calculating E_1".to_string(),
            source: e,
        })?;

        let e_upper_1_tilde =
            Ciphertext::from_expanded(&e_upper_1.gamma, &[e_upper_1.phis.first().unwrap().clone()])
                .get_ciphertext_exponentiation(self.k_id, context.encryption_parameters)
                .map_err(|e| SendVoteErrorRepr::ElgamalError {
                    msg: "Error calculating E_1_tilde".to_string(),
                    source: e,
                })?;

        let p_cc_id = p_hat
            .iter()
            .map(|p| {
                Integer::from(*p).mod_exponentiate(self.k_id, context.encryption_parameters.p())
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| SendVoteErrorRepr::ModularExponentiation {
                reason: "Calculating pCC_id".to_string(),
                source: e,
            })?;
        let r_prime = gen_random_integer(context.encryption_parameters.q()).map_err(|e| {
            SendVoteErrorRepr::RandomError {
                msg: "Error generating random r".to_string(),
                source: e,
            }
        })?;
        let e_upper_2 = Ciphertext::get_ciphertext(
            context.encryption_parameters,
            &p_cc_id,
            &r_prime,
            context.pk_ccr,
        )
        .map_err(|e| SendVoteErrorRepr::ElgamalError {
            msg: "Error calculating E_2".to_string(),
            source: e,
        })?;

        let e_upper_2_tilde = (
            &e_upper_2.gamma,
            e_upper_2
                .phis
                .iter()
                .fold(Integer::one().clone(), |acc, phi_i| {
                    acc.mod_multiply(phi_i, context.encryption_parameters.p())
                }),
        );

        let upper_k_id = context
            .encryption_parameters
            .g()
            .mod_exponentiate(self.k_id, context.encryption_parameters.p())
            .map_err(|e| SendVoteErrorRepr::ModularExponentiation {
                reason: "Calculating upper_k_id".to_string(),
                source: e,
            })?;

        let mut i_aux = vec![
            "CreateVote".to_string(),
            context.vc_id.to_string(),
            get_hash_context(&GetHashContextContext {
                encryption_parameters: context.encryption_parameters,
                ee: context.ee_id,
                vcs: context.vcs_id,
                p_table: context.p_table,
                upper_lambda: context.upper_lambda,
                el_pk: context.el_pk.iter().collect::<Vec<_>>().as_slice(),
                pk_ccr: context.pk_ccr.iter().collect::<Vec<_>>().as_slice(),
            })
            .map_err(|e| SendVoteErrorRepr::HashContext { source: e })?,
        ];
        i_aux.extend(
            e_upper_1
                .to_vec()
                .into_iter()
                .map(|i| i.integer_to_string()),
        );
        i_aux.extend(
            e_upper_2
                .to_vec()
                .into_iter()
                .map(|i| i.integer_to_string()),
        );
        let pi_exp = gen_exponentiation_proof(
            context.encryption_parameters,
            &[
                context.encryption_parameters.g(),
                &e_upper_1.gamma,
                e_upper_1.phis.first().unwrap(),
            ],
            self.k_id,
            &[
                &upper_k_id,
                &e_upper_1
                    .gamma
                    .mod_exponentiate(self.k_id, context.encryption_parameters.p())
                    .map_err(|e| SendVoteErrorRepr::ModularExponentiation {
                        reason: "pi_exp".to_string(),
                        source: e,
                    })?,
                &e_upper_1
                    .phis
                    .first()
                    .unwrap()
                    .mod_exponentiate(self.k_id, context.encryption_parameters.p())
                    .map_err(|e| SendVoteErrorRepr::ModularExponentiation {
                        reason: "pi_exp".to_string(),
                        source: e,
                    })?,
            ],
            &i_aux,
        )
        .map_err(|e| SendVoteErrorRepr::ExpProofError { source: e })?;

        let pk_ccr_tilde = context
            .pk_ccr
            .iter()
            .fold(Integer::one().clone(), |acc, pk_ccr_i| {
                acc.mod_multiply(pk_ccr_i, context.encryption_parameters.p())
            });

        let pi_eq_enc = gen_plaintext_equality_proof(
            context.encryption_parameters,
            (
                &e_upper_1_tilde.gamma,
                e_upper_1_tilde.phis.first().unwrap(),
            ),
            (e_upper_2_tilde.0, &e_upper_2_tilde.1),
            context.el_pk.first().unwrap(),
            &pk_ccr_tilde,
            (
                &r.mod_multiply(self.k_id, context.encryption_parameters.p()),
                &r_prime,
            ),
            &i_aux,
        )
        .map_err(|e| SendVoteErrorRepr::PlaintextEqualityProofError { source: e })?;

        Ok(CreateVoteOutput {
            upper_e_1: e_upper_1.to_vec().into_iter().cloned().collect(),
            upper_e_2: e_upper_2.to_vec().into_iter().cloned().collect(),
            upper_e_1_tilde: (
                e_upper_1_tilde.gamma,
                e_upper_1_tilde.phis.first().unwrap().clone(),
            ),
            pi_exp,
            pi_eq_enc,
        })
    }
}

impl VerifyDomainTrait<CreateVoteContext<'_>, SendVoteError> for CreateVoteInput<'_> {
    fn verifiy_domain(&self, context: &CreateVoteContext<'_>) -> Vec<SendVoteError> {
        let mut res = vec![];

        match context.p_table.get_psi() {
            Ok(psi) => {
                if self.v_tilde_id.len() != psi {
                    res.push(SendVoteError::from(SendVoteErrorRepr::DomainError {
                        msg: "Number of selected voting options does not match psi".to_string(),
                    }));
                }
            }
            Err(e) => res.push(SendVoteError::from(
                SendVoteErrorRepr::ElectoralModelError {
                    msg: "claculating psi".to_string(),
                    source: e,
                },
            )),
        };

        match context.p_table.get_blank_correctness_information() {
            Ok(blank) => match context.p_table.get_correctness_information(self.v_tilde_id) {
                Ok(correctness) => {
                    let correctness_str =
                        correctness.iter().map(|c| c.as_str()).collect::<Vec<_>>();
                    if blank != correctness_str {
                        res.push(SendVoteError::from(SendVoteErrorRepr::DomainError {
                            msg: "Correctness information does not match blank correctness information"
                                .to_string(),
                        }));
                    }
                }
                Err(e) => res.push(SendVoteError::from(
                    SendVoteErrorRepr::ElectoralModelError {
                        msg: "claculating CorrectnessInformation".to_string(),
                        source: e,
                    },
                )),
            },
            Err(e) => res.push(SendVoteError::from(
                SendVoteErrorRepr::ElectoralModelError {
                    msg: "claculating BlankCorrectnessInformation".to_string(),
                    source: e,
                },
            )),
        };

        if self.s_tilde_id.len() > context.p_table.get_delta() - 1 {
            res.push(SendVoteError::from(SendVoteErrorRepr::DomainError {
                msg: "Number of selected write-ins exceeds delta - 1".to_string(),
            }));
        }

        for (i, s_tilde_id_i) in self.s_tilde_id.iter().enumerate() {
            if s_tilde_id_i.is_empty() {
                res.push(SendVoteError::from(SendVoteErrorRepr::DomainError {
                    msg: format!("Write-in at index {} is empty", i),
                }));
            }
            if s_tilde_id_i.len() >= MAX_LENGTH_WRITE_IN_FIELD {
                res.push(SendVoteError::from(SendVoteErrorRepr::DomainError {
                    msg: format!("Write-in at index {} exceeds maximum length", i),
                }));
            }
        }

        res
    }
}
