use super::{
    get_hash_election_event_context, ElectionEventContextError, GetHashElectionEventContextContext,
};
use rust_ev_crypto_primitives::{
    elgamal::EncryptionParameters, zero_knowledge_proofs::verify_schnorr, HashError, Integer,
    VerifyDomainTrait,
};
use thiserror::Error;
use tracing::instrument;

/// Output structure of VerifyKeyGenerationSchnorrProofs containing all errors and failures
pub struct VerifyKeyGenerationSchnorrProofsOuput {
    pub verif_schnorr_ccr: Vec<String>,
    pub verif_schnorr_ccm: Vec<String>,
    pub verif_schnorr_eb: Vec<String>,
    pub errors: Vec<VerifyKeyGenerationSchnorrProofsError>,
}

/// Input structure of VerifyKeyGenerationSchnorrProofs according to the specifications
pub struct VerifyKeyGenerationSchnorrProofsInput<'a> {
    pub pk_ccr: &'a [Vec<&'a Integer>],
    pub pi_pkccr: &'a [Vec<(&'a Integer, &'a Integer)>],
    pub el_pk: &'a [Vec<&'a Integer>],
    pub pi_elpk: &'a [Vec<(&'a Integer, &'a Integer)>],
    pub eb_pk: &'a [&'a Integer],
    pub pi_eb: &'a [(&'a Integer, &'a Integer)],
}

/// Enum representing the errors during the algorithms VerifyKeyGenerationSchnorrProofs
#[derive(Error, Debug)]
pub enum VerifyKeyGenerationSchnorrProofsError {
    #[error("Error validating domain: {0}")]
    Domain(String),
    #[error("Error calculated schorr proof: {0}")]
    SchorrProof(String),
    #[error(transparent)]
    ElectionEventContextError(#[from] ElectionEventContextError),
    #[error(transparent)]
    HashError(#[from] HashError),
}

impl VerifyKeyGenerationSchnorrProofsOuput {
    fn new_with_error(error: VerifyKeyGenerationSchnorrProofsError) -> Self {
        Self {
            verif_schnorr_ccr: vec![],
            verif_schnorr_ccm: vec![],
            verif_schnorr_eb: vec![],
            errors: vec![error],
        }
    }

    fn new_with_errors(errors: Vec<VerifyKeyGenerationSchnorrProofsError>) -> Self {
        Self {
            verif_schnorr_ccr: vec![],
            verif_schnorr_ccm: vec![],
            verif_schnorr_eb: vec![],
            errors,
        }
    }
}

impl VerifyDomainTrait<VerifyKeyGenerationSchnorrProofsError>
    for (
        &GetHashElectionEventContextContext<'_, '_>,
        &VerifyKeyGenerationSchnorrProofsInput<'_>,
    )
{
    fn verifiy_domain(&self) -> Vec<VerifyKeyGenerationSchnorrProofsError> {
        let mut res = vec![];
        if self.1.pk_ccr.len() != 4 {
            res.push(VerifyKeyGenerationSchnorrProofsError::Domain(format!(
                "Size of pk_ccr must be 4. actual: {}",
                self.1.pk_ccr.len()
            )));
        }
        if self.1.pi_pkccr.len() != 4 {
            res.push(VerifyKeyGenerationSchnorrProofsError::Domain(format!(
                "Size of pi_pkccr must be 4. actual: {}",
                self.1.pi_pkccr.len()
            )));
        }
        if self.1.el_pk.len() != 4 {
            res.push(VerifyKeyGenerationSchnorrProofsError::Domain(format!(
                "Size of el_pk must be 4. actual: {}",
                self.1.el_pk.len()
            )));
        }
        if self.1.pi_elpk.len() != 4 {
            res.push(VerifyKeyGenerationSchnorrProofsError::Domain(format!(
                "Size of pi_elpk must be 4. actual: {}",
                self.1.pi_elpk.len()
            )));
        }
        if self.1.pk_ccr[0].len() != self.0.psi_max {
            res.push(VerifyKeyGenerationSchnorrProofsError::Domain(format!(
                "Size of pk_ccr_0 must be phi_max={}. actual: {}",
                self.0.psi_max,
                self.1.pk_ccr[0].len()
            )));
        }
        if self.1.pi_pkccr[0].len() != self.0.psi_max {
            res.push(VerifyKeyGenerationSchnorrProofsError::Domain(format!(
                "Size of pi_pkccr_0 must be phi_max={}. actual: {}",
                self.0.psi_max,
                self.1.pi_pkccr[0].len()
            )));
        }
        if self.1.el_pk[0].len() != self.0.delta_max {
            res.push(VerifyKeyGenerationSchnorrProofsError::Domain(format!(
                "Size of el_pk_0 must be delta_max={}. actual: {}",
                self.0.delta_max,
                self.1.el_pk[0].len()
            )));
        }
        if self.1.pi_elpk[0].len() != self.0.delta_max {
            res.push(VerifyKeyGenerationSchnorrProofsError::Domain(format!(
                "Size of pi_elpk_0 must be delta_max={}. actual: {}",
                self.0.delta_max,
                self.1.pi_elpk[0].len()
            )));
        }
        if self.1.eb_pk.len() != self.0.delta_max {
            res.push(VerifyKeyGenerationSchnorrProofsError::Domain(format!(
                "Size of eb_pk must be delta_max={}. actual: {}",
                self.0.delta_max,
                self.1.eb_pk.len()
            )));
        }
        if self.1.pi_eb.len() != self.0.delta_max {
            res.push(VerifyKeyGenerationSchnorrProofsError::Domain(format!(
                "Size of pi_eb must be delta_max={}. actual: {}",
                self.0.delta_max,
                self.1.pi_eb.len()
            )));
        }
        res
    }
}

impl VerifyKeyGenerationSchnorrProofsOuput {
    /// Algorithm VerifyKeyGenerationSchnorrProofs (3.22)
    pub fn verify_key_generation_schnorr_proofs(
        context: &GetHashElectionEventContextContext,
        input: &VerifyKeyGenerationSchnorrProofsInput,
    ) -> Self {
        // Verifiy domain
        let verif_domain = (context, input).verifiy_domain();
        if !verif_domain.is_empty() {
            return Self::new_with_errors(verif_domain);
        }

        // Calculate h_context
        let h_context = match get_hash_election_event_context(context) {
            Ok(c) => c,
            Err(e) => return Self::new_with_error(VerifyKeyGenerationSchnorrProofsError::from(e)),
        };

        let mut errors = vec![];

        let (
            (verif_schnorr_ccr, mut errors_ccr),
            ((verif_schnorr_ccm, mut errors_ccm), (verif_schnorr_eb, mut errors_eb)),
        ) = rayon::join(
            || {
                verify_cc_schnorr_proofs(
                    &VerifyCCSchnorrProofsContext {
                        ep: context.encryption_parameters,
                        upper_n_upper_v: input.pk_ccr.len(),
                        upper_n_pk: input.pk_ccr[0].len(),
                    },
                    &VerifyCCSchnorrProofsInput {
                        pk_cc: input.pk_ccr,
                        pi_pkcc: input.pi_pkccr,
                        i_aux: &[context.ee.to_string(), "GenKeysCCR".to_string()],
                    },
                )
            },
            || {
                rayon::join(
                    || {
                        verify_cc_schnorr_proofs(
                            &VerifyCCSchnorrProofsContext {
                                ep: context.encryption_parameters,
                                upper_n_upper_v: input.el_pk.len(),
                                upper_n_pk: input.el_pk[0].len(),
                            },
                            &VerifyCCSchnorrProofsInput {
                                pk_cc: input.el_pk,
                                pi_pkcc: input.pi_elpk,
                                i_aux: &[h_context.clone(), "SetupTallyCCM".to_string()],
                            },
                        )
                    },
                    || {
                        verify_cc_schnorr_proofs(
                            &VerifyCCSchnorrProofsContext {
                                ep: context.encryption_parameters,
                                upper_n_upper_v: 1,
                                upper_n_pk: input.eb_pk.len(),
                            },
                            &VerifyCCSchnorrProofsInput {
                                pk_cc: &[input.eb_pk.to_vec()],
                                pi_pkcc: &[input.pi_eb.to_vec()],
                                i_aux: &[h_context.clone(), "SetupTallyEB".to_string()],
                            },
                        )
                    },
                )
            },
        );

        errors.append(&mut errors_ccr);
        errors.append(&mut errors_ccm);
        errors.append(&mut errors_eb);
        Self {
            verif_schnorr_ccr,
            verif_schnorr_ccm,
            verif_schnorr_eb,
            errors,
        }
    }
}

#[derive(Debug)]
pub struct VerifyCCSchnorrProofsContext<'a> {
    ep: &'a EncryptionParameters,
    upper_n_upper_v: usize,
    upper_n_pk: usize,
}

#[derive(Debug)]
pub struct VerifyCCSchnorrProofsInput<'a> {
    pk_cc: &'a [Vec<&'a Integer>],
    pi_pkcc: &'a [Vec<(&'a Integer, &'a Integer)>],
    i_aux: &'a [String],
}

impl VerifyDomainTrait<VerifyKeyGenerationSchnorrProofsError>
    for (
        &VerifyCCSchnorrProofsContext<'_>,
        &VerifyCCSchnorrProofsInput<'_>,
    )
{
    fn verifiy_domain(&self) -> Vec<VerifyKeyGenerationSchnorrProofsError> {
        let mut res = vec![];
        if self.1.pk_cc.len() != self.0.upper_n_upper_v {
            res.push(VerifyKeyGenerationSchnorrProofsError::Domain(format!(
                "Size of pk_cc must be {}. actual: {}",
                self.0.upper_n_upper_v,
                self.1.pk_cc.len()
            )));
        }
        if self.1.pi_pkcc.len() != self.0.upper_n_upper_v {
            res.push(VerifyKeyGenerationSchnorrProofsError::Domain(format!(
                "Size of pi_pkcc must be {}. actual: {}",
                self.0.upper_n_upper_v,
                self.1.pi_pkcc.len()
            )));
        }
        res.append(
            &mut self
                .1
                .pk_cc
                .iter()
                .enumerate()
                .map(|(j, pk_cc_j)| {
                    if pk_cc_j.len() != self.0.upper_n_pk {
                        return format!(
                            "Size of pk_cc_j for j={} must be {}. Acutal {}",
                            j,
                            self.0.upper_n_pk,
                            pk_cc_j.len()
                        );
                    }
                    String::new()
                })
                .filter(|s| !s.is_empty())
                .map(VerifyKeyGenerationSchnorrProofsError::Domain)
                .collect::<Vec<_>>(),
        );
        res.append(
            &mut self
                .1
                .pi_pkcc
                .iter()
                .enumerate()
                .map(|(j, pi_pkcc_j)| {
                    if pi_pkcc_j.len() != self.0.upper_n_pk {
                        return format!(
                            "Size of pi_pkcc_j for j={} must be {}. Acutal {}",
                            j,
                            self.0.upper_n_pk,
                            pi_pkcc_j.len()
                        );
                    }
                    String::new()
                })
                .filter(|s| !s.is_empty())
                .map(VerifyKeyGenerationSchnorrProofsError::Domain)
                .collect::<Vec<_>>(),
        );
        res
    }
}

#[instrument(level = "trace")]
fn verify_cc_schnorr_proofs(
    context: &VerifyCCSchnorrProofsContext,
    input: &VerifyCCSchnorrProofsInput,
) -> (Vec<String>, Vec<VerifyKeyGenerationSchnorrProofsError>) {
    let mut result = vec![];
    let mut errors = (context, input).verifiy_domain();
    if !errors.is_empty() {
        return (result, errors);
    }
    for j in 1..(context.upper_n_upper_v + 1) {
        let mut i_aux_j = input.i_aux.to_vec();
        i_aux_j.push(j.to_string());
        let res_proofs = input.pk_cc[j - 1]
            .iter()
            .zip(input.pi_pkcc[j - 1].iter())
            .enumerate()
            .map(|(i, (pk_cc_j_i, pi_pkcc_j_i))| {
                match verify_schnorr(context.ep, *pi_pkcc_j_i, pk_cc_j_i, &i_aux_j) {
                    Ok(b) => match b {
                        true => Ok(String::new()),
                        false => Ok(format!("Schnorr proof not ok for j={j}, i={i}")),
                    },
                    Err(e) => Err(VerifyKeyGenerationSchnorrProofsError::SchorrProof(format!(
                        "j={j}, i={i}: {e}",
                    ))),
                }
            })
            .collect::<Vec<_>>();
        result.append(
            &mut res_proofs
                .iter()
                .filter_map(|r| r.as_ref().ok())
                .filter(|s| !s.is_empty())
                .cloned()
                .collect::<Vec<_>>(),
        );
        errors.append(
            &mut res_proofs
                .into_iter()
                .filter(|r| r.is_err())
                .map(|r| r.unwrap_err())
                .collect::<Vec<_>>(),
        );
    }
    (result, errors)
}
