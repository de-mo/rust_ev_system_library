// Copyright © 2023 Denis Morel

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU Lesser General Public License and
// a copy of the GNU General Public License along with this program. If not, see
// <https://www.gnu.org/licenses/>.

use rust_ev_crypto_primitives::{
    elgamal::{combine_public_keys, verify_decryptions, Ciphertext, EncryptionParameters},
    mix_net::{verify_shuffle, MixNetResultTrait, ShuffleArgument},
    Integer, VerifyDomainTrait,
};

use super::MixOfflineError;

/// Context structure of VerifyMixDecOffline according to the specifications
pub struct VerifyMixDecOfflineContext<'a> {
    pub encryption_parameters: &'a EncryptionParameters,
    pub ee: &'a str,
    pub bb: &'a str,
    pub delta: usize,
    pub el_pk: &'a [Integer],
    pub ccm_el_pk: &'a [&'a [Integer]],
    pub eb_pk: &'a [Integer],
}

/// Input structure of VerifyMixDecOffline according to the specifications
pub struct VerifyMixDecOfflineInput<'a> {
    pub c_init_1: &'a [Ciphertext],
    pub c_mix: &'a [&'a [Ciphertext]],
    pub pi_mix: &'a [ShuffleArgument<'a>],
    pub c_dec: &'a [&'a [Ciphertext]],
    pub pi_dec: &'a [Vec<(&'a Integer, &'a [Integer])>],
}

/// Output structure of VerifyVotingClientProof according to the specifications
pub struct VerifyMixDecOfflineOutput {
    pub shuffle_verif: Vec<String>,
    pub decrypt_verif: Vec<String>,
    pub errors: Vec<MixOfflineError>,
}

impl VerifyMixDecOfflineOutput {
    pub fn errors(&self) -> &[MixOfflineError] {
        &self.errors
    }

    pub fn failures(&self) -> Vec<String> {
        let mut res = self.shuffle_verif.clone();
        res.extend(self.decrypt_verif.iter().cloned());
        res
    }
}

impl<'a, 'b> VerifyDomainTrait<MixOfflineError>
    for (
        &VerifyMixDecOfflineContext<'a>,
        &VerifyMixDecOfflineInput<'b>,
    )
{
    fn verifiy_domain(&self) -> Vec<MixOfflineError> {
        let mut res = vec![];
        let context = self.0;
        let input = self.1;
        let hat_upper_n_c = input.c_init_1.len();
        if hat_upper_n_c < 2 {
            res.push(MixOfflineError::VerifyMixDecOfflineInput(
                "N_c must be greater or equal 2".to_string(),
            ));
        }
        res.extend(
            input
                .c_init_1
                .iter()
                .enumerate()
                .filter_map(|(j, c_init_j)| match c_init_j.l() == context.delta {
                    true => None,
                    false => Some(MixOfflineError::VerifyMixDecOfflineInput(format!(
                        "c_init_{} has not size of delta (={})",
                        j, context.delta
                    ))),
                }),
        );
        if input.c_mix.len() != 4 {
            res.push(MixOfflineError::VerifyMixDecOfflineInput(
                "c_mix must have a size of 4".to_string(),
            ));
        }
        res.extend(input.c_mix.iter().enumerate().flat_map(|(j, c_mix_j)| {
            let mut inner_res = vec![];
            if c_mix_j.len() != hat_upper_n_c {
                inner_res.push(MixOfflineError::VerifyMixDecOfflineInput(format!(
                    "c_mix_{} must have a size of N_c",
                    j
                )));
            };
            inner_res.extend(c_mix_j.iter().enumerate().filter_map(|(i, c_mix_j_i)| {
                match c_mix_j_i.l() == context.delta {
                    true => None,
                    false => Some(MixOfflineError::VerifyMixDecOfflineInput(format!(
                        "c_mix_{}_{} has not size of delta (={})",
                        j, i, context.delta
                    ))),
                }
            }));
            inner_res
        }));
        if input.pi_mix.len() != 4 {
            res.push(MixOfflineError::VerifyMixDecOfflineInput(
                "pi_mix must have a size of 4".to_string(),
            ));
        }
        if input.c_dec.len() != 4 {
            res.push(MixOfflineError::VerifyMixDecOfflineInput(
                "c_dec must have a size of 4".to_string(),
            ));
        }
        res.extend(input.c_dec.iter().enumerate().flat_map(|(j, c_dec_j)| {
            let mut inner_res = vec![];
            if c_dec_j.len() != hat_upper_n_c {
                inner_res.push(MixOfflineError::VerifyMixDecOfflineInput(format!(
                    "c_dec_{} must have a size of N_c",
                    j
                )));
            };
            inner_res.extend(c_dec_j.iter().enumerate().filter_map(|(i, c_dec_j_i)| {
                match c_dec_j_i.l() == context.delta {
                    true => None,
                    false => Some(MixOfflineError::VerifyMixDecOfflineInput(format!(
                        "c_dec_{}_{} has not size of delta (={})",
                        j, i, context.delta
                    ))),
                }
            }));
            inner_res
        }));
        if input.pi_dec.len() != 4 {
            res.push(MixOfflineError::VerifyMixDecOfflineInput(
                "pi_dec must have a size of 4".to_string(),
            ));
        }
        res.extend(input.pi_dec.iter().enumerate().flat_map(|(j, pi_dec_j)| {
            let mut inner_res = vec![];
            if pi_dec_j.len() != hat_upper_n_c {
                inner_res.push(MixOfflineError::VerifyMixDecOfflineInput(format!(
                    "pi_dec_{} must have a size of N_c",
                    j
                )));
            };
            inner_res.extend(pi_dec_j.iter().enumerate().filter_map(|(i, pi_dec_j_i)| {
                match pi_dec_j_i.1.len() == context.delta {
                    true => None,
                    false => Some(MixOfflineError::VerifyMixDecOfflineInput(format!(
                        "pi_dec_{}_{} has not size of delta + 1  (={})",
                        j,
                        i,
                        context.delta + 1
                    ))),
                }
            }));
            inner_res
        }));
        res
    }
}

impl VerifyMixDecOfflineOutput {
    /// Algorithm 6.7
    pub fn verify_mix_dec_offline(
        context: &VerifyMixDecOfflineContext,
        input: &VerifyMixDecOfflineInput,
    ) -> Self {
        let mut errors = (context, input).verifiy_domain();
        if !errors.is_empty() {
            return Self {
                shuffle_verif: vec![],
                decrypt_verif: vec![],
                errors,
            };
        }
        let mut shuffle_verif = vec![];
        let mut decrypt_verif = vec![];

        match verify_shuffle(
            context.encryption_parameters,
            input.c_init_1,
            input.c_mix[0],
            &input.pi_mix[0],
            context.el_pk,
        ) {
            Ok(res) => {
                if !res.is_ok() {
                    shuffle_verif.push(format!("VerifiyShuffle 1 not successful: {}", res))
                }
            }
            Err(e) => errors.push(MixOfflineError::VerifyMixDecOfflineProcess(format!(
                "VerifiyShuffle 1: {}",
                e
            ))),
        }

        let i_aux = [
            context.ee.to_string(),
            context.bb.to_string(),
            "MixDecOnline".to_string(),
            "1".to_string(),
        ];
        match verify_decryptions(
            context.encryption_parameters,
            input.c_mix[0],
            context.ccm_el_pk[0],
            input.c_dec[0],
            input.pi_dec[0].as_slice(),
            &i_aux,
        ) {
            Ok(res) => {
                if !res.is_ok() {
                    decrypt_verif.push(format!("VerifyDecryptions 1 not successful: {}", res))
                }
            }
            Err(e) => errors.push(MixOfflineError::VerifyMixDecOfflineProcess(format!(
                "VerifyDecryptions 1: {}",
                e
            ))),
        }

        (1..4).for_each(|j| {
            let mut combined_vec = context
                .ccm_el_pk
                .iter()
                .skip(j)
                .map(|v| v.to_vec())
                .collect::<Vec<_>>();
            combined_vec.push(context.eb_pk.to_vec());

            match combine_public_keys(context.encryption_parameters.p(), &combined_vec) {
                Ok(combined_el_pk) => {
                    match verify_shuffle(
                        context.encryption_parameters,
                        input.c_dec[j - 1],
                        input.c_mix[j],
                        &input.pi_mix[j],
                        &combined_el_pk,
                    ) {
                        Ok(res) => {
                            if !res.is_ok() {
                                shuffle_verif.push(format!(
                                    "VerifiyShuffle {} not successful: {}",
                                    j + 1,
                                    res
                                ))
                            }
                        }
                        Err(e) => errors.push(MixOfflineError::VerifyMixDecOfflineProcess(
                            format!("VerifiyShuffle {}: {}", j + 1, e),
                        )),
                    }
                }
                Err(e) => errors.push(MixOfflineError::VerifyMixDecOfflineProcess(format!(
                    "VerifiyShuffle {}: Error calculating combined el_pk {}",
                    j + 1,
                    e
                ))),
            }

            let i_aux = [
                context.ee.to_string(),
                context.bb.to_string(),
                "MixDecOnline".to_string(),
                (j + 1).to_string(),
            ];
            match verify_decryptions(
                context.encryption_parameters,
                input.c_mix[j],
                context.ccm_el_pk[j],
                input.c_dec[j],
                &input.pi_dec[j],
                &i_aux,
            ) {
                Ok(res) => {
                    if !res.is_ok() {
                        decrypt_verif.push(format!(
                            "VerifyDecryptions {} not successful: {}",
                            j + 1,
                            res
                        ))
                    }
                }
                Err(e) => errors.push(MixOfflineError::VerifyMixDecOfflineProcess(format!(
                    "VerifyDecryptions {}: {}",
                    j + 1,
                    e
                ))),
            }
        });
        Self {
            shuffle_verif,
            decrypt_verif,
            errors,
        }
    }
}
