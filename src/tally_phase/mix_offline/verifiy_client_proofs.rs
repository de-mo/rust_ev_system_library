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

use std::collections::HashSet;

use crate::preliminaries::{get_hash_context, GetHashContextContext, PTable};
use rust_ev_crypto_primitives::{
    elgamal::EncryptionParameters,
    zero_knowledge_proofs::{verify_exponentiation, verify_plaintext_equality},
    ConstantsTrait, Integer, OperationsTrait, VerifyDomainTrait,
};

use super::MixOfflineError;

pub struct VerifyVotingClientProofsContext<'a, 'b, 'c, 'd, 'e, 'f> {
    encryption_parameters: &'a EncryptionParameters,
    ee: &'b str,
    vcs: &'c str,
    p_table: &'d PTable,
    upper_n_upper_e: usize,
    el_pk: &'e [Integer],
    pk_ccr: &'f [Integer],
}

pub struct VerifyVotingClientProofsInput<'g, 'h, 'i, 'j, 'k, 'l, 'm> {
    vc_1: &'g [String],
    e1_1: &'h [Vec<Integer>],
    e1_tilde_1: &'i [(Integer, Integer)],
    e2_1: &'j [Vec<Integer>],
    pi_exp_1: &'k [(Integer, Integer)],
    pi_eq_enc_1: &'l [(Integer, (Integer, Integer))],
    k_map: &'m [(String, Integer)],
}

impl<'a, 'b, 'c, 'd, 'e, 'f, 'g, 'h, 'i, 'j, 'k, 'l, 'm> VerifyDomainTrait<MixOfflineError>
    for (
        &VerifyVotingClientProofsContext<'a, 'b, 'c, 'd, 'e, 'f>,
        &VerifyVotingClientProofsInput<'g, 'h, 'i, 'j, 'k, 'l, 'm>,
    )
{
    fn verifiy_domain(&self) -> Vec<MixOfflineError> {
        let mut res = vec![];
        let upper_n_c = self.1.vc_1.len();
        if upper_n_c == 0 {
            res.push(MixOfflineError::ProcessPlaintextsInput(
                "N_c must be greater or equal 1".to_string(),
            ));
        }
        if upper_n_c > self.0.upper_n_upper_e {
            res.push(MixOfflineError::ProcessPlaintextsInput(
                "N_c must be smaller or equal N_E".to_string(),
            ));
        }
        if self.1.e1_1.len() != upper_n_c {
            res.push(MixOfflineError::ProcessPlaintextsInput(
                "E1_1 has wrong length".to_string(),
            ));
        }
        if self.1.e1_tilde_1.len() != upper_n_c {
            res.push(MixOfflineError::ProcessPlaintextsInput(
                "e1_tilde_1 has wrong length".to_string(),
            ));
        }
        if self.1.e2_1.len() != upper_n_c {
            res.push(MixOfflineError::ProcessPlaintextsInput(
                "e2_1 has wrong length".to_string(),
            ));
        }
        if self.1.pi_exp_1.len() != upper_n_c {
            res.push(MixOfflineError::ProcessPlaintextsInput(
                "pi_exp_1 has wrong length".to_string(),
            ));
        }
        if self.1.pi_eq_enc_1.len() != upper_n_c {
            res.push(MixOfflineError::ProcessPlaintextsInput(
                "pi_eq_enc_1 has wrong length".to_string(),
            ));
        }
        if self.1.k_map.len() != self.0.upper_n_upper_e {
            res.push(MixOfflineError::ProcessPlaintextsInput(
                "k_map has wrong length".to_string(),
            ));
        }
        match self.0.p_table.get_psi() {
            Err(e) => res.push(MixOfflineError::VerifyVotingClientProofsInput(format!(
                "Error calculating psi: {}",
                e
            ))),
            Ok(psi) => {
                for (i, e1_1_i) in self.1.e1_1.iter().enumerate() {
                    if e1_1_i.len() != psi + 1 {
                        res.push(MixOfflineError::ProcessPlaintextsInput(format!(
                            "Inner vector of E1_1 is not of length psi+1 at position {}",
                            i
                        )));
                    }
                }
            }
        }
        if self.1.vc_1.len() != self.1.vc_1.iter().collect::<HashSet<_>>().len() {
            res.push(MixOfflineError::ProcessPlaintextsInput(
                "Confirmed verification card vc_1 are not distinct".to_string(),
            ));
        }
        res
    }
}

pub fn verify_voting_client_proofs(
    context: &VerifyVotingClientProofsContext,
    input: &VerifyVotingClientProofsInput,
) -> Result<Vec<String>, MixOfflineError> {
    let mut res = vec![];
    let verif_domain = (context, input).verifiy_domain();
    if !verif_domain.is_empty() {
        return Err(verif_domain[0].clone());
    }
    let p_tilde_ccr = context
        .pk_ccr
        .iter()
        .fold(Integer::one().clone(), |acc, pk_ccr_i| {
            acc.mod_multiply(pk_ccr_i, context.encryption_parameters.p())
        });
    for (i, vc_1_i) in input.vc_1.iter().enumerate() {
        let upper_k_id = input
            .k_map
            .iter()
            .find(|(vc_i, _)| vc_i == vc_1_i)
            .map(|(_, k_i)| k_i)
            .ok_or(MixOfflineError::ProcessPlaintextsProcess(format!(
                "Entry of KMAP for vc1[{}]={} not found",
                i, vc_1_i
            )))?;
        let gamma_1 = input.e1_1[i][0].clone();
        let phi_1_0 = input.e1_1[i][1].clone();
        let gamma_1_k_id = input.e1_tilde_1[i].0.clone();
        let phi_1_0_k_id = input.e1_tilde_1[i].1.clone();
        let e2_tilde_i = (
            input.e2_1[i][0].clone(),
            input.e2_1[i]
                .iter()
                .skip(1)
                .fold(Integer::one().clone(), |acc, phi_2_k| {
                    acc.mod_multiply(phi_2_k, context.encryption_parameters.p())
                }),
        );
        let mut i_aux = vec![
            "CreateVote".to_string(),
            vc_1_i.to_string(),
            get_hash_context(&GetHashContextContext::from(context)).map_err(|e| {
                MixOfflineError::ProcessPlaintextsProcess(format!(
                    "Error in get_hash_context: {}",
                    e
                ))
            })?,
        ];
        let mut i_aux_extension = input.e1_1[i]
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>();
        i_aux.append(&mut i_aux_extension);
        let mut i_aux_extension: Vec<String> = input.e2_1[i]
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>();
        i_aux.append(&mut i_aux_extension);
        if !verify_exponentiation(
            context.encryption_parameters,
            &vec![context.encryption_parameters.g().clone(), gamma_1, phi_1_0],
            &vec![upper_k_id.clone(), gamma_1_k_id, phi_1_0_k_id],
            (&input.pi_exp_1[i].0, &input.pi_exp_1[i].1),
            &i_aux,
        )
        .map_err(|e| {
            MixOfflineError::ProcessPlaintextsProcess(format!(
                "Error in verify_exponentiation: {}",
                e
            ))
        })? {
            res.push(format!("VerifExp_i for {i} not successful"));
        }
        if !verify_plaintext_equality(
            context.encryption_parameters,
            (&input.e1_tilde_1[i].0, &input.e1_tilde_1[i].1),
            (&e2_tilde_i.0, &e2_tilde_i.1),
            &context.el_pk[0],
            &p_tilde_ccr,
            (
                &input.pi_eq_enc_1[i].0,
                (&input.pi_eq_enc_1[i].1 .0, &input.pi_eq_enc_1[i].1 .1),
            ),
            &i_aux,
        )
        .map_err(|e| {
            MixOfflineError::ProcessPlaintextsProcess(format!(
                "Error in verify_plaintext_equality: {}",
                e
            ))
        })? {
            res.push(format!("VerifEqEn_I for {i} not successful"));
        }
    }
    Ok(res)
}

impl<'a, 'b, 'c, 'd, 'e, 'f> From<&VerifyVotingClientProofsContext<'a, 'b, 'c, 'd, 'e, 'f>>
    for GetHashContextContext<'a, 'b, 'c, 'd, 'e, 'f>
{
    fn from(value: &VerifyVotingClientProofsContext<'a, 'b, 'c, 'd, 'e, 'f>) -> Self {
        GetHashContextContext {
            encryption_parameters: value.encryption_parameters,
            ee: value.ee,
            vcs: value.vcs,
            p_table: value.p_table,
            el_pk: value.el_pk,
            pk_ccr: value.pk_ccr,
        }
    }
}
