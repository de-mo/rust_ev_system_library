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

use super::MixOfflineError;
use crate::preliminaries::{decode_write_ins, factorize, EPPTableAsContext, PTableTrait};
use rust_ev_crypto_primitives::{ConstantsTrait, Integer};

/// Output structure of ProcessPlaintexts according to the specifications
pub struct ProcessPlaintextsOutput {
    /// L_votes: List of all selected encoded voting options
    pub l_votes: Vec<Vec<usize>>,
    /// L_decodedVotes: List of all selected decoded voting options
    pub l_decoded_votes: Vec<Vec<String>>,
    /// L_writeIns: List of all selected decoded write-in votes
    pub l_write_ins: Vec<Vec<String>>,
}

impl ProcessPlaintextsOutput {
    /// Algorithm 6.9
    pub fn process_plaintexts(
        context: &EPPTableAsContext,
        plaintext_votes: &[&[Integer]],
    ) -> Result<Self, MixOfflineError> {
        let upper_n_hat_upper_c = plaintext_votes.len();
        if upper_n_hat_upper_c < 2 {
            return Err(MixOfflineError::ProcessPlaintextsInput(format!(
                "N_C={upper_n_hat_upper_c} must be geater than 2"
            )));
        }
        let delta = plaintext_votes[0].len();
        if plaintext_votes.iter().any(|m_i| m_i.len() != delta) {
            return Err(MixOfflineError::ProcessPlaintextsInput(
                "Not all vectors of plaintext_votes have the size of delta".to_string(),
            ));
        }
        let ones = vec![Integer::one().clone(); delta];
        let tau_hat = context
            .p_table()
            .get_blank_correctness_information()
            .map_err(|e| {
                MixOfflineError::ProcessPlaintextsProcess(format!(
                    "Electoral model error processing tau_hat: {:?}",
                    e
                ))
            })?;
        let mut l_votes = vec![];
        let mut l_decoded_votes = vec![];
        let mut l_write_ins = vec![];
        for m_i in plaintext_votes.iter() {
            if m_i != &ones {
                let p_hat_k = factorize(context, &m_i[0]).map_err(|e| {
                    MixOfflineError::ProcessPlaintextsProcess(format!(
                        "Electoral model error facorizing: {:?}",
                        e
                    ))
                })?;
                let v_hat_k = context
                    .p_table()
                    .get_actual_voting_options(&p_hat_k)
                    .map_err(|e| {
                        MixOfflineError::ProcessPlaintextsProcess(format!(
                            "Electoral model error getting actual voting options: {:?}",
                            e
                        ))
                    })?
                    .iter()
                    .map(|&s| s.clone())
                    .collect::<Vec<_>>();
                let tau_prime = context
                    .p_table()
                    .get_correctness_information(
                        v_hat_k
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .as_slice(),
                    )
                    .map_err(|e| {
                        MixOfflineError::ProcessPlaintextsProcess(format!(
                            "Electoral model error getting correctnes information: {:?}",
                            e
                        ))
                    })?;
                if tau_prime != tau_hat {
                    return Err(MixOfflineError::ProcessPlaintextsProcess(
                        "tau_prime is differant that tau_hat".to_string(),
                    ));
                }
                let w_k = m_i.iter().skip(1).cloned().collect::<Vec<_>>();
                let s_hat_k = decode_write_ins(
                    context.encryption_parameters(),
                    context
                        .p_table()
                        .get_write_in_encoded_voting_options()
                        .as_slice(),
                    context
                        .p_table()
                        .get_psi()
                        .map_err(|e| MixOfflineError::GetPsi { source: e })?,
                    context.p_table().get_delta(),
                    &p_hat_k,
                    &w_k,
                )
                .map_err(|e| {
                    MixOfflineError::ProcessPlaintextsProcess(format!(
                        "Write-in error decoding the write-ins: {:?}",
                        e
                    ))
                })?;
                l_votes.push(p_hat_k);
                l_decoded_votes.push(v_hat_k);
                l_write_ins.push(s_hat_k);
            }
        }
        Ok(Self {
            l_votes,
            l_decoded_votes,
            l_write_ins,
        })
    }
}
