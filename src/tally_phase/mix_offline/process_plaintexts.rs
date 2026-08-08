// Copyright © 2023 Denis Morel

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

use std::collections::HashSet;

use super::MixOfflineError;
use crate::{
    preliminaries::{EPPTableAsContext, PTable, PTableTrait, decode_write_ins, factorize, indices},
    tally_phase::mix_offline::MixOfflineErrorRepr,
};
use rust_ev_crypto_primitives::{ConstantsTrait, Integer, elgamal::EncryptionParameters};

/// Context structure of ProcessPlaintexts according to the specifications
pub struct ProcessPlaintextsContext<'a> {
    pub encryption_parameters: &'a EncryptionParameters,
    pub p_table: &'a PTable,
    pub psis: &'a [usize],
    pub pgs: &'a [usize],
}

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
    pub fn process_plaintexts<'a>(
        context: &ProcessPlaintextsContext<'a>,
        plaintext_votes: &[&[Integer]],
    ) -> Result<Self, MixOfflineError> {
        Self::process_plaintexts_impl(context, plaintext_votes).map_err(MixOfflineError)
    }

    fn process_plaintexts_impl<'a>(
        context: &ProcessPlaintextsContext<'a>,
        plaintext_votes: &[&[Integer]],
    ) -> Result<Self, MixOfflineErrorRepr> {
        let upper_n_hat_upper_c = plaintext_votes.len();
        if upper_n_hat_upper_c < 2 {
            return Err(MixOfflineErrorRepr::ProcessPlaintextsInput(format!(
                "N_C={upper_n_hat_upper_c} must be geater than 2"
            )));
        }
        let delta = plaintext_votes[0].len();
        if plaintext_votes.iter().any(|m_i| m_i.len() != delta) {
            return Err(MixOfflineErrorRepr::ProcessPlaintextsInput(
                "Not all vectors of plaintext_votes have the size of delta".to_string(),
            ));
        }
        let ones = vec![Integer::one().clone(); delta];
        let tau_hat = context
            .p_table
            .get_blank_correctness_information()
            .map_err(|e| {
                MixOfflineErrorRepr::ProcessPlaintextsProcess(format!(
                    "Electoral model error processing tau_hat: {e:?}",
                ))
            })?;
        let mut l_votes = vec![];
        let mut l_decoded_votes = vec![];
        let mut l_write_ins = vec![];
        for m_i in plaintext_votes.iter() {
            if m_i != &ones {
                let p_hat_k =
                    factorize(&EPPTableAsContext::from(context), &m_i[0]).map_err(|e| {
                        MixOfflineErrorRepr::ProcessPlaintextsProcess(format!(
                            "Electoral model error facorizing: {e:?}",
                        ))
                    })?;
                let v_hat_k = context
                    .p_table
                    .get_actual_voting_options(&p_hat_k)
                    .map_err(|e| {
                        MixOfflineErrorRepr::ProcessPlaintextsProcess(format!(
                            "Electoral model error getting actual voting options: {e:?}",
                        ))
                    })?
                    .iter()
                    .map(|&s| s.as_str())
                    .collect::<Vec<_>>();
                let tau_prime = context
                    .p_table
                    .get_correctness_information(v_hat_k.as_slice())
                    .map_err(|e| {
                        MixOfflineErrorRepr::ProcessPlaintextsProcess(format!(
                            "Electoral model error getting correctnes information: {e:?}",
                        ))
                    })?;
                if tau_prime != tau_hat {
                    return Err(MixOfflineErrorRepr::ProcessPlaintextsProcess(
                        "tau_prime is differant that tau_hat".to_string(),
                    ));
                }
                let w_k = m_i.iter().skip(1).collect::<Vec<_>>();
                let s_hat_k = decode_write_ins(
                    context.encryption_parameters,
                    context
                        .p_table
                        .get_write_in_encoded_voting_options()
                        .as_slice(),
                    context
                        .p_table
                        .get_psi()
                        .map_err(|e| MixOfflineErrorRepr::GetPsi { source: e })?,
                    context.p_table.get_delta(),
                    &p_hat_k,
                    &w_k,
                )
                .map_err(|e| {
                    MixOfflineErrorRepr::ProcessPlaintextsProcess(format!(
                        "Write-in error decoding the write-ins: {e:?}",
                    ))
                })?;
                let v_hat_k_prime = process_invalid_encoding(
                    &ProcessInvalidEncodingContext::from(context),
                    v_hat_k.as_slice(),
                )
                .map_err(|e| {
                    MixOfflineErrorRepr::ProcessInvalidEncodingProcess(format!(
                        "Error processing invalid encoding: {e:?}",
                    ))
                })?;
                l_votes.push(p_hat_k);
                l_decoded_votes.push(v_hat_k_prime);
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

impl<'a> From<&ProcessPlaintextsContext<'a>> for EPPTableAsContext<'a, 'a> {
    fn from(context: &ProcessPlaintextsContext<'a>) -> Self {
        EPPTableAsContext::new(context.encryption_parameters, context.p_table)
    }
}

/// Context structure of ProcessInvalidEncoding according to the specifications
struct ProcessInvalidEncodingContext<'a> {
    pub p_table: &'a PTable,
    pub psis: &'a [usize],
    pub pgs: &'a [usize],
}

fn process_invalid_encoding(
    context: &ProcessInvalidEncodingContext<'_>,
    v_k_hat: &[&str],
) -> Result<Vec<String>, MixOfflineError> {
    process_invalid_encoding_impl(context, v_k_hat).map_err(MixOfflineError)
}

fn process_invalid_encoding_impl(
    context: &ProcessInvalidEncodingContext<'_>,
    v_k_hat: &[&str],
) -> Result<Vec<String>, MixOfflineErrorRepr> {
    let mut v_k_hat_prime = v_k_hat.iter().map(|&s| s.to_string()).collect::<Vec<_>>();
    let v_b = context
        .p_table
        .get_blank_actual_voting_options()
        .map_err(|e| {
            MixOfflineErrorRepr::ProcessInvalidEncodingProcess(format!(
                "Electoral model error getting blank actual voting options: {e:?}",
            ))
        })?;
    for i in 0..context.eta() {
        let pg_idx = indices(i, context.pgs, context.psis);
        let v_a = context.p_table.get_abstention_actual_voting_options(i);
        let v_k_hat_i = v_k_hat
            .iter()
            .enumerate()
            .filter(|(j, _)| *j >= pg_idx.0 && *j < pg_idx.1)
            .map(|(_, v_k_hat_j)| *v_k_hat_j)
            .collect::<Vec<_>>();
        let v_a_set = HashSet::<_>::from_iter(v_a.iter().cloned());
        let v_k_hat_i_set = HashSet::<_>::from_iter(v_k_hat_i.iter().cloned());
        let upper_iota = v_k_hat_i_set.intersection(&v_a_set).collect::<HashSet<_>>();
        if !upper_iota.is_empty() || upper_iota.len() != v_a.len() {
            v_k_hat_prime
                .iter_mut()
                .take(pg_idx.0)
                .skip(pg_idx.0)
                .for_each(|v_k_hat_prime_j| {
                    if upper_iota.contains(&v_k_hat_prime_j.as_str()) {
                        *v_k_hat_prime_j = v_b[i].to_string();
                    }
                });
        }
    }
    Ok(v_k_hat_prime)
}

impl<'a> ProcessInvalidEncodingContext<'a> {
    fn eta(&self) -> usize {
        self.pgs.len()
    }
}

impl<'a> From<&ProcessPlaintextsContext<'a>> for ProcessInvalidEncodingContext<'a> {
    fn from(context: &ProcessPlaintextsContext<'a>) -> Self {
        ProcessInvalidEncodingContext {
            p_table: context.p_table,
            psis: context.psis,
            pgs: context.pgs,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        preliminaries::PTableElement,
        test_data::get_test_data_mix_offline,
        test_json_data::{
            json_array_value_to_array_integer_base64, json_array_value_to_array_string,
            json_array_value_to_array_usize, json_to_encryption_parameters_base64,
        },
    };
    use serde_json::Value;

    fn json_to_p_table_element(value: &Value) -> PTableElement {
        PTableElement {
            actual_voting_option: value["actualVotingOption"].as_str().unwrap().to_string(),
            encoded_voting_option: value["encodedVotingOption"].as_u64().unwrap() as usize,
            semantic_information: value["semanticInformation"].as_str().unwrap().to_string(),
            correctness_information: value["correctnessInformation"]
                .as_str()
                .unwrap()
                .to_string(),
        }
    }

    pub fn json_to_p_table(value: &Value) -> PTable {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(json_to_p_table_element)
            .collect()
    }

    fn json_to_plaintext_votes(value: &Value) -> Vec<Vec<Integer>> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|v| json_array_value_to_array_integer_base64(&v["message"]))
            .collect::<Vec<_>>()
    }

    #[test]
    fn test_process_plaintexts() {
        for tc in get_test_data_mix_offline("process-plaintexts.json")
            .as_array()
            .unwrap()
            .iter()
        {
            let description = tc["description"].as_str().unwrap();
            let context = &tc["context"];
            let ep = json_to_encryption_parameters_base64(&context["encryptionGroup"]);
            let p_table = json_to_p_table(&context["primesMappingTable"]["pTable"]);
            let psis = json_array_value_to_array_usize(&context["numberOfSelectionsVector"]);
            let pgs = json_array_value_to_array_usize(&context["presentationGroupsVector"]);
            let plaintext_votes = json_to_plaintext_votes(&tc["input"]["plaintextVotes"]);
            let context = ProcessPlaintextsContext {
                encryption_parameters: &ep,
                p_table: &p_table,
                psis: &psis,
                pgs: &pgs,
            };
            let expected_output = ProcessPlaintextsOutput {
                l_votes: tc["output"]["selectedEncodedVotingOptions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| json_array_value_to_array_usize(v))
                    .collect::<Vec<_>>(),
                l_decoded_votes: tc["output"]["selectedDecodedVotingOptions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| json_array_value_to_array_string(v))
                    .collect::<Vec<_>>(),
                l_write_ins: tc["output"]["selectedDecodedWriteInVotes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| json_array_value_to_array_string(v))
                    .collect::<Vec<_>>(),
            };
            let output = ProcessPlaintextsOutput::process_plaintexts(
                &context,
                &plaintext_votes
                    .iter()
                    .map(|v| v.as_slice())
                    .collect::<Vec<_>>(),
            )
            .expect(&format!("Error processing plaintexts: {}", description));
            assert_eq!(
                output.l_votes, expected_output.l_votes,
                "Error in l_votes: {}",
                description
            );
            assert_eq!(
                output.l_decoded_votes, expected_output.l_decoded_votes,
                "Error in l_decoded_votes: {}",
                description
            );
            assert_eq!(
                output.l_write_ins, expected_output.l_write_ins,
                "Error in l_write_ins: {}",
                description
            );
        }
    }
}
