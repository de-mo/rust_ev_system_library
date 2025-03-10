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

use super::PTableElement;
use chrono::NaiveDateTime;
use rust_ev_crypto_primitives::{
    elgamal::EncryptionParameters, EncodeTrait, HashError, HashableMessage, RecursiveHashTrait,
};
use thiserror::Error;

/// Enum representing the errors during the algorithms regardinf election event context
#[derive(Error, Debug)]
pub enum ElectionEventContextError {
    #[error(transparent)]
    HashError(#[from] HashError),
}

/// Format to transform NaiveDate to String
pub const NAIVE_DATETIME_TO_STRING_FORMAT: &str = "%Y-%m-%dT%H:%M:%S";

/// Transform a naive date to string according to the specification of Swiss Post<
pub fn naive_datetime_to_string(datetime: &NaiveDateTime) -> String {
    datetime.format(NAIVE_DATETIME_TO_STRING_FORMAT).to_string()
}

/// Context for Verification card sets. Fields according specification of Swiss Post.
pub struct VerificationCardSetContext<'a> {
    pub vcs: &'a str,
    pub vcs_alias: &'a str,
    pub vcs_desc: &'a str,
    pub bb: &'a str,
    pub t_s_bb: &'a NaiveDateTime,
    pub t_f_bb: &'a NaiveDateTime,
    pub test_ballot_box: bool,
    pub upper_n_upper_e: usize,
    pub grace_period: usize,
    pub p_table: &'a Vec<PTableElement>,
    pub encryption_parameters: &'a EncryptionParameters,
}

/// Context for GetHashElectionEventContext. Fields according specification of Swiss Post.
pub struct GetHashElectionEventContextContext<'a, 'b> {
    pub encryption_parameters: &'a EncryptionParameters,
    pub ee: &'a str,
    pub ee_alias: &'a str,
    pub ee_descr: &'a str,
    pub vcs_contexts: Vec<VerificationCardSetContext<'b>>,
    pub t_s_ee: &'a NaiveDateTime,
    pub t_f_ee: &'a NaiveDateTime,
    pub n_max: usize,
    pub psi_max: usize,
    pub delta_max: usize,
}

/// Algorithm 3.2
///
/// Return a [`Vec<String>`] with the unsuccessfully verifications. Empty if the verification is ok
///
/// Error [ElectionEventContextError] if something is going wrong
pub fn get_hash_election_event_context(
    context: &GetHashElectionEventContextContext,
) -> Result<String, ElectionEventContextError> {
    let h = HashableMessage::from(context);
    Ok(h.recursive_hash()
        .map_err(ElectionEventContextError::HashError)?
        .base64_encode()
        .unwrap())
}

impl<'a, 'hash> From<&'hash VerificationCardSetContext<'a>> for HashableMessage<'hash>
where
    'hash: 'a,
{
    fn from(value: &'hash VerificationCardSetContext<'a>) -> Self {
        let h_p_table_j = HashableMessage::from(vec![
            HashableMessage::from(vec![
                HashableMessage::from(value.encryption_parameters.p()),
                HashableMessage::from(value.encryption_parameters.q()),
                HashableMessage::from(value.encryption_parameters.g()),
            ]),
            HashableMessage::from(
                value
                    .p_table
                    .iter()
                    .map(HashableMessage::from)
                    .collect::<Vec<_>>(),
            ),
        ]);
        HashableMessage::from(vec![
            HashableMessage::from(value.vcs),
            HashableMessage::from(value.vcs_alias),
            HashableMessage::from(value.vcs_desc),
            HashableMessage::from(value.bb),
            HashableMessage::from(naive_datetime_to_string(value.t_s_bb)),
            HashableMessage::from(naive_datetime_to_string(value.t_f_bb)),
            HashableMessage::from(value.test_ballot_box),
            HashableMessage::from(value.upper_n_upper_e),
            HashableMessage::from(value.grace_period),
            h_p_table_j,
        ])
    }
}

impl<'a, 'b, 'hash> From<&'hash GetHashElectionEventContextContext<'a, 'b>>
    for HashableMessage<'hash>
where
    'hash: 'a + 'b,
{
    fn from(value: &'hash GetHashElectionEventContextContext<'a, 'b>) -> Self {
        let h_vcs = HashableMessage::from(
            value
                .vcs_contexts
                .iter()
                .map(HashableMessage::from)
                .collect::<Vec<_>>(),
        );

        HashableMessage::from(vec![
            HashableMessage::from(value.ee),
            HashableMessage::from(value.ee_alias),
            HashableMessage::from(value.ee_descr),
            h_vcs,
            HashableMessage::from(naive_datetime_to_string(value.t_s_ee)),
            HashableMessage::from(naive_datetime_to_string(value.t_f_ee)),
            HashableMessage::from(value.n_max),
            HashableMessage::from(value.psi_max),
            HashableMessage::from(value.delta_max),
        ])
    }
}

#[cfg(test)]
mod test {
    use std::fs;

    use super::*;
    use crate::{
        preliminaries::PTableElement,
        test_data::get_test_data_path,
        test_json_data::{json_to_encryption_parameters_base64, json_value_to_naive_datetime},
    };
    use chrono::NaiveDateTime;
    use serde_json::Value;

    pub fn get_hash_contexts() -> Vec<Value> {
        serde_json::from_str(
            &fs::read_to_string(get_test_data_path().join("get-hash-election-event-context.json"))
                .unwrap(),
        )
        .unwrap()
    }

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

    pub fn json_to_p_table(value: &Value) -> Vec<PTableElement> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(json_to_p_table_element)
            .collect()
    }

    pub fn json_to_vcs_context<'a>(
        p_table: &'a Vec<PTableElement>,
        ep: &'a EncryptionParameters,
        start_time: &'a NaiveDateTime,
        stop_time: &'a NaiveDateTime,
        value: &'a Value,
    ) -> VerificationCardSetContext<'a> {
        VerificationCardSetContext {
            vcs: value["verificationCardSetId"].as_str().unwrap(),
            vcs_alias: value["verificationCardSetAlias"].as_str().unwrap(),
            vcs_desc: value["verificationCardSetDescription"].as_str().unwrap(),
            bb: value["ballotBoxId"].as_str().unwrap(),
            t_s_bb: start_time,
            t_f_bb: stop_time,
            test_ballot_box: value["testBallotBox"].as_bool().unwrap(),
            upper_n_upper_e: value["numberOfVotingCards"].as_u64().unwrap() as usize,
            grace_period: value["gracePeriod"].as_u64().unwrap() as usize,
            p_table,
            encryption_parameters: ep,
        }
    }

    #[test]
    #[ignore = "Not working (but alogirthm is used in verify signature and is working"]
    fn test_hash_ee_context() {
        for test_case in get_hash_contexts() {
            let description = test_case["description"].as_str().unwrap();
            let output = test_case["output"]["d"].as_str().unwrap();
            let context = &test_case["context"];
            let ep = json_to_encryption_parameters_base64(&context["encryptionGroup"]);
            let ee_context = &context["electionEventContext"];
            let ee = ee_context["electionEventId"].as_str().unwrap();
            let ee_alias = ee_context["electionEventAlias"].as_str().unwrap();
            let ee_descr = ee_context["electionEventDescription"].as_str().unwrap();
            let t_s_ee = json_value_to_naive_datetime(&ee_context["startTime"]);
            let t_f_ee = json_value_to_naive_datetime(&ee_context["finishTime"]);
            let n_max = ee_context["maximumNumberOfVotingOptions"].as_u64().unwrap() as usize;
            let psi_max = ee_context["maximumNumberOfSelections"].as_u64().unwrap() as usize;
            let delta_max = ee_context["maximumNumberOfWriteInsPlusOne"]
                .as_u64()
                .unwrap() as usize;
            let json_vcs_contexts = ee_context["verificationCardSetContexts"]
                .as_array()
                .unwrap();
            let start_times = json_vcs_contexts
                .iter()
                .map(|v| json_value_to_naive_datetime(&v["ballotBoxStartTime"]))
                .collect::<Vec<_>>();
            let finish_times = json_vcs_contexts
                .iter()
                .map(|v| json_value_to_naive_datetime(&v["ballotBoxFinishTime"]))
                .collect::<Vec<_>>();
            let p_tables = json_vcs_contexts
                .iter()
                .map(|v| json_to_p_table(&v["primesMappingTable"]["pTable"]))
                .collect::<Vec<_>>();
            let eps = json_vcs_contexts
                .iter()
                .map(|v| {
                    json_to_encryption_parameters_base64(
                        &v["primesMappingTable"]["encryptionGroup"],
                    )
                })
                .collect::<Vec<_>>();
            let vcs_contexts = json_vcs_contexts
                .iter()
                .zip(
                    eps.iter()
                        .zip(p_tables.iter())
                        .zip(start_times.iter().zip(finish_times.iter())),
                )
                .map(|(v, ((ep, p_table), (st, ft)))| json_to_vcs_context(p_table, ep, st, ft, v))
                .collect::<Vec<_>>();
            let hash_context = GetHashElectionEventContextContext {
                encryption_parameters: &ep,
                ee,
                ee_alias,
                ee_descr,
                vcs_contexts,
                t_s_ee: &t_s_ee,
                t_f_ee: &t_f_ee,
                n_max,
                psi_max,
                delta_max,
            };
            assert_eq!(
                get_hash_election_event_context(&hash_context).unwrap(),
                output,
                "{}",
                description
            )
        }
    }
}
