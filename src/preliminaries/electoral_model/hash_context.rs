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

use super::{ElectoralModelError, PTable};
use rust_ev_crypto_primitives::{
    elgamal::EncryptionParameters, EncodeTrait, HashableMessage, Integer, RecursiveHashTrait,
};

/// Input structure of  GetHashContext according to the specifications
pub struct GetHashContextContext<'a> {
    pub encryption_parameters: &'a EncryptionParameters,
    pub ee: &'a str,
    pub vcs: &'a str,
    pub p_table: &'a PTable,
    pub el_pk: &'a [&'a Integer],
    pub pk_ccr: &'a [&'a Integer],
}

/// Algorithm 3.11
///
/// Error [ElectoralModelError] if something is going wrong
pub fn get_hash_context(context: &GetHashContextContext) -> Result<String, ElectoralModelError> {
    Ok(HashableMessage::from(context)
        .recursive_hash()
        .map_err(ElectoralModelError::HashError)?
        .base64_encode()
        .unwrap())
}

impl<'a> From<&'a GetHashContextContext<'a>> for HashableMessage<'a> {
    fn from(context: &'a GetHashContextContext) -> Self {
        let mut h = vec![
            HashableMessage::from("EncryptionParameters"),
            HashableMessage::from(context.encryption_parameters.p()),
            HashableMessage::from(context.encryption_parameters.q()),
            HashableMessage::from(context.encryption_parameters.g()),
            HashableMessage::from("ElectionEventContext"),
            HashableMessage::from(context.ee),
            HashableMessage::from(context.vcs),
        ];
        let mut extension = context
            .p_table
            .get_actual_voting_options(&[])
            .unwrap()
            .iter()
            .map(|e| HashableMessage::from(*e))
            .collect::<Vec<_>>();
        h.push(HashableMessage::from("ActualVotingOptions"));
        h.append(&mut extension);
        let mut extension = context
            .p_table
            .get_encoded_voting_options(&[])
            .unwrap()
            .iter()
            .map(|e| HashableMessage::from(*e))
            .collect::<Vec<_>>();
        h.push(HashableMessage::from("EncodedVotingOptions"));
        h.append(&mut extension);
        let mut extension = context
            .p_table
            .get_semantic_information()
            .iter()
            .map(|e| HashableMessage::from(*e))
            .collect::<Vec<_>>();
        h.push(HashableMessage::from("SemanticInformation"));
        h.append(&mut extension);
        let mut extension = context
            .p_table
            .get_correctness_information(&[])
            .unwrap()
            .iter()
            .map(|e| HashableMessage::from(*e))
            .collect::<Vec<_>>();
        h.push(HashableMessage::from("CorrectnessInformation"));
        h.append(&mut extension);
        let mut extension = context
            .el_pk
            .iter()
            .map(|&e| HashableMessage::from(e))
            .collect::<Vec<_>>();
        h.push(HashableMessage::from("ELpk"));
        h.append(&mut extension);
        let mut extension = context
            .pk_ccr
            .iter()
            .map(|&e| HashableMessage::from(e))
            .collect::<Vec<_>>();
        h.push(HashableMessage::from("pkCCR"));
        h.append(&mut extension);
        HashableMessage::from(h)
    }
}

#[cfg(test)]
mod test {
    use std::fs;

    use super::*;
    use crate::{
        preliminaries::PTableElement,
        test_data::get_test_data_path,
        test_json_data::{json_array_value_to_array_integer, json_value_to_integer_base16},
    };
    use serde_json::Value;

    pub fn get_hash_contexts() -> Vec<Value> {
        serde_json::from_str(
            &fs::read_to_string(get_test_data_path().join("get-hash-context.json")).unwrap(),
        )
        .unwrap()
    }

    fn json_to_p_table_element(value: &Value) -> PTableElement {
        PTableElement {
            actual_voting_option: value["v"].as_str().unwrap().to_string(),
            encoded_voting_option: value["pTilde"].as_u64().unwrap() as usize,
            semantic_information: value["sigma"].as_str().unwrap().to_string(),
            correctness_information: value["tau"].as_str().unwrap().to_string(),
        }
    }

    pub fn json_to_p_table(value: &Value) -> PTable {
        PTable(
            value
                .as_array()
                .unwrap()
                .iter()
                .map(json_to_p_table_element)
                .collect(),
        )
    }

    #[test]
    fn test_hash_context() {
        for test_case in get_hash_contexts() {
            let description = test_case["description"].as_str().unwrap();
            let output = test_case["output"].as_str().unwrap();
            let context = &test_case["context"];
            let ep = EncryptionParameters::from((
                &json_value_to_integer_base16(&context["p"]),
                &json_value_to_integer_base16(&context["q"]),
                &json_value_to_integer_base16(&context["g"]),
            ));
            let ee = context["ee"].as_str().unwrap();
            let vcs = context["vcs"].as_str().unwrap();
            let el_pk = json_array_value_to_array_integer(&context["ELpk"]);
            let pk_ccr = json_array_value_to_array_integer(&context["pkCCR"]);
            let p_table = json_to_p_table(&context["pTable"]);
            let hash_context_context = GetHashContextContext {
                encryption_parameters: &ep,
                ee,
                vcs,
                p_table: &p_table,
                el_pk: &el_pk.iter().collect::<Vec<_>>(),
                pk_ccr: &pk_ccr.iter().collect::<Vec<_>>(),
            };
            assert_eq!(
                get_hash_context(&hash_context_context).unwrap(),
                output,
                "{}",
                description
            )
        }
    }
}
