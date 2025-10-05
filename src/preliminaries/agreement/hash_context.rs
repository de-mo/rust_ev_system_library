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

use super::{AgreementError, AgreementErrorRepr};
use crate::preliminaries::{PTable, PTableTrait};
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
pub fn get_hash_context(context: &GetHashContextContext) -> Result<String, AgreementError> {
    Ok(HashableMessage::from(context)
        .recursive_hash()
        .map_err(|e| AgreementErrorRepr::HashContext { source: e })?
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
    use super::*;
    use crate::{
        test_data::get_test_data_agreement,
        test_json_data::json_to_p_table,
        test_json_data::{
            json_array_value_to_array_integer_base64, json_to_encryption_parameters_base64,
        },
    };

    #[test]
    fn test_hash_context() {
        for tc in get_test_data_agreement("get-hash-context.json")
            .as_array()
            .unwrap()
            .iter()
        {
            let description = tc["description"].as_str().unwrap();
            let output = tc["output"].as_str().unwrap();
            let context = &tc["context"];
            let ep = json_to_encryption_parameters_base64(context);
            let ee = context["ee"].as_str().unwrap();
            let vcs = context["vcs"].as_str().unwrap();
            let el_pk = json_array_value_to_array_integer_base64(&context["ELpk"]);
            let pk_ccr = json_array_value_to_array_integer_base64(&context["pkCCR"]);
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
                "{description}",
            )
        }
    }
}
