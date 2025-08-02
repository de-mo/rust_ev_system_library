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

pub mod chanel_security;
pub mod preliminaries;
pub mod tally_phase;

/// Maximum number of characters in a write-in field (l_w)
pub const MAX_LENGTH_WRITE_IN_FIELD: usize = 400;

/// Expose rust_ev_crypto_primitives und rust_ev_crypto_primitives::prelude to avoid problems
/// of consistencies
pub mod rust_ev_crypto_primitives {
    pub mod prelude {
        pub use rust_ev_crypto_primitives::*;
    }
}

#[cfg(test)]
mod test_data {
    use serde_json::Value;
    use std::{fs, path::PathBuf};

    const TEST_DATA_DIR_NAME: &str = "test_data";
    const WRITEINS_DIR_NAME: &str = "writeins";
    const AGREEMENT_DIR_NAME: &str = "agreement";
    const STREAM_DIR_NAME: &str = "stream";

    pub fn get_test_data_path() -> PathBuf {
        PathBuf::from(".").join(TEST_DATA_DIR_NAME)
    }

    fn get_test_data_writeins_path() -> PathBuf {
        get_test_data_path().join(WRITEINS_DIR_NAME)
    }

    fn get_test_data_agreement_path() -> PathBuf {
        get_test_data_path().join(AGREEMENT_DIR_NAME)
    }

    fn get_test_data_straam_path() -> PathBuf {
        get_test_data_path().join(STREAM_DIR_NAME)
    }

    pub fn get_test_data_writeins(filname: &str) -> Value {
        serde_json::from_str(
            &fs::read_to_string(get_test_data_writeins_path().join(filname)).unwrap(),
        )
        .unwrap()
    }

    pub fn get_test_data_agreement(filname: &str) -> Value {
        serde_json::from_str(
            &fs::read_to_string(get_test_data_agreement_path().join(filname)).unwrap(),
        )
        .unwrap()
    }

    pub fn get_test_data_stream(filname: &str) -> Value {
        serde_json::from_str(
            &fs::read_to_string(get_test_data_straam_path().join(filname)).unwrap(),
        )
        .unwrap()
    }

    pub fn get_prime_tables_1() -> Value {
        serde_json::from_str(
            &fs::read_to_string(get_test_data_path().join("prime_tables_1.json")).unwrap(),
        )
        .unwrap()
    }

    pub fn get_prime_tables_2() -> Value {
        serde_json::from_str(
            &fs::read_to_string(get_test_data_path().join("prime_tables_2.json")).unwrap(),
        )
        .unwrap()
    }
}

#[cfg(test)]
mod test_json_data {
    use crate::preliminaries::{PTable, PTableElement};
    use chrono::NaiveDateTime;
    use rust_ev_crypto_primitives::{
        elgamal::EncryptionParameters, ByteArray, DecodeTrait, Integer,
    };
    use serde_json::Value;

    pub fn json_array_value_to_array_string(array: &Value) -> Vec<String> {
        array
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    }

    pub fn json_array_value_to_array_integer_base64(array: &Value) -> Vec<Integer> {
        Integer::base_64_decode_vector(
            json_array_value_to_array_string(array)
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .as_slice(),
        )
        .unwrap()
    }

    pub fn json_array_value_to_array_usize_base64(array: &Value) -> Vec<usize> {
        json_array_value_to_array_integer_base64(array)
            .iter()
            .map(|x| x.to_usize().unwrap())
            .collect()
    }

    pub fn json_value_to_integer_base64(value: &Value) -> Integer {
        Integer::base64_decode(value.as_str().unwrap()).unwrap()
    }

    pub fn json_value_to_usize_base64(value: &Value) -> usize {
        json_value_to_integer_base64(value).to_usize().unwrap()
    }

    pub fn json_value_to_bytearray_base64(value: &Value) -> ByteArray {
        ByteArray::base64_decode(value.as_str().unwrap()).unwrap()
    }

    pub fn json_to_encryption_parameters_base64(value: &Value) -> EncryptionParameters {
        EncryptionParameters::from((
            &json_value_to_integer_base64(&value["p"]),
            &json_value_to_integer_base64(&value["q"]),
            &json_value_to_integer_base64(&value["g"]),
        ))
    }

    pub fn json_value_to_naive_datetime(value: &Value) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(value.as_str().unwrap(), "%Y-%m-%dT%H:%M:%S").unwrap()
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
        value
            .as_array()
            .unwrap()
            .iter()
            .map(json_to_p_table_element)
            .collect()
    }
}
