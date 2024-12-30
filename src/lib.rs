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
    use std::{fs, path::PathBuf};

    use serde_json::Value;

    const TEST_DATA_DIR_NAME: &str = "test_data";
    const WRITEINS_DIR_NAME: &str = "writeins";

    pub fn get_test_data_path() -> PathBuf {
        PathBuf::from(".").join(TEST_DATA_DIR_NAME)
    }

    pub fn get_test_data_writeins_path() -> PathBuf {
        get_test_data_path().join(WRITEINS_DIR_NAME)
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
    use chrono::NaiveDateTime;
    use rust_ev_crypto_primitives::{elgamal::EncryptionParameters, DecodeTrait, Hexa, Integer};
    use serde_json::Value;

    pub fn json_array_value_to_array_string(array: &Value) -> Vec<String> {
        array
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    }

    pub fn json_array_value_to_array_integer(array: &Value) -> Vec<Integer> {
        Integer::from_hexa_string_slice(&json_array_value_to_array_string(array)).unwrap()
    }

    pub fn json_value_to_integer_base16(value: &Value) -> Integer {
        Integer::from_hexa_string(value.as_str().unwrap()).unwrap()
    }

    pub fn json_value_to_integer_base64(value: &Value) -> Integer {
        Integer::base64_decode(value.as_str().unwrap()).unwrap()
    }

    pub fn json_to_encryption_parameters_base64(value: &Value) -> EncryptionParameters {
        EncryptionParameters::from((
            &json_value_to_integer_base64(&value["p"]),
            &json_value_to_integer_base64(&value["q"]),
            &json_value_to_integer_base64(&value["g"]),
        ))
    }

    pub fn json_to_encryption_parameters_base16(value: &Value) -> EncryptionParameters {
        EncryptionParameters::from((
            &json_value_to_integer_base16(&value["p"]),
            &json_value_to_integer_base16(&value["q"]),
            &json_value_to_integer_base16(&value["g"]),
        ))
    }

    pub fn json_value_to_naive_datetime(value: &Value) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(value.as_str().unwrap(), "%Y-%m-%dT%H:%M:%S").unwrap()
    }
}
