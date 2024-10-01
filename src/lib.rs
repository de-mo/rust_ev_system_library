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

#[cfg(test)]
mod test_json_data {
    use std::{fs, path::PathBuf};

    use rust_ev_crypto_primitives::{elgamal::EncryptionParameters, Hexa, Integer};
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

    pub fn json_value_to_integer(value: &Value) -> Integer {
        Integer::from_hexa_string(value.as_str().unwrap()).unwrap()
    }

    fn json_to_encryption_parameters(value: &Value) -> EncryptionParameters {
        EncryptionParameters::from((
            &json_value_to_integer(&value["p"]),
            &json_value_to_integer(&value["q"]),
            &json_value_to_integer(&value["g"]),
        ))
    }

    pub fn get_prime_tables_1() -> Value {
        let p = PathBuf::from(".")
            .join("test_data")
            .join("prime_tables_1.json");
        serde_json::from_str(&fs::read_to_string(p).unwrap()).unwrap()
    }
}
