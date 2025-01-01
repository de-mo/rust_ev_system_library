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

use super::WriteInsError;
use rust_ev_crypto_primitives::{
    alphabets::ALPHABET_LATIN, elgamal::EncryptionParameters, ConstantsTrait, Integer,
    OperationsTrait,
};

/// Algorithm 3.17
///
/// Error [WriteInsError] if something is going wrong
pub fn quadratic_residue_to_write_in(
    encryption_parameters: &EncryptionParameters,
    y: &Integer,
) -> Result<String, WriteInsError> {
    let p = encryption_parameters.p();
    let q = encryption_parameters.q();
    let mut x = y
        .mod_exponentiate(&(Integer::from(p + 1) / 4), p)
        .map_err(|e| {
            WriteInsError::IntegerToWriteInput(format!("Error with mod_exponentiate {}", e))
        })?;
    if &x > q {
        x = p - x;
    }
    integer_to_write_in(encryption_parameters, &x)
}

/// Algorithm 3.17
///
/// Error [WriteInsError] if something is going wrong
fn integer_to_write_in(
    encryption_parameters: &EncryptionParameters,
    x: &Integer,
) -> Result<String, WriteInsError> {
    if x <= Integer::zero() {
        return Err(WriteInsError::IntegerToWriteInput(
            "x cannot be less or equal 0".to_string(),
        ));
    }
    let a = ALPHABET_LATIN.size();
    // ensure that x is in Z_q
    let mut x_internal = Integer::from(x % encryption_parameters.q());
    let mut res = String::new();
    loop {
        if &x_internal == Integer::zero() {
            break;
        }
        let b = x_internal.mod_u(a as u32) as usize;
        let c = ALPHABET_LATIN.character_at_pos(b).unwrap();
        res.insert(0, c);
        x_internal = (x_internal - b) / a;
    }
    Ok(res)
}

#[cfg(test)]
mod test {
    use std::fs;

    use crate::{
        test_data::get_test_data_writeins_path,
        test_json_data::{json_to_encryption_parameters_base16, json_value_to_integer_base16},
    };

    use super::*;
    use serde_json::Value;

    fn get_test_case_integer_to_write_in() -> Value {
        serde_json::from_str(
            &fs::read_to_string(get_test_data_writeins_path().join("integer-to-write-in.json"))
                .unwrap(),
        )
        .unwrap()
    }

    fn get_test_case_qr_to_write_in() -> Value {
        serde_json::from_str(
            &fs::read_to_string(get_test_data_writeins_path().join("qr-to-write-in.json")).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn test_integer_to_write_in() {
        let value = get_test_case_integer_to_write_in();
        for tc in value.as_array().unwrap().iter() {
            let description = tc["description"].as_str().unwrap();
            let ep = json_to_encryption_parameters_base16(&tc["context"]);
            let x = json_value_to_integer_base16(&tc["input"]["x"]);
            let expected = tc["output"]["output"].as_str().unwrap();
            assert_eq!(
                integer_to_write_in(&ep, &x).unwrap().as_str(),
                expected,
                "{}",
                description
            )
        }
        assert!(integer_to_write_in(
            &json_to_encryption_parameters_base16(&value[0]["context"]),
            Integer::zero()
        )
        .is_err())
    }

    #[test]
    fn test_qr_to_write_in() {
        let value = get_test_case_qr_to_write_in();
        for tc in value.as_array().unwrap().iter() {
            let description = tc["description"].as_str().unwrap();
            let ep = json_to_encryption_parameters_base16(&tc["context"]);
            let y = json_value_to_integer_base16(&tc["input"]["y"]);
            let expected = tc["output"]["output"].as_str().unwrap();
            assert_eq!(
                quadratic_residue_to_write_in(&ep, &y).unwrap().as_str(),
                expected,
                "{}",
                description
            )
        }
    }
}
