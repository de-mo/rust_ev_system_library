use crate::preliminaries::write_ins::WriteInsErrorRepr;

use super::WriteInsError;
use rust_ev_crypto_primitives::{
    Integer, OperationsTrait, alphabets::ALPHABET_LATIN, elgamal::EncryptionParameters, ops::Pow,
};

/// Algorithm 3.21
///
/// Error [WriteInsError] if something is going wrong
pub fn write_in_to_quadratic_residue(
    ep: &EncryptionParameters,
    s: &str,
) -> Result<Integer, WriteInsError> {
    let x = write_in_to_integer(ep, s)?;
    let y = x
        .mod_square(ep.p())
        .map_err(|e| WriteInsErrorRepr::ModSquare { source: e })?;
    Ok(y)
}

/// Algorithm 3.22
///
/// Error [WriteInsError] if something is going wrong
pub fn write_in_to_integer(ep: &EncryptionParameters, s: &str) -> Result<Integer, WriteInsError> {
    let a = Integer::from(ALPHABET_LATIN.size());
    if Integer::from(a.clone().pow(s.len() as u32)) > *ep.q() {
        return Err(WriteInsErrorRepr::EncodeWriteInsInput(format!(
            "The write-in string is too long to be encoded in the given encryption parameters"
        ))
        .into());
    }
    let mut x = Integer::from(0);
    for (i, c) in s.chars().enumerate() {
        let b = ALPHABET_LATIN.rank_of_character(c).ok_or_else(|| {
            WriteInsErrorRepr::EncodeWriteInsInput(format!(
                "Character '{}' at position {} not in alphabet",
                c, i
            ))
        })?;
        x = ((x * &a) + Integer::from(b)) % ep.q();
    }
    Ok(x)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        test_data::get_test_data_writeins,
        test_json_data::{json_to_encryption_parameters_base16, json_value_to_integer_base16},
    };

    #[test]
    fn test_write_in_to_integer() {
        let value = get_test_data_writeins("write-in-to-integer.json");
        for tc in value.as_array().unwrap().iter() {
            let description = tc["description"].as_str().unwrap();
            let ep = json_to_encryption_parameters_base16(&tc["context"]);
            let s = tc["input"]["s"].as_str().unwrap();
            if !&tc["output"]["output"].is_null() {
                let expected = json_value_to_integer_base16(&tc["output"]["output"]);
                assert_eq!(
                    write_in_to_integer(&ep, s).unwrap(),
                    expected,
                    "{description}"
                )
            } else {
                assert!(
                    write_in_to_integer(&ep, s).is_err(),
                    "{description} should have returned an error"
                )
            }
        }
    }

    #[test]
    fn test_qr_to_write_in() {
        let value = get_test_data_writeins("write-in-to-quadratic-residue_reduced.json");
        for tc in value.as_array().unwrap().iter() {
            let description = tc["description"].as_str().unwrap();
            let ep = json_to_encryption_parameters_base16(&tc["context"]);
            let s = tc["input"]["s"].as_str().unwrap();
            if !&tc["output"]["output"].is_null() {
                let expected = json_value_to_integer_base16(&tc["output"]["output"]);
                assert_eq!(
                    write_in_to_quadratic_residue(&ep, s).unwrap(),
                    expected,
                    "{description}"
                )
            } else {
                assert!(
                    write_in_to_quadratic_residue(&ep, s).is_err(),
                    "{description} should have returned an error"
                )
            }
        }
    }
}
