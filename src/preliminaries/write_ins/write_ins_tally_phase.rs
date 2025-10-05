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

use rust_ev_crypto_primitives::{elgamal::EncryptionParameters, string::truncate, Integer};

use crate::MAX_LENGTH_WRITE_IN_FIELD;

use super::{decoding_write_ins::quadratic_residue_to_write_in, WriteInsError, WriteInsErrorRepr};

/// Algorithm 3.20
fn is_writein_option(p_w_tilde: &[usize], p_tilde_i: &usize) -> bool {
    p_w_tilde.contains(p_tilde_i)
}

/// Algorithm 3.22
///
/// Error [WriteInsError] if something is going wrong
pub fn decode_write_ins(
    ep: &EncryptionParameters,
    p_w_tilde: &[usize],
    psi: usize,
    delta: usize,
    p_hat: &[usize],
    w: &[Integer],
) -> Result<Vec<String>, WriteInsError> {
    decode_write_ins_impl(ep, p_w_tilde, psi, delta, p_hat, w).map_err(WriteInsError::from)
}

pub fn decode_write_ins_impl(
    ep: &EncryptionParameters,
    p_w_tilde: &[usize],
    psi: usize,
    delta: usize,
    p_hat: &[usize],
    w: &[Integer],
) -> Result<Vec<String>, WriteInsErrorRepr> {
    if p_hat.len() != psi {
        return Err(WriteInsErrorRepr::DecodeWriteInsInput(format!(
            "The length of p_hat={} must be psi={}",
            p_hat.len(),
            psi
        )));
    }
    if w.len() != delta - 1 {
        return Err(WriteInsErrorRepr::DecodeWriteInsInput(format!(
            "The length of w={} must be delta - 1={}",
            w.len(),
            delta - 1
        )));
    }
    if delta == 1 {
        return Ok(vec![]);
    }
    let mut res = vec![];
    let mut w_iter = w.iter();
    for p_hat_i in p_hat.iter() {
        if is_writein_option(p_w_tilde, p_hat_i) {
            let w_k = w_iter.next().unwrap();
            let s = quadratic_residue_to_write_in(ep, w_k).map_err(|e| {
                WriteInsErrorRepr::QuadraticToWriteInsForVal {
                    val: w_k.clone(),
                    source: Box::new(e),
                }
            })?;
            res.push(truncate(&s, MAX_LENGTH_WRITE_IN_FIELD))
        }
    }
    Ok(res)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        test_data::get_test_data_writeins,
        test_json_data::{
            json_array_value_to_array_integer_base64, json_array_value_to_array_string,
            json_array_value_to_array_usize_base64, json_to_encryption_parameters_base64,
            json_value_to_usize_base64,
        },
    };

    #[test]
    fn test_is_writein_option() {
        let value = get_test_data_writeins("is-write-in-option.json");
        for tc in value.as_array().unwrap().iter() {
            let description = tc["description"].as_str().unwrap();
            let p_w_tilde = json_array_value_to_array_usize_base64(&tc["input"]["p_w_tilde"]);
            let p_i_tilde = json_value_to_usize_base64(&tc["input"]["p_i_tilde"]);
            let expected = tc["output"]["output"].as_bool().unwrap();
            assert_eq!(
                is_writein_option(&p_w_tilde, &p_i_tilde),
                expected,
                "{description}"
            )
        }
    }

    #[test]
    fn test_decode_write_ins() {
        let value = get_test_data_writeins("decode-write-ins.json");
        for tc in value.as_array().unwrap().iter() {
            let description = tc["description"].as_str().unwrap();
            let ep = json_to_encryption_parameters_base64(&tc["context"]);
            let p_w_tilde = json_array_value_to_array_usize_base64(&tc["context"]["p_w_tilde"]);
            let psi = tc["context"]["psi"].as_number().unwrap().as_u128().unwrap() as usize;
            let delta = tc["context"]["delta"]
                .as_number()
                .unwrap()
                .as_u128()
                .unwrap() as usize;
            let p_hat = json_array_value_to_array_usize_base64(&tc["input"]["p_hat"]);
            let w = json_array_value_to_array_integer_base64(&tc["input"]["w"]);
            let expected = json_array_value_to_array_string(&tc["output"]["s_hat"]);
            let res = decode_write_ins(&ep, &p_w_tilde, psi, delta, &p_hat, &w);
            assert!(
                res.is_ok(),
                "Error with res {}: {}",
                res.unwrap_err(),
                description
            );
            assert_eq!(res.unwrap(), expected, "{description}")
        }
    }
}
