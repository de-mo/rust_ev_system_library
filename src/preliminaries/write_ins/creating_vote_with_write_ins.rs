use super::{WriteInsError, encoding_write_ins::write_in_to_quadratic_residue};
use rust_ev_crypto_primitives::{ConstantsTrait, Integer, elgamal::EncryptionParameters};

pub fn encode_write_ins(
    ep: &EncryptionParameters,
    delta: usize,
    s_tilde: &[&str],
) -> Result<Vec<Integer>, WriteInsError> {
    let mut res = s_tilde
        .iter()
        .map(|s| write_in_to_quadratic_residue(ep, s))
        .collect::<Result<Vec<_>, _>>()?;
    let mut res_filled = vec![Integer::one().clone(); delta - 1 - s_tilde.len()];
    res.append(&mut res_filled);
    Ok(res)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        test_data::get_test_data_writeins,
        test_json_data::{
            json_array_value_to_array_integer_base64, json_array_value_to_array_string,
            json_to_encryption_parameters_base64,
        },
    };

    #[test]
    fn test_encode_write_ins() {
        let value = get_test_data_writeins("encode-write-ins.json");
        for tc in value.as_array().unwrap().iter() {
            let description = tc["description"].as_str().unwrap();
            let ep = json_to_encryption_parameters_base64(&tc["context"]);
            let delta = tc["context"]["delta"]
                .as_number()
                .unwrap()
                .as_u128()
                .unwrap() as usize;
            let s_hat = json_array_value_to_array_string(&tc["input"]["s_hat"]);
            let expected = json_array_value_to_array_integer_base64(&tc["output"]["w"]);
            let res = encode_write_ins(
                &ep,
                delta,
                s_hat
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .as_slice(),
            );
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
