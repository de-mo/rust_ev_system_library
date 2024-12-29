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

use super::{EPPTableAsContext, ElectoralModelError, PTableTrait};
use rust_ev_crypto_primitives::{ConstantsTrait, Integer};

/// Algorithm 3.12
///
/// Error [ElectoralModelError] if something is going wrong
pub fn factorize(
    context: &EPPTableAsContext,
    x: &Integer,
) -> Result<Vec<usize>, ElectoralModelError> {
    let p_tilde = context.p_table.get_encoded_voting_options(&[])?;
    let psi = context.p_table.get_psi()?;
    let res = p_tilde
        .into_iter()
        .filter(|p_tilde_k| x.is_divisible(&Integer::from(*p_tilde_k)))
        .collect::<Vec<_>>();
    if res.len() != psi {
        return Err(ElectoralModelError::FactorizeInput(format!(
            "The nummer of factors {} is not equal psi {psi}",
            res.len()
        )));
    }
    if &res.iter().fold(Integer::one().clone(), |acc, p| (acc * p)) != x {
        return Err(ElectoralModelError::FactorizeInput(
            "The product of the factors is not equal to the given number".to_string(),
        ));
    }
    Ok(res)
}

#[cfg(test)]
mod test {
    use super::super::primes_mapping_table::test_json_data::json_to_p_table;
    use super::*;
    use crate::test_data::{get_prime_tables_1, get_prime_tables_2};
    use crate::test_json_data::json_to_encryption_parameters_base64;

    #[test]
    fn test_factorize_psi_1() {
        let prime_tables_1 = get_prime_tables_1();
        let p_table = json_to_p_table(&prime_tables_1["pTable"]);
        let ep = json_to_encryption_parameters_base64(&prime_tables_1["encryptionGroup"]);
        let context = EPPTableAsContext {
            p_table: &p_table,
            encryption_parameters: &ep,
        };
        assert_eq!(factorize(&context, &Integer::from(13)).unwrap(), vec![13]);
        assert!(factorize(&context, &Integer::from(11 * 13)).is_err(),);
    }

    #[test]
    fn test_factorize_psi_11() {
        let prime_tables_1 = get_prime_tables_2();
        let p_table = json_to_p_table(&prime_tables_1["pTable"]);
        let ep = json_to_encryption_parameters_base64(&prime_tables_1["encryptionGroup"]);
        let context = EPPTableAsContext {
            p_table: &p_table,
            encryption_parameters: &ep,
        };
        let res: Vec<usize> = vec![61, 67, 71, 73, 79, 83, 89, 101, 107, 109, 149];
        let x = res.iter().fold(Integer::one().clone(), |acc, p| acc * p);
        assert_eq!(factorize(&context, &x).unwrap(), res);
        assert!(factorize(&context, &Integer::from(61 * 67)).is_err(),);
        let res2: Vec<usize> = vec![7, 61, 67, 71, 73, 79, 83, 89, 101, 107, 109];
        let x2 = res2.iter().fold(Integer::one().clone(), |acc, p| acc * p);
        assert!(factorize(&context, &x2).is_err());
    }
}
