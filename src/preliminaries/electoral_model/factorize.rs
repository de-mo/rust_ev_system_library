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

use super::{EPPTableAsContext, ElectoralModelError};
use rust_ev_crypto_primitives::{ConstantsTrait, Integer};

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
