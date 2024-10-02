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

use rust_ev_crypto_primitives::{string::truncate, Integer};

use crate::{preliminaries::EPPTableAsContext, MAX_LENGTH_WRITE_IN_FIELD};

use super::{decoding_write_ins::quadratic_residue_to_write_in, WriteInsError};

/// Algorithm 3.20
fn is_writein_option(context: &EPPTableAsContext, p_tilde_i: &usize) -> bool {
    context
        .p_table()
        .get_write_in_encoded_voting_options()
        .contains(p_tilde_i)
}

/// Algorithm 3.22
///
/// Error [WriteInsError] if something is going wrong
pub fn decode_write_ins(
    context: &EPPTableAsContext,
    p_hat: &[usize],
    w: &[Integer],
) -> Result<Vec<String>, WriteInsError> {
    let psi = context
        .p_table()
        .get_psi()
        .map_err(WriteInsError::ElectoralModelError)?;
    let delta = context.p_table().get_delta();
    if p_hat.len() != psi {
        return Err(WriteInsError::DecodeWriteInsInput(format!(
            "The length of p_hat={} must be psi={}",
            p_hat.len(),
            psi
        )));
    }
    if w.len() != delta - 1 {
        return Err(WriteInsError::DecodeWriteInsInput(format!(
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
        if is_writein_option(context, p_hat_i) {
            let w_k = w_iter.next().unwrap();
            let s = quadratic_residue_to_write_in(context.encryption_parameters(), w_k)?;
            res.push(truncate(&s, MAX_LENGTH_WRITE_IN_FIELD))
        }
    }
    Ok(res)
}
