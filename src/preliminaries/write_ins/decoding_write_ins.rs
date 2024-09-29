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
pub fn quadratic_residue_to_write_in(
    encryption_parameters: &EncryptionParameters,
    y: &Integer,
) -> Result<String, WriteInsError> {
    let p = encryption_parameters.p();
    let q = encryption_parameters.q();
    let mut x = y.mod_exponentiate(&(Integer::from(p + 1) / 4), p);
    if &x > q {
        x = x - p;
    }
    integer_to_write_in(encryption_parameters, &x)
}

/// Algorithm 3.17
fn integer_to_write_in(
    encryption_parameters: &EncryptionParameters,
    x: &Integer,
) -> Result<String, WriteInsError> {
    if x == Integer::zero() {
        return Err(WriteInsError::IntegerToWriteInput(
            "x cannot be 0".to_string(),
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
        let b = Integer::from(x % a);
        let c = ALPHABET_LATIN
            .character_at_pos(usize::try_from(&b).unwrap())
            .unwrap();
        res.push(c);
        x_internal = Integer::from(x_internal - &b) / a;
    }
    Ok(res)
}
