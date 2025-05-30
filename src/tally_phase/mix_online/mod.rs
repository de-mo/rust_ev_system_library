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

//! Module implementing the algorithms for the tally phase

mod get_mixnet_initial_ciphertexts;

pub use get_mixnet_initial_ciphertexts::*;
use rust_ev_crypto_primitives::{elgamal::ElgamalError, HashError};
use thiserror::Error;

/// Errors during the algorithms for Mix Online
#[derive(Error, Debug)]
#[error(transparent)]
pub struct MixOnlineError(#[from] MixOnlineErrorRepr);

#[derive(Error, Debug)]
enum MixOnlineErrorRepr {
    #[error("Error input in GetMixnetInitialCiphertexts: {0}")]
    GetMixnetInitialCiphertextsInput(String),
    #[error("Error calculating e_trivial")]
    ETrivail { source: ElgamalError },
    #[error("Error calculating hvc_j")]
    HVCJ { source: HashError },
}
