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

//! Algorithms defined in section Write-ins

mod decoding_write_ins;
mod write_ins_tally_phase;

use super::ElectoralModelError;
use rust_ev_crypto_primitives::{Integer, ModExponentiateError};
use thiserror::Error;
pub use write_ins_tally_phase::decode_write_ins;

/// Enum representing the errors during the algorithms in write-ins
#[derive(Error, Debug)]
#[error(transparent)]
pub struct WriteInsError(#[from] WriteInsErrorRepr);

#[derive(Error, Debug)]
enum WriteInsErrorRepr {
    #[error("Error input in decode_write_ins: {0}")]
    DecodeWriteInsInput(String),
    #[error("Error getting psi")]
    ElectoralModelError(#[from] ElectoralModelError),
    #[error("Error calculating quadratic to write-in")]
    QuadraticToWriteIns { source: ModExponentiateError },
    #[error("Error calculating quadratic to write-in for {val}")]
    QuadraticToWriteInsForVal {
        val: Integer,
        source: Box<WriteInsError>,
    },
    #[error("x cannot be less or equal 0")]
    XPositive,
}
