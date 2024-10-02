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

//! Algorithms defined in section Write-ins

mod decoding_write_ins;
mod write_ins_tally_phase;

pub use write_ins_tally_phase::decode_write_ins;

use super::ElectoralModelError;
use thiserror::Error;

/// Enum representing the errors during the algorithms in write-ins
#[derive(Error, Debug)]
pub enum WriteInsError {
    #[error("Error input in decode_write_ins: {0}")]
    DecodeWriteInsInput(String),
    #[error(transparent)]
    ElectoralModelError(#[from] ElectoralModelError),
    #[error("Error input in integer_to_write_in: {0}")]
    IntegerToWriteInput(String),
}
