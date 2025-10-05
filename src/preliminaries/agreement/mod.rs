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

//! Algorithms defined in section Agreement algorithms

mod election_event_context;
mod hash_context;

pub use election_event_context::*;
pub use hash_context::*;
use rust_ev_crypto_primitives::HashError;
use thiserror::Error;

/// Enum representing the errors during the algorithms in electoral model
#[derive(Error, Debug)]
#[error(transparent)]
pub struct AgreementError(#[from] AgreementErrorRepr);

/// Enum representing the errors during the algorithms in electoral model
#[derive(Error, Debug)]
enum AgreementErrorRepr {
    #[error("Error hashing context")]
    HashContext { source: HashError },
}
