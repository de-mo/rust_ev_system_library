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
use thiserror::Error;

// enum representing the errors during the algorithms for Mix Offline
#[derive(Error, Debug, Clone)]
pub enum MixOnlineError {
    #[error("Error input in GetMixnetInitialCiphertexts: {0}")]
    GetMixnetInitialCiphertextsInput(String),
    #[error("Error processing in GetMixnetInitialCiphertexts: {0}")]
    GetMixnetInitialCiphertextsProcess(String),
}
