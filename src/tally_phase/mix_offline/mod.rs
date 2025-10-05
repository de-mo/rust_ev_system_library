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

//! Module implementing the algorithms for mixing offline

mod process_plaintexts;
mod verifiy_client_proofs;
mod verify_mix_dec_offline;

use crate::preliminaries::ElectoralModelError;
pub use process_plaintexts::ProcessPlaintextsOutput;
use thiserror::Error;
pub use verifiy_client_proofs::*;
pub use verify_mix_dec_offline::*;

/// Errors during the algorithms for Mix Offline
#[derive(Error, Debug)]
#[error(transparent)]
pub struct MixOfflineError(#[from] MixOfflineErrorRepr);

// enum representing the errors during the algorithms for Mix Offline
#[derive(Error, Debug)]
pub enum MixOfflineErrorRepr {
    #[error("Error input in ProcessPlaintexts: {0}")]
    ProcessPlaintextsInput(String),
    #[error("Error processing in ProcessPlaintexts: {0}")]
    ProcessPlaintextsProcess(String),
    #[error("Domain Error in inputs of VerifyVotingClientProofs: {0}")]
    VerifyVotingClientProofsInput(String),
    #[error("Error in processing VerifyVotingClientProofs: {0}")]
    VerifyVotingClientProofsProcess(String),
    #[error("Domain Error in inputs of VerifyMixDecOffline: {0}")]
    VerifyMixDecOfflineInput(String),
    #[error("Error in processing VerifyMixDecOffline: {0}")]
    VerifyMixDecOfflineProcess(String),
    #[error("Error getting psi from pTable")]
    GetPsi { source: ElectoralModelError },
}
