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

mod factorize;
mod primes_mapping_table;

pub use factorize::*;
pub use primes_mapping_table::*;
use rust_ev_crypto_primitives::elgamal::EncryptionParameters;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ElectoralModelError {
    #[error("Error output in get_blank_correctness_information: {0}")]
    GetBlankCorrectnessInformationOutput(String),
    #[error("Error output in get_encoded_voting_options: {0}")]
    GetEncodedVotingOptionsInput(String),
    #[error("Error output in get_actual_voting_options: {0}")]
    GetActualVotingOptionsInput(String),
    #[error("Error output in get_correctness_information: {0}")]
    GetCorrectnessInformationInput(String),
    #[error("Error output in factorize: {0}")]
    FactorizeInput(String),
}

pub struct EPPTableAsContext<'a, 'b> {
    p_table: &'a PTable,
    encryption_parameters: &'b EncryptionParameters,
}

impl<'a, 'b> EPPTableAsContext<'a, 'b> {
    pub fn new(encryption_parameters: &'b EncryptionParameters, p_table: &'a PTable) -> Self {
        Self {
            p_table,
            encryption_parameters,
        }
    }

    pub fn p_table(&self) -> &'a PTable {
        self.p_table
    }

    pub fn encryption_parameters(&self) -> &'b EncryptionParameters {
        self.encryption_parameters
    }
}
