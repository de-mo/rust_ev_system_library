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

mod action;
mod subscribers;

use std::path::PathBuf;
use structopt::StructOpt;
use subscribers::init_subscriber;
use tracing::instrument;

use crate::action::{decrypt, encrypt};

/// Specification of the sub commands tally and setup
#[derive(Debug, PartialEq, StructOpt)]
#[structopt()]
pub struct CrytperSubcommand {
    #[structopt(parse(from_os_str))]
    /// Path to the input file
    pub input: PathBuf,

    #[structopt(parse(from_os_str))]
    /// Path to the output file
    pub output: PathBuf,

    #[structopt(short = "p", long = "password")]
    /// The password to encrypt / decrypt
    pub password: String,

    #[structopt(long = "replace")]
    /// True will replace the existing file. By False, will not replace the file and generate an error
    pub replace: bool,
}

#[derive(Debug, PartialEq, StructOpt)]
#[structopt()]
pub enum SubCommands {
    #[structopt()]
    /// Encrypt a file
    Encrypt(CrytperSubcommand),

    #[structopt()]
    /// Decrypt a file
    Decrypt(CrytperSubcommand),
}

/// Main command
#[derive(Debug, StructOpt)]
#[structopt(name = env!("CARGO_PKG_NAME"), version = env!("CARGO_PKG_VERSION"), author = env!("CARGO_PKG_AUTHORS"), about = env!("CARGO_PKG_DESCRIPTION"))]
/// Crypter / Decrypter
/// Encrypt and decrypt files
pub struct VerifiyCommand {
    #[structopt(subcommand)]
    pub sub: SubCommands,
}

/// Execute the command
/// This is the main method called from the console
///
/// # return
/// * Nothing if the execution runs correctly
/// * [anyhow::Result] with the related error by a problem
#[instrument()]
fn execute_command() -> anyhow::Result<()> {
    match VerifiyCommand::from_args().sub {
        SubCommands::Encrypt(c) => encrypt(&c),
        SubCommands::Decrypt(c) => decrypt(&c),
    }
}

pub fn main() -> anyhow::Result<()> {
    let _guards = init_subscriber();
    execute_command()
}
