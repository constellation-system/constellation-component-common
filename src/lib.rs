// Copyright © 2024-25 The Johns Hopkins Applied Physics Laboratory LLC.
//
// This program is free software: you can redistribute it and/or
// modify it under the terms of the GNU Affero General Public License,
// version 3, as published by the Free Software Foundation.  If you
// would like to purchase a commercial license for this software, please
// contact APL’s Tech Transfer at 240-592-0817 or
// techtransfer@jhuapl.edu.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public
// License along with this program.  If not, see
// <https://www.gnu.org/licenses/>.

#![allow(clippy::redundant_field_names)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![allow(clippy::upper_case_acronyms)]

pub mod comm;
pub mod config;

#[allow(clippy::all)]
#[rustfmt::skip]
mod generated;

use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;

/// Index used to identify principals in the stream.
///
/// These correspond one-to-one with counterparties, but not all
/// parties may be present in a given round.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PartyStreamIdx(usize);

impl From<usize> for PartyStreamIdx {
    #[inline]
    fn from(val: usize) -> PartyStreamIdx {
        PartyStreamIdx(val)
    }
}

impl From<PartyStreamIdx> for usize {
    #[inline]
    fn from(val: PartyStreamIdx) -> usize {
        val.0
    }
}

impl Display for PartyStreamIdx {
    #[inline]
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        write!(f, "{}", self.0)
    }
}
