// Copyright © 2024-26 The Johns Hopkins Applied Physics Laboratory LLC.
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

use std::array::TryFromSliceError;
use std::convert::Infallible;
use std::convert::TryInto;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;
use std::marker::PhantomData;

use constellation_common::codec::Decoder;
use constellation_common::codec::Encoder;
use constellation_common::codec::per::PERCodec;
use constellation_common::config::Create;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::hashid::HashAlgo;
use constellation_common::hashid::HashID;

use crate::generated::consensus_ctl::ConsensusCtlHeader;
use crate::generated::consensus_ctl::ConsensusCtlRoundHeader;
use crate::generated::consensus_ctl::ConsensusCtlSealHeader;
use crate::generated::consensus_ctl::ConsensusCtlSubmitHeader;

const CONSENSUS_CTL_SEAL_HEADER_SIZE: usize = 9;
const CONSENSUS_CTL_SEAL_HEADER_BITS: usize =
    CONSENSUS_CTL_SEAL_HEADER_SIZE * 8;

const CONSENSUS_CTL_ROUND_HEADER_SIZE: usize = 1050;
const CONSENSUS_CTL_ROUND_HEADER_BITS: usize =
    CONSENSUS_CTL_ROUND_HEADER_SIZE * 8;

const CONSENSUS_CTL_SUBMIT_HEADER_SIZE: usize = 9;
const CONSENSUS_CTL_SUBMIT_HEADER_BITS: usize =
    CONSENSUS_CTL_SUBMIT_HEADER_SIZE * 8;

const CONSENSUS_CTL_HEADER_SIZE: usize = 1051;
const CONSENSUS_CTL_HEADER_BITS: usize = CONSENSUS_CTL_HEADER_SIZE * 8;

type ConsensusCtlSubmitHeaderCodec =
    PERCodec<ConsensusCtlSubmitHeader, CONSENSUS_CTL_SUBMIT_HEADER_BITS>;

type ConsensusCtlRoundHeaderCodec =
    PERCodec<ConsensusCtlRoundHeader, CONSENSUS_CTL_ROUND_HEADER_BITS>;

type ConsensusCtlSealHeaderPERCodec =
    PERCodec<ConsensusCtlSealHeader, CONSENSUS_CTL_SEAL_HEADER_BITS>;

type ConsensusCtlHeaderPERCodec =
    PERCodec<ConsensusCtlHeader, CONSENSUS_CTL_HEADER_BITS>;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ConsensusCtlRound<RoundID, H, Seal>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: HashID {
    /// The round's ID.
    round: RoundID,
    /// Hashes for transactions in the round.
    hashes: Vec<H>,
    /// Seals for the round.
    seals: Option<Vec<Seal>>
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ConsensusCtlSubmit<H>
where
    H: HashID {
    hashes: Vec<H>
}

// XXX this is temporary, because we can't do asymmetric buses yet.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ConsensusCtl<RoundID, H, Seal>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: HashID {
    Round(ConsensusCtlRound<RoundID, H, Seal>),
    Submit(ConsensusCtlSubmit<H>)
}

#[derive(Clone)]
pub struct ConsensusCtlSubmitCodec<H>
where
    H: HashAlgo {
    header_codec: ConsensusCtlSubmitHeaderCodec,
    hash: H
}

#[derive(Clone)]
pub struct ConsensusCtlRoundCodec<RoundID, H, Seal, SealCodec>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: HashAlgo {
    round: PhantomData<RoundID>,
    seal: PhantomData<Seal>,
    header_codec: ConsensusCtlRoundHeaderCodec,
    seal_header_codec: ConsensusCtlSealHeaderPERCodec,
    seal_codec: SealCodec,
    hash: H
}

// XXX temporary because we can't do asymmetric buses yet.
#[derive(Clone)]
pub struct ConsensusCtlCodec<RoundID, H, Seal, SealCodec>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: HashAlgo {
    round: PhantomData<RoundID>,
    seal: PhantomData<Seal>,
    header_codec: ConsensusCtlHeaderPERCodec,
    seal_header_codec: ConsensusCtlSealHeaderPERCodec,
    seal_codec: SealCodec,
    hash: H
}

#[derive(Debug)]
pub enum ConsensusCtlSubmitEncodeError<Header> {
    /// Error occurred writing the header.
    Header {
        /// Error that occurred writing the header.
        err: Header
    },
    /// Provided buffer was too short.
    TooShort
}

#[derive(Debug)]
pub enum ConsensusCtlSubmitDecodeError<Header> {
    /// Error occurred reading the header.
    Header {
        /// Error that occurred reading the header.
        err: Header
    },
    /// Error occurred reading the hash.
    Hash {
        /// Error that occurred reading the hash.
        err: TryFromSliceError
    },
    /// Provided buffer was too short.
    TooShort
}

#[derive(Debug)]
pub enum ConsensusCtlRoundEncodeError<Header, Seal> {
    /// Error occurred writing the header.
    Header {
        /// Error that occurred writing the header.
        err: Header
    },
    /// Error occurred writing a seal.
    Seal {
        /// Error that occurred writing the seal.
        err: Seal
    },
    /// Provided buffer was too short.
    TooShort
}

#[derive(Debug)]
pub enum ConsensusCtlRoundDecodeError<Header, Seal> {
    /// Error occurred reading the header.
    Header {
        /// Error that occurred reading the header.
        err: Header
    },
    /// Error occurred reading a seal.
    Seal {
        /// Error that occurred reading the seal.
        err: Seal
    },
    /// Error occurred reading the hash.
    Hash {
        /// Error that occurred reading the hash.
        err: TryFromSliceError
    },
    /// Error occurred reading the round ID.
    Round {
        /// Error that occurred reading the round ID.
        err: Vec<u8>
    },
    /// Provided buffer was too short.
    TooShort
}

impl<H> ConsensusCtlSubmit<H>
where
    H: HashID
{
    #[inline]
    pub fn new(hashes: Vec<H>) -> Self {
        ConsensusCtlSubmit { hashes: hashes }
    }

    #[inline]
    pub fn hashes(&self) -> &[H] {
        &self.hashes
    }

    #[inline]
    pub fn take(self) -> Vec<H> {
        self.hashes
    }
}

impl<RoundID, H, Seal> ConsensusCtlRound<RoundID, H, Seal>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: HashID
{
    #[inline]
    pub fn new(
        round: RoundID,
        hashes: Vec<H>,
        seals: Option<Vec<Seal>>
    ) -> Self {
        ConsensusCtlRound {
            round: round,
            hashes: hashes,
            seals: seals
        }
    }

    #[inline]
    pub fn round(&self) -> &RoundID {
        &self.round
    }

    #[inline]
    pub fn hashes(&self) -> &[H] {
        &self.hashes
    }

    #[inline]
    pub fn seals(&self) -> Option<&Vec<Seal>> {
        self.seals.as_ref()
    }

    #[inline]
    pub fn take(self) -> (RoundID, Vec<H>, Option<Vec<Seal>>) {
        (self.round, self.hashes, self.seals)
    }
}

impl<H> Default for ConsensusCtlSubmitCodec<H>
where
    H: Default + HashAlgo
{
    #[inline]
    fn default() -> Self {
        ConsensusCtlSubmitCodec {
            header_codec: ConsensusCtlSubmitHeaderCodec::default(),
            hash: H::default()
        }
    }
}

impl<H> Create for ConsensusCtlSubmitCodec<H>
where
    H: Default + HashAlgo
{
    type Config = ();
    type CreateError = Infallible;

    #[inline]
    fn create(_param: Self::Config) -> Result<Self, Self::CreateError> {
        Ok(ConsensusCtlSubmitCodec {
            header_codec: ConsensusCtlSubmitHeaderCodec::default(),
            hash: H::default()
        })
    }
}

impl<H> Encoder<ConsensusCtlSubmit<H::HashID>> for ConsensusCtlSubmitCodec<H>
where
    H: Default + HashAlgo
{
    type EncodeError =
        ConsensusCtlSubmitEncodeError<
            <ConsensusCtlSubmitHeaderCodec as Encoder<
                ConsensusCtlSubmitHeader
            >>::EncodeError
        >;

    #[inline]
    fn buf_size(
        &self,
        val: &ConsensusCtlSubmit<H::HashID>
    ) -> usize {
        let hashes = val.hashes.len() * 64;

        hashes + 9
    }

    fn encode(
        &mut self,
        val: &ConsensusCtlSubmit<H::HashID>,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let nhashes = val.hashes.len();
        let header = ConsensusCtlSubmitHeader {
            nhashes: nhashes as u64
        };
        let hashes_len = nhashes * 64;
        let mut curr = 0;

        curr += self
            .header_codec
            .encode(&header, &mut buf[curr..])
            .map_err(|err| ConsensusCtlSubmitEncodeError::Header {
                err: err
            })?;

        if curr + hashes_len < buf.len() {
            for hash in val.hashes.iter() {
                buf[curr..curr + 64].copy_from_slice(hash.bytes());

                curr += 64;
            }
        } else {
            return Err(ConsensusCtlSubmitEncodeError::TooShort);
        }

        Ok(curr)
    }
}

impl<H> Decoder<ConsensusCtlSubmit<H::HashID>> for ConsensusCtlSubmitCodec<H>
where
    H: Default + HashAlgo
{
    type DecodeError =
        ConsensusCtlSubmitDecodeError<
            <ConsensusCtlSubmitHeaderCodec as Decoder<
                ConsensusCtlSubmitHeader
            >>::DecodeError
        >;

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(ConsensusCtlSubmit<H::HashID>, usize), Self::DecodeError> {
        let mut curr = 0;
        let (header, nbytes) =
            self.header_codec.decode(&buf[curr..]).map_err(|err| {
                ConsensusCtlSubmitDecodeError::Header { err: err }
            })?;

        curr += nbytes;

        let nhashes = header.nhashes as usize;
        let hashes_len = nhashes * 64;
        let mut hashes = Vec::with_capacity(nhashes);

        if curr + hashes_len < buf.len() {
            for _ in 0..nhashes {
                let hash = self
                    .hash
                    .wrap_hashed_bytes(&buf[curr..curr + 64])
                    .map_err(|err| {
                    ConsensusCtlSubmitDecodeError::Hash { err: err }
                })?;

                hashes.push(hash);
                curr += 64;
            }
        } else {
            return Err(ConsensusCtlSubmitDecodeError::TooShort);
        }

        let out = ConsensusCtlSubmit { hashes: hashes };

        Ok((out, curr))
    }
}

impl<RoundID, H, Seal, SealCodec> Create
    for ConsensusCtlRoundCodec<RoundID, H, Seal, SealCodec>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: Default + HashAlgo,
    SealCodec: Create
{
    type Config = SealCodec::Config;
    type CreateError = SealCodec::CreateError;

    #[inline]
    fn create(param: Self::Config) -> Result<Self, Self::CreateError> {
        let seal_codec = SealCodec::create(param)?;

        Ok(ConsensusCtlRoundCodec {
            round: PhantomData,
            seal: PhantomData,
            seal_header_codec: ConsensusCtlSealHeaderPERCodec::default(),
            header_codec: ConsensusCtlRoundHeaderCodec::default(),
            seal_codec: seal_codec,
            hash: H::default()
        })
    }
}

impl<RoundID, H, Seal, SealCodec>
    Encoder<ConsensusCtlRound<RoundID, H::HashID, Seal>>
    for ConsensusCtlRoundCodec<RoundID, H, Seal, SealCodec>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: Default + HashAlgo,
    SealCodec: Encoder<Seal>
{
    type EncodeError =
        ConsensusCtlRoundEncodeError<
            <ConsensusCtlSubmitHeaderCodec as Encoder<
                ConsensusCtlSubmitHeader
            >>::EncodeError,
            SealCodec::EncodeError
        >;

    #[inline]
    fn buf_size(
        &self,
        val: &ConsensusCtlRound<RoundID, H::HashID, Seal>
    ) -> usize {
        let round = 16;
        let hashes = (val.hashes.len() * 64) + 2;
        let seals = if let Some(seals) = &val.seals {
            let mut len = 9;

            for seal in seals.iter() {
                len += self.seal_codec.buf_size(seal)
            }

            len
        } else {
            1
        };

        hashes + seals + round
    }

    fn encode(
        &mut self,
        val: &ConsensusCtlRound<RoundID, H::HashID, Seal>,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let round: u128 = val.round.clone().into();
        let round = round.to_le_bytes().to_vec();
        let hashes = val
            .hashes
            .iter()
            .map(|hash| hash.bytes().to_vec())
            .collect();
        let nseals = val.seals.as_ref().map_or(0, |seals| seals.len());
        let header = ConsensusCtlRoundHeader {
            round: round,
            hashes: hashes,
            nseals: nseals as u64
        };
        let mut curr = 0;

        curr += self
            .header_codec
            .encode(&header, &mut buf[curr..])
            .map_err(|err| ConsensusCtlRoundEncodeError::Header { err: err })?;

        if let Some(seals) = &val.seals {
            for seal in seals.iter() {
                let seal =
                    self.seal_codec.encode_to_vec(seal).map_err(|err| {
                        ConsensusCtlRoundEncodeError::Seal { err: err }
                    })?;
                let seal_len = seal.len();
                let header = ConsensusCtlSealHeader {
                    len: seal_len as u64
                };

                curr += self
                    .seal_header_codec
                    .encode(&header, &mut buf[curr..])
                    .map_err(|err| ConsensusCtlRoundEncodeError::Header {
                        err: err
                    })?;

                if curr + seal_len < buf.len() {
                    buf[curr..curr + seal_len].copy_from_slice(&seal[..]);

                    curr += seal_len;
                } else {
                    return Err(ConsensusCtlRoundEncodeError::TooShort);
                }
            }
        }

        Ok(curr)
    }
}

impl<RoundID, H, Seal, SealCodec>
    Decoder<ConsensusCtlRound<RoundID, H::HashID, Seal>>
    for ConsensusCtlRoundCodec<RoundID, H, Seal, SealCodec>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: Default + HashAlgo,
    SealCodec: Decoder<Seal>
{
    type DecodeError =
        ConsensusCtlRoundDecodeError<
            <ConsensusCtlSubmitHeaderCodec as Decoder<
                ConsensusCtlSubmitHeader
            >>::DecodeError,
            SealCodec::DecodeError
        >;

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<
        (ConsensusCtlRound<RoundID, H::HashID, Seal>, usize),
        Self::DecodeError
    > {
        let mut curr = 0;
        let (header, nbytes) = self
            .header_codec
            .decode(&buf[curr..])
            .map_err(|err| ConsensusCtlRoundDecodeError::Header { err: err })?;

        curr += nbytes;

        let round =
            header.round.clone().try_into().map_err(|err| {
                ConsensusCtlRoundDecodeError::Round { err: err }
            })?;
        let round = u128::from_le_bytes(round);
        let round = round.into();
        let mut hashes = Vec::with_capacity(header.hashes.len());

        for hash in header.hashes.iter() {
            let hash = self.hash.wrap_hashed_bytes(hash).map_err(|err| {
                ConsensusCtlRoundDecodeError::Hash { err: err }
            })?;

            hashes.push(hash);
        }

        let nseals = header.nseals as usize;

        let out = if nseals != 0 {
            let mut seals = Vec::with_capacity(nseals);

            for _ in 0..nseals {
                let (header, nbytes) =
                    self.seal_header_codec.decode(&buf[curr..]).map_err(
                        |err| ConsensusCtlRoundDecodeError::Header { err: err }
                    )?;

                curr += nbytes;

                let (seal, nbytes) = self
                    .seal_codec
                    .decode(&buf[curr..curr + header.len as usize])
                    .map_err(|err| ConsensusCtlRoundDecodeError::Seal {
                        err: err
                    })?;

                curr += nbytes;
                seals.push(seal)
            }

            ConsensusCtlRound {
                round: round,
                hashes: hashes,
                seals: Some(seals)
            }
        } else {
            ConsensusCtlRound {
                round: round,
                hashes: hashes,
                seals: None
            }
        };

        Ok((out, curr))
    }
}

impl<RoundID, H, Seal, SealCodec> Create
    for ConsensusCtlCodec<RoundID, H, Seal, SealCodec>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: Default + HashAlgo,
    SealCodec: Create
{
    type Config = SealCodec::Config;
    type CreateError = SealCodec::CreateError;

    #[inline]
    fn create(param: Self::Config) -> Result<Self, Self::CreateError> {
        let seal_codec = SealCodec::create(param)?;

        Ok(ConsensusCtlCodec {
            round: PhantomData,
            seal: PhantomData,
            seal_header_codec: ConsensusCtlSealHeaderPERCodec::default(),
            header_codec: ConsensusCtlHeaderPERCodec::default(),
            seal_codec: seal_codec,
            hash: H::default()
        })
    }
}

impl<RoundID, H, Seal, SealCodec>
    Encoder<ConsensusCtl<RoundID, H::HashID, Seal>>
    for ConsensusCtlCodec<RoundID, H, Seal, SealCodec>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: Default + HashAlgo,
    SealCodec: Encoder<Seal>
{
    type EncodeError =
        ConsensusCtlRoundEncodeError<
            <ConsensusCtlSubmitHeaderCodec as Encoder<
                ConsensusCtlSubmitHeader
            >>::EncodeError,
            SealCodec::EncodeError
        >;

    #[inline]
    fn buf_size(
        &self,
        val: &ConsensusCtl<RoundID, H::HashID, Seal>
    ) -> usize {
        match val {
            ConsensusCtl::Round(val) => {
                let round = 16;
                let hashes = (val.hashes.len() * 64) + 2;
                let seals = if let Some(seals) = &val.seals {
                    let mut len = 9;

                    for seal in seals.iter() {
                        len += self.seal_codec.buf_size(seal)
                    }

                    len
                } else {
                    1
                };

                hashes + seals + round
            }
            ConsensusCtl::Submit(val) => {
                let hashes = val.hashes.len() * 64;

                hashes + 9
            }
        }
    }

    fn encode(
        &mut self,
        val: &ConsensusCtl<RoundID, H::HashID, Seal>,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        match val {
            ConsensusCtl::Round(val) => {
                let round: u128 = val.round.clone().into();
                let round = round.to_le_bytes().to_vec();
                let hashes = val
                    .hashes
                    .iter()
                    .map(|hash| hash.bytes().to_vec())
                    .collect();
                let nseals = val.seals.as_ref().map_or(0, |seals| seals.len());
                let header = ConsensusCtlRoundHeader {
                    round: round,
                    hashes: hashes,
                    nseals: nseals as u64
                };
                let header = ConsensusCtlHeader::Round(header);
                let mut curr = 0;

                curr += self
                    .header_codec
                    .encode(&header, &mut buf[curr..])
                    .map_err(|err| ConsensusCtlRoundEncodeError::Header {
                        err: err
                    })?;

                if let Some(seals) = &val.seals {
                    for seal in seals.iter() {
                        let seal = self
                            .seal_codec
                            .encode_to_vec(seal)
                            .map_err(|err| {
                                ConsensusCtlRoundEncodeError::Seal { err: err }
                            })?;
                        let seal_len = seal.len();
                        let header = ConsensusCtlSealHeader {
                            len: seal_len as u64
                        };

                        curr += self
                            .seal_header_codec
                            .encode(&header, &mut buf[curr..])
                            .map_err(|err| {
                                ConsensusCtlRoundEncodeError::Header {
                                    err: err
                                }
                            })?;

                        if curr + seal_len < buf.len() {
                            buf[curr..curr + seal_len]
                                .copy_from_slice(&seal[..]);

                            curr += seal_len;
                        } else {
                            return Err(ConsensusCtlRoundEncodeError::TooShort);
                        }
                    }
                }

                Ok(curr)
            }
            ConsensusCtl::Submit(val) => {
                let nhashes = val.hashes.len();
                let header = ConsensusCtlSubmitHeader {
                    nhashes: nhashes as u64
                };
                let header = ConsensusCtlHeader::Submit(header);
                let hashes_len = nhashes * 64;
                let mut curr = 0;

                curr += self
                    .header_codec
                    .encode(&header, &mut buf[curr..])
                    .map_err(|err| ConsensusCtlRoundEncodeError::Header {
                        err: err
                    })?;

                if curr + hashes_len < buf.len() {
                    for hash in val.hashes.iter() {
                        buf[curr..curr + 64].copy_from_slice(hash.bytes());

                        curr += 64;
                    }
                } else {
                    return Err(ConsensusCtlRoundEncodeError::TooShort);
                }

                Ok(curr)
            }
        }
    }
}

impl<RoundID, H, Seal, SealCodec>
    Decoder<ConsensusCtl<RoundID, H::HashID, Seal>>
    for ConsensusCtlCodec<RoundID, H, Seal, SealCodec>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: Default + HashAlgo,
    SealCodec: Decoder<Seal>
{
    type DecodeError =
        ConsensusCtlRoundDecodeError<
            <ConsensusCtlSubmitHeaderCodec as Decoder<
                ConsensusCtlSubmitHeader
            >>::DecodeError,
            SealCodec::DecodeError
        >;

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<
        (ConsensusCtl<RoundID, H::HashID, Seal>, usize),
        Self::DecodeError
    > {
        let mut curr = 0;
        let (header, nbytes) = self
            .header_codec
            .decode(&buf[curr..])
            .map_err(|err| ConsensusCtlRoundDecodeError::Header { err: err })?;

        curr += nbytes;

        match header {
            ConsensusCtlHeader::Round(header) => {
                let round = header.round.clone().try_into().map_err(|err| {
                    ConsensusCtlRoundDecodeError::Round { err: err }
                })?;
                let round = u128::from_le_bytes(round);
                let round = round.into();
                let mut hashes = Vec::with_capacity(header.hashes.len());

                for hash in header.hashes.iter() {
                    let hash =
                        self.hash.wrap_hashed_bytes(hash).map_err(|err| {
                            ConsensusCtlRoundDecodeError::Hash { err: err }
                        })?;

                    hashes.push(hash);
                }

                let nseals = header.nseals as usize;

                let out = if nseals != 0 {
                    let mut seals = Vec::with_capacity(nseals);

                    for _ in 0..nseals {
                        let (header, nbytes) = self
                            .seal_header_codec
                            .decode(&buf[curr..])
                            .map_err(|err| {
                                ConsensusCtlRoundDecodeError::Header {
                                    err: err
                                }
                            })?;

                        curr += nbytes;

                        let (seal, nbytes) = self
                            .seal_codec
                            .decode(&buf[curr..curr + header.len as usize])
                            .map_err(|err| {
                                ConsensusCtlRoundDecodeError::Seal { err: err }
                            })?;

                        curr += nbytes;
                        seals.push(seal)
                    }

                    ConsensusCtlRound {
                        round: round,
                        hashes: hashes,
                        seals: Some(seals)
                    }
                } else {
                    ConsensusCtlRound {
                        round: round,
                        hashes: hashes,
                        seals: None
                    }
                };
                let out = ConsensusCtl::Round(out);

                Ok((out, curr))
            }
            ConsensusCtlHeader::Submit(header) => {
                let nhashes = header.nhashes as usize;
                let hashes_len = nhashes * 64;
                let mut hashes = Vec::with_capacity(nhashes);

                if curr + hashes_len < buf.len() {
                    for _ in 0..nhashes {
                        let hash = self
                            .hash
                            .wrap_hashed_bytes(&buf[curr..curr + 64])
                            .map_err(|err| {
                                ConsensusCtlRoundDecodeError::Hash { err: err }
                            })?;

                        hashes.push(hash);
                        curr += 64;
                    }
                } else {
                    return Err(ConsensusCtlRoundDecodeError::TooShort);
                }

                let out = ConsensusCtlSubmit { hashes: hashes };
                let out = ConsensusCtl::Submit(out);

                Ok((out, curr))
            }
        }
    }
}

impl<Header> ScopedError for ConsensusCtlSubmitEncodeError<Header>
where
    Header: ScopedError
{
    #[inline]
    fn scope(&self) -> ErrorScope {
        match self {
            ConsensusCtlSubmitEncodeError::Header { .. } |
            ConsensusCtlSubmitEncodeError::TooShort => ErrorScope::Unrecoverable
        }
    }
}

impl<Header, Seal> ScopedError for ConsensusCtlRoundEncodeError<Header, Seal>
where
    Header: ScopedError,
    Seal: ScopedError
{
    #[inline]
    fn scope(&self) -> ErrorScope {
        match self {
            ConsensusCtlRoundEncodeError::Seal { err } => err.scope(),
            ConsensusCtlRoundEncodeError::Header { .. } |
            ConsensusCtlRoundEncodeError::TooShort => ErrorScope::Unrecoverable
        }
    }
}

impl<Header, Seal> ScopedError for ConsensusCtlRoundDecodeError<Header, Seal>
where
    Header: ScopedError,
    Seal: ScopedError
{
    #[inline]
    fn scope(&self) -> ErrorScope {
        match self {
            ConsensusCtlRoundDecodeError::Seal { err } => err.scope(),
            ConsensusCtlRoundDecodeError::Header { .. } |
            ConsensusCtlRoundDecodeError::Hash { .. } |
            ConsensusCtlRoundDecodeError::Round { .. } |
            ConsensusCtlRoundDecodeError::TooShort => ErrorScope::Unrecoverable
        }
    }
}

impl<Header> ScopedError for ConsensusCtlSubmitDecodeError<Header>
where
    Header: ScopedError
{
    #[inline]
    fn scope(&self) -> ErrorScope {
        match self {
            ConsensusCtlSubmitDecodeError::Header { .. } |
            ConsensusCtlSubmitDecodeError::Hash { .. } |
            ConsensusCtlSubmitDecodeError::TooShort => ErrorScope::Unrecoverable
        }
    }
}

impl<Header, Seal> Display for ConsensusCtlRoundEncodeError<Header, Seal>
where
    Header: Display,
    Seal: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            ConsensusCtlRoundEncodeError::Header { err } => err.fmt(f),
            ConsensusCtlRoundEncodeError::Seal { err } => err.fmt(f),
            ConsensusCtlRoundEncodeError::TooShort => {
                write!(f, "buffer is too short")
            }
        }
    }
}

impl<Header, Seal> Display for ConsensusCtlRoundDecodeError<Header, Seal>
where
    Header: Display,
    Seal: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            ConsensusCtlRoundDecodeError::Header { err } => err.fmt(f),
            ConsensusCtlRoundDecodeError::Hash { err } => err.fmt(f),
            ConsensusCtlRoundDecodeError::Seal { err } => err.fmt(f),
            ConsensusCtlRoundDecodeError::Round { .. } => {
                write!(f, "wrong size of round ID")
            }
            ConsensusCtlRoundDecodeError::TooShort => {
                write!(f, "buffer is too short")
            }
        }
    }
}

impl<Header> Display for ConsensusCtlSubmitEncodeError<Header>
where
    Header: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            ConsensusCtlSubmitEncodeError::Header { err } => err.fmt(f),
            ConsensusCtlSubmitEncodeError::TooShort => {
                write!(f, "buffer is too short")
            }
        }
    }
}

impl<Header> Display for ConsensusCtlSubmitDecodeError<Header>
where
    Header: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            ConsensusCtlSubmitDecodeError::Header { err } => err.fmt(f),
            ConsensusCtlSubmitDecodeError::Hash { err } => err.fmt(f),
            ConsensusCtlSubmitDecodeError::TooShort => {
                write!(f, "buffer is too short")
            }
        }
    }
}

#[cfg(test)]
use constellation_common::codec::DatagramCodec;
#[cfg(test)]
use constellation_common::hashid::SHA3Algo;

#[cfg(test)]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TestSeal {
    bytes: Vec<u8>
}

#[cfg(test)]
#[derive(Clone)]
pub struct TestSealCodec;

#[cfg(test)]
impl Create for TestSealCodec {
    type Config = ();
    type CreateError = Infallible;

    #[inline]
    fn create(_param: ()) -> Result<Self, Infallible> {
        Ok(TestSealCodec)
    }
}

#[cfg(test)]
impl Encoder<TestSeal> for TestSealCodec {
    type EncodeError = Infallible;

    #[inline]
    fn buf_size(
        &self,
        val: &TestSeal
    ) -> usize {
        val.bytes.len()
    }

    #[inline]
    fn encode(
        &mut self,
        val: &TestSeal,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let len = val.bytes.len();

        buf[..len].copy_from_slice(&val.bytes[..]);

        Ok(len)
    }
}

#[cfg(test)]
impl Decoder<TestSeal> for TestSealCodec {
    type DecodeError = Infallible;

    #[inline]
    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(TestSeal, usize), Self::DecodeError> {
        let bytes = buf[..].to_vec();
        let len = bytes.len();

        Ok((TestSeal { bytes: bytes }, len))
    }
}

#[test]
fn test_submit_header() {
    let header = ConsensusCtlSubmitHeader {
        nhashes: 0x1234567890abcdef
    };
    let mut codec = ConsensusCtlSubmitHeaderCodec::default();
    let mut buf = [0; ConsensusCtlSubmitHeaderCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_round_header() {
    let header = ConsensusCtlRoundHeader {
        round: vec![0x11; 16],
        hashes: vec![
            vec![0x00; 64],
            vec![0x11; 64],
            vec![0x22; 64],
            vec![0x33; 64],
            vec![0x44; 64],
            vec![0x55; 64],
            vec![0x66; 64],
            vec![0x77; 64],
            vec![0x88; 64],
            vec![0x99; 64],
            vec![0xaa; 64],
            vec![0xbb; 64],
            vec![0xcc; 64],
            vec![0xdd; 64],
            vec![0xee; 64],
            vec![0xff; 64],
        ],
        nseals: 0x1234567890abcdef
    };
    let mut codec = ConsensusCtlRoundHeaderCodec::default();
    let mut buf = [0; ConsensusCtlRoundHeaderCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_submit() {
    let mut codec: ConsensusCtlSubmitCodec<SHA3Algo> =
        ConsensusCtlSubmitCodec::create(()).expect("Expected success");
    let submit = ConsensusCtlSubmit {
        hashes: vec![
            codec
                .hash
                .wrap_hashed_bytes(&[0x00; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0x11; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0x22; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0x33; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0x44; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0x55; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0x66; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0x77; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0x88; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0x99; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0xaa; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0xbb; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0xcc; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0xdd; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0xee; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0xff; 64])
                .expect("Expected success"),
        ]
    };
    let len = codec.buf_size(&submit);
    let mut buf = vec![0; len];
    let _ = codec.encode(&submit, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(submit, decoded);
}

#[test]
fn test_round_no_seals() {
    let mut codec: ConsensusCtlRoundCodec<
        _,
        SHA3Algo,
        TestSeal,
        TestSealCodec
    > = ConsensusCtlRoundCodec::create(()).expect("Expected success");
    let round = ConsensusCtlRound {
        round: 0x1234567890abcdef,
        hashes: vec![
            codec
                .hash
                .wrap_hashed_bytes(&[0x00; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0x11; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0x22; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0x33; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0x44; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0x55; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0x66; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0x77; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0x88; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0x99; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0xaa; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0xbb; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0xcc; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0xdd; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0xee; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0xff; 64])
                .expect("Expected success"),
        ],
        seals: None
    };
    let len = codec.buf_size(&round);
    let mut buf = vec![0; len];
    let _ = codec.encode(&round, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(round, decoded);
}

#[test]
fn test_round_seals() {
    let mut codec: ConsensusCtlRoundCodec<
        _,
        SHA3Algo,
        TestSeal,
        TestSealCodec
    > = ConsensusCtlRoundCodec::create(()).expect("Expected success");
    let round = ConsensusCtlRound {
        round: 0x1234567890abcdef,
        hashes: vec![
            codec
                .hash
                .wrap_hashed_bytes(&[0x00; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0x11; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0x22; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0x33; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0x44; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0x55; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0x66; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0x77; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0x88; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0x99; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0xaa; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0xbb; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0xcc; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0xdd; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0xee; 64])
                .expect("Expected success"),
            codec
                .hash
                .wrap_hashed_bytes(&[0xff; 64])
                .expect("Expected success"),
        ],
        seals: Some(vec![
            TestSeal {
                bytes: vec![0, 1, 2]
            },
            TestSeal {
                bytes: vec![3, 4, 5]
            },
            TestSeal {
                bytes: vec![6, 7, 8]
            },
        ])
    };
    let len = codec.buf_size(&round);
    let mut buf = vec![0; len];
    let _ = codec.encode(&round, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(round, decoded);
}
