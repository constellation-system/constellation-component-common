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

use std::array::TryFromSliceError;
use std::convert::Infallible;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;

use constellation_common::codec::per::PERCodec;
use constellation_common::codec::Codec;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::hashid::HashAlgo;
use constellation_common::hashid::HashID;

use crate::generated::xact::XactBatchHeader;
use crate::generated::xact::XactReqHeader;

const XACT_BATCH_HEADER_SIZE: usize = 11;
const XACT_BATCH_HEADER_BITS: usize = XACT_BATCH_HEADER_SIZE * 8;

const XACT_REQ_HEADER_SIZE: usize = 65;
const XACT_REQ_HEADER_HEADER_BITS: usize = XACT_REQ_HEADER_SIZE * 8;

pub type XactReqHeaderPERCodec =
    PERCodec<XactReqHeader, XACT_REQ_HEADER_HEADER_BITS>;

pub type XactBatchHeaderPERCodec =
    PERCodec<XactBatchHeader, XACT_BATCH_HEADER_BITS>;

#[derive(Clone, Debug)]
pub struct XactReq<H>
where
    H: HashID {
    hash: H,
    data: Vec<u8>
}

#[derive(Clone, Debug)]
pub struct XactBatch<H>
where
    H: HashID {
    seqnum: u64,
    reqs: Vec<XactReq<H>>
}

#[derive(Clone)]
pub struct XactBatchCodec<H>
where
    H: HashAlgo,
    H::HashID: Clone {
    req: XactReqHeaderPERCodec,
    batch: XactBatchHeaderPERCodec,
    hash: H
}

#[derive(Debug)]
pub enum XactBatchEncodeError {
    Batch {
        err: <XactBatchHeaderPERCodec as Codec<XactBatchHeader>>::EncodeError
    },
    Req {
        err: <XactReqHeaderPERCodec as Codec<XactReqHeader>>::EncodeError
    },
    TooShort
}

#[derive(Debug)]
pub enum XactBatchDecodeError {
    Batch {
        err: <XactBatchHeaderPERCodec as Codec<XactBatchHeader>>::EncodeError
    },
    Req {
        err: <XactReqHeaderPERCodec as Codec<XactReqHeader>>::EncodeError
    },
    Hash {
        err: TryFromSliceError
    },
    TooShort
}

impl<ID> XactBatch<ID>
where
    ID: HashID
{
    pub fn create<H, I>(
        algo: &H,
        seqnum: u64,
        reqs: I
    ) -> Self
    where
        H: HashAlgo<HashID = ID>,
        I: Iterator<Item = Vec<u8>> {
        let reqs = reqs
            .map(|data| {
                let hash = algo.hash_bytes(&data);

                XactReq {
                    hash: hash,
                    data: data
                }
            })
            .collect();

        XactBatch {
            seqnum: seqnum,
            reqs: reqs
        }
    }

    #[inline]
    fn buf_size(&self) -> usize {
        let datasize: usize = self.reqs.iter().map(|req| req.data.len()).sum();
        let reqsize = self.reqs.len() * XACT_REQ_HEADER_SIZE;

        XACT_BATCH_HEADER_SIZE + reqsize + datasize
    }
}

impl<H> Codec<XactBatch<H::HashID>> for XactBatchCodec<H>
where
    H: HashAlgo + Default,
    H::HashID: Clone
{
    type CreateError = Infallible;
    type DecodeError = XactBatchDecodeError;
    type EncodeError = XactBatchEncodeError;
    type Param = ();

    #[inline]
    fn create(_param: ()) -> Result<Self, Infallible> {
        Ok(Self::default())
    }

    #[inline]
    fn encode_to_vec(
        &mut self,
        val: &XactBatch<H::HashID>
    ) -> Result<Vec<u8>, Self::EncodeError> {
        let mut buf = vec![0; val.buf_size()];

        self.encode(val, &mut buf)?;

        Ok(buf)
    }

    fn encode(
        &mut self,
        val: &XactBatch<H::HashID>,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let metadata = XactBatchHeader {
            seqnum: val.seqnum,
            nreqs: val.reqs.len() as u32
        };
        let mut curr = self
            .batch
            .encode(&metadata, buf)
            .map_err(|err| XactBatchEncodeError::Batch { err: err })?;

        for req in val.reqs.iter() {
            let datalen = req.data.len();
            let header = XactReqHeader {
                hash: req.hash.bytes().to_vec(),
                len: datalen as u64
            };

            curr += self
                .req
                .encode(&header, &mut buf[curr..])
                .map_err(|err| XactBatchEncodeError::Req { err: err })?;

            curr += if curr + datalen <= buf.len() {
                buf[curr..curr + datalen].copy_from_slice(&req.data);

                Ok(datalen)
            } else {
                Err(XactBatchEncodeError::TooShort)
            }?;
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(XactBatch<H::HashID>, usize), Self::DecodeError> {
        let (batch, mut curr) = self
            .batch
            .decode(buf)
            .map_err(|err| XactBatchDecodeError::Batch { err: err })?;
        let nreqs = batch.nreqs;
        let mut reqs = Vec::with_capacity(nreqs as usize);

        for _ in 0..nreqs {
            let (req, nbytes) = self
                .req
                .decode(&buf[curr..])
                .map_err(|err| XactBatchDecodeError::Req { err: err })?;

            curr += nbytes;

            let datalen = req.len as usize;
            let mut data = vec![0; datalen];
            let hash = self
                .hash
                .wrap_hashed_bytes(&req.hash)
                .map_err(|err| XactBatchDecodeError::Hash { err: err })?;

            curr += if curr + datalen <= buf.len() {
                data.copy_from_slice(&buf[curr..curr + datalen]);
                reqs.push(XactReq {
                    hash: hash,
                    data: data
                });

                Ok(datalen)
            } else {
                Err(XactBatchDecodeError::TooShort)
            }?;
        }

        Ok((
            XactBatch {
                seqnum: batch.seqnum,
                reqs: reqs
            },
            curr
        ))
    }
}

impl<H> Default for XactBatchCodec<H>
where
    H: HashAlgo + Default,
    H::HashID: Clone
{
    #[inline]
    fn default() -> Self {
        XactBatchCodec {
            req: XactReqHeaderPERCodec::default(),
            batch: XactBatchHeaderPERCodec::default(),
            hash: H::default()
        }
    }
}

impl ScopedError for XactBatchEncodeError {
    #[inline]
    fn scope(&self) -> ErrorScope {
        ErrorScope::Msg
    }
}

impl ScopedError for XactBatchDecodeError {
    #[inline]
    fn scope(&self) -> ErrorScope {
        ErrorScope::Msg
    }
}

impl Display for XactBatchEncodeError {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            XactBatchEncodeError::Batch { err } => err.fmt(f),
            XactBatchEncodeError::Req { err } => err.fmt(f),
            XactBatchEncodeError::TooShort => {
                write!(f, "output buffer is too short")
            }
        }
    }
}

impl Display for XactBatchDecodeError {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            XactBatchDecodeError::Batch { err } => err.fmt(f),
            XactBatchDecodeError::Req { err } => err.fmt(f),
            XactBatchDecodeError::Hash { err } => err.fmt(f),
            XactBatchDecodeError::TooShort => {
                write!(f, "input buffer is too short")
            }
        }
    }
}
