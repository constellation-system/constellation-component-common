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
use std::iter::once;
use std::marker::PhantomData;

use constellation_common::codec::per::PERCodec;
use constellation_common::codec::Codec;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::hashid::HashAlgo;
use constellation_common::hashid::HashID;
use constellation_common::version::Version;
use uuid::Uuid;

use crate::generated::xact::XactBatchHeader;
use crate::generated::xact::XactEffectsHeader;
use crate::generated::xact::XactReqHeader;

const XACT_BATCH_HEADER_SIZE: usize = 11;
const XACT_BATCH_HEADER_BITS: usize = XACT_BATCH_HEADER_SIZE * 8;

const XACT_REQ_HEADER_SIZE: usize = 98;
const XACT_REQ_HEADER_BITS: usize = XACT_REQ_HEADER_SIZE * 8;

type XactReqHeaderPERCodec = PERCodec<XactReqHeader, XACT_REQ_HEADER_BITS>;

type XactBatchHeaderPERCodec =
    PERCodec<XactBatchHeader, XACT_BATCH_HEADER_BITS>;

#[derive(Clone, Debug)]
pub struct XactEffects<E> {
    /// Whether or not this is a hard effect.
    hard: bool,
    /// Raw data describing the effect, or `None` if there is none.
    effects: Option<E>
}

#[derive(Clone, Debug)]
pub struct XactHashReq<H, T, E>
where
    H: HashID {
    hash: H,
    payload: T,
    class: Uuid,
    instance: Option<u64>,
    effects: XactEffects<E>,
    version: Version
}

#[derive(Clone, Debug)]
pub struct XactReq<T, E> {
    payload: T,
    class: Uuid,
    instance: Option<u64>,
    effects: XactEffects<E>,
    version: Version
}

#[derive(Clone, Debug)]
pub struct XactBatch<R> {
    seqnum: u64,
    reqs: Vec<R>
}

/// A codec for [XactBatch]es that will produce hashes for the
/// payload.
///
/// This will only encode or decode [XactReq]s, which do not have a
/// hash.  Encoding operations will compute the hash.
///
/// This is typically used by clients.
#[derive(Clone)]
pub struct XactBatchHashCodec<H, Payload, Effect, PayloadCodec, EffectCodec>
where
    H: HashAlgo,
    H::HashID: Clone,
    PayloadCodec: Codec<Payload>,
    EffectCodec: Codec<Effect> {
    payload: PhantomData<Payload>,
    effect: PhantomData<Effect>,
    req_codec: XactReqHeaderPERCodec,
    batch_codec: XactBatchHeaderPERCodec,
    payload_codec: PayloadCodec,
    effect_codec: EffectCodec,
    hash: H
}

/// A codec for [XactBatch]es that will not produce hashes for the
/// payload, but will decode it.
///
/// This will only encode or decode [XactHashReq]s.  Encoding
/// operations will use the hash that is present.
///
/// This is typically used by processors.
#[derive(Clone)]
pub struct XactBatchCodec<H, Payload, Effect, PayloadCodec, EffectCodec>
where
    H: HashAlgo,
    H::HashID: Clone,
    PayloadCodec: Codec<Payload>,
    EffectCodec: Codec<Effect> {
    payload: PhantomData<Payload>,
    effect: PhantomData<Effect>,
    req_codec: XactReqHeaderPERCodec,
    batch_codec: XactBatchHeaderPERCodec,
    payload_codec: PayloadCodec,
    effect_codec: EffectCodec,
    hash: H
}

/// A codec for [XactBatch]es that will not produce hashes or decode
/// the payload.
///
/// This will only encode or decode [XactHashReq]s.  Payloads and
/// effects will be left as `Vec<u8>`s.  Hashes will be left as-is.
///
/// This is typically used by peers.
#[derive(Clone)]
pub struct XactBatchBlobCodec<H>
where
    H: HashAlgo,
    H::HashID: Clone {
    req_codec: XactReqHeaderPERCodec,
    batch_codec: XactBatchHeaderPERCodec,
    hash: H
}

#[derive(Debug)]
pub enum XactBatchCodecCreateError<Payload, Effect> {
    Payload { err: Payload },
    Effect { err: Effect }
}

#[derive(Debug)]
pub enum XactBatchEncodeError<Payload, Effects> {
    Payload {
        err: Payload
    },
    Effects {
        err: Effects
    },
    Batch {
        err: <XactBatchHeaderPERCodec as Codec<XactBatchHeader>>::EncodeError
    },
    Req {
        err: <XactReqHeaderPERCodec as Codec<XactReqHeader>>::EncodeError
    },
    TooShort
}

#[derive(Debug)]
pub enum XactBatchDecodeError<Payload, Effects> {
    Payload {
        err: Payload
    },
    Effects {
        err: Effects
    },
    Batch {
        err: <XactBatchHeaderPERCodec as Codec<XactBatchHeader>>::EncodeError
    },
    Req {
        err: <XactReqHeaderPERCodec as Codec<XactReqHeader>>::EncodeError
    },
    Hash {
        err: TryFromSliceError
    },
    UUID {
        err: uuid::Error
    },
    TooShort
}

impl<E> Default for XactEffects<E> {
    #[inline]
    fn default() -> Self {
        XactEffects {
            hard: false,
            effects: None
        }
    }
}

impl<E> XactEffects<E> {
    /// Soft effect constranit for no effects.
    ///
    /// This states that the transaction should run without effects,
    /// but will not fail if it does cause an effect.
    #[inline]
    pub fn soft_none() -> Self {
        XactEffects {
            effects: None,
            hard: false
        }
    }

    /// Hard effect constraint for no effects.
    ///
    /// This will cause the transaction to fail if it causes any
    /// effects.
    #[inline]
    pub fn hard_none() -> Self {
        XactEffects {
            effects: None,
            hard: true
        }
    }

    /// Hard effect constraint.
    ///
    /// This will cause the transaction to fail if it causes any
    /// effects beyond what is described by the data.
    #[inline]
    pub fn hard(effects: E) -> Self {
        XactEffects {
            effects: Some(effects),
            hard: true
        }
    }

    /// Soft effect constraint.
    ///
    /// This indicates the transaction may cause some effects, but
    /// will not fail if it causes effects beyond what is described by
    /// the data.
    #[inline]
    pub fn soft(effects: E) -> Self {
        XactEffects {
            effects: Some(effects),
            hard: false
        }
    }
}

impl<R> XactBatch<R> {
    pub fn new(
        seqnum: u64,
        reqs: Vec<R>
    ) -> Self {
        XactBatch {
            seqnum: seqnum,
            reqs: reqs
        }
    }

    #[inline]
    pub fn take(self) -> (u64, Vec<R>) {
        (self.seqnum, self.reqs)
    }
}

impl<H, T, E> XactHashReq<H, T, E>
where
    H: HashID
{
    #[inline]
    pub fn hash(&self) -> &H {
        &self.hash
    }

    #[inline]
    pub fn class(&self) -> &Uuid {
        &self.class
    }

    #[inline]
    pub fn version(&self) -> &Version {
        &self.version
    }

    #[inline]
    pub fn instance(&self) -> Option<u64> {
        self.instance
    }

    #[inline]
    pub fn effects(&self) -> &XactEffects<E> {
        &self.effects
    }

    #[inline]
    pub fn payload(&self) -> &T {
        &self.payload
    }

    #[inline]
    pub fn take(self) -> (H, Uuid, Version, Option<u64>, XactEffects<E>, T) {
        (
            self.hash,
            self.class,
            self.version,
            self.instance,
            self.effects,
            self.payload
        )
    }
}

impl<T, E> XactReq<T, E> {
    #[inline]
    pub fn new(
        payload: T,
        class: Uuid,
        instance: Option<u64>,
        effects: XactEffects<E>,
        version: Version
    ) -> Self {
        XactReq {
            payload: payload,
            class: class,
            version: version,
            instance: instance,
            effects: effects
        }
    }

    #[inline]
    pub fn class(&self) -> &Uuid {
        &self.class
    }

    #[inline]
    pub fn version(&self) -> &Version {
        &self.version
    }

    #[inline]
    pub fn instance(&self) -> Option<u64> {
        self.instance
    }

    #[inline]
    pub fn effects(&self) -> &XactEffects<E> {
        &self.effects
    }

    #[inline]
    pub fn payload(&self) -> &T {
        &self.payload
    }

    #[inline]
    pub fn take(self) -> (Uuid, Version, Option<u64>, XactEffects<E>, T) {
        (
            self.class,
            self.version,
            self.instance,
            self.effects,
            self.payload
        )
    }
}

impl<H, Payload, Effect, PayloadCodec, EffectCodec>
    Codec<XactBatch<XactReq<Payload, Effect>>>
    for XactBatchHashCodec<H, Payload, Effect, PayloadCodec, EffectCodec>
where
    H: Default + HashAlgo,
    H::HashID: Clone,
    PayloadCodec: Codec<Payload>,
    EffectCodec: Codec<Effect>
{
    type CreateError = XactBatchCodecCreateError<
        PayloadCodec::CreateError,
        EffectCodec::CreateError
    >;
    type DecodeError = XactBatchDecodeError<
        PayloadCodec::DecodeError,
        EffectCodec::DecodeError
    >;
    type EncodeError = XactBatchEncodeError<
        PayloadCodec::EncodeError,
        EffectCodec::EncodeError
    >;
    type Param = (PayloadCodec::Param, EffectCodec::Param);

    #[inline]
    fn create(param: Self::Param) -> Result<Self, Self::CreateError> {
        let (payload, effect) = param;
        let payload_codec = PayloadCodec::create(payload)
            .map_err(|err| XactBatchCodecCreateError::Payload { err: err })?;
        let effect_codec = EffectCodec::create(effect)
            .map_err(|err| XactBatchCodecCreateError::Effect { err: err })?;

        Ok(XactBatchHashCodec {
            payload: PhantomData,
            effect: PhantomData,
            batch_codec: XactBatchHeaderPERCodec::default(),
            req_codec: XactReqHeaderPERCodec::default(),
            payload_codec: payload_codec,
            effect_codec: effect_codec,
            hash: H::default()
        })
    }

    #[inline]
    fn buf_size(
        &self,
        val: &XactBatch<XactReq<Payload, Effect>>
    ) -> usize {
        let reqs_len: usize = val
            .reqs
            .iter()
            .map(|req| {
                let hash = self.hash.hash_len();
                let payload = self.payload_codec.buf_size(&req.payload);
                let effects = match &req.effects.effects {
                    Some(effects) => self.effect_codec.buf_size(effects) + 2,
                    None => 2
                };
                let class = 64;
                let instance = 10;
                let version = 3;

                hash + payload + effects + class + instance + version
            })
            .sum();

        reqs_len + 18
    }

    fn encode(
        &mut self,
        val: &XactBatch<XactReq<Payload, Effect>>,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let metadata = XactBatchHeader {
            seqnum: val.seqnum,
            nreqs: val.reqs.len() as u32
        };
        let mut curr = self
            .batch_codec
            .encode(&metadata, buf)
            .map_err(|err| XactBatchEncodeError::Batch { err: err })?;

        for req in val.reqs.iter() {
            // XXX find a way to prevent copying here.
            let payload = self
                .payload_codec
                .encode_to_vec(&req.payload)
                .map_err(|err| XactBatchEncodeError::Payload { err: err })?;
            let payload_len = payload.len();

            match &req.effects.effects {
                Some(effects) => {
                    let effects =
                        self.effect_codec.encode_to_vec(effects).map_err(
                            |err| XactBatchEncodeError::Effects { err: err }
                        )?;
                    let effects_len = effects.len();
                    let effects_header = XactEffectsHeader {
                        len: Some(effects_len as u64),
                        hard: req.effects.hard
                    };
                    let mut header = XactReqHeader {
                        hash: vec![0; self.hash.hash_len()],
                        version: req.version.clone(),
                        domain: req.class.into(),
                        effects: effects_header,
                        instance: req.instance,
                        len: payload_len as u64
                    };
                    let offset = curr;
                    let algo = H::default();

                    curr += self
                        .req_codec
                        .encode(&header, &mut buf[curr..])
                        .map_err(|err| XactBatchEncodeError::Req {
                            err: err
                        })?;

                    let hashid = algo.hash_bytes(once(&buf[offset..curr]));

                    header.hash = hashid.bytes().to_vec();
                    curr += self
                        .req_codec
                        .encode(&header, &mut buf[curr..])
                        .map_err(|err| XactBatchEncodeError::Req {
                            err: err
                        })?;
                    curr += if curr + effects_len <= buf.len() {
                        buf[curr..curr + effects_len].copy_from_slice(&effects);

                        Ok(effects_len)
                    } else {
                        Err(XactBatchEncodeError::TooShort)
                    }?;
                }
                None => {
                    let effects_header = XactEffectsHeader {
                        hard: req.effects.hard,
                        len: None
                    };
                    let mut header = XactReqHeader {
                        hash: vec![0; self.hash.hash_len()],
                        version: req.version.clone(),
                        domain: req.class.into(),
                        effects: effects_header,
                        instance: req.instance,
                        len: payload_len as u64
                    };
                    let offset = curr;
                    let algo = H::default();

                    curr += self
                        .req_codec
                        .encode(&header, &mut buf[curr..])
                        .map_err(|err| XactBatchEncodeError::Req {
                            err: err
                        })?;

                    let hashid = algo.hash_bytes(once(&buf[offset..curr]));

                    header.hash = hashid.bytes().to_vec();
                    curr += self
                        .req_codec
                        .encode(&header, &mut buf[curr..])
                        .map_err(|err| XactBatchEncodeError::Req {
                            err: err
                        })?;
                }
            }

            curr += if curr + payload_len <= buf.len() {
                buf[curr..curr + payload_len].copy_from_slice(&payload);

                Ok(payload_len)
            } else {
                Err(XactBatchEncodeError::TooShort)
            }?;
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(XactBatch<XactReq<Payload, Effect>>, usize), Self::DecodeError>
    {
        let (batch, mut curr) = self
            .batch_codec
            .decode(buf)
            .map_err(|err| XactBatchDecodeError::Batch { err: err })?;
        let nreqs = batch.nreqs;
        let mut reqs = Vec::with_capacity(nreqs as usize);

        for _ in 0..nreqs {
            let (req, nbytes) = self
                .req_codec
                .decode(&buf[curr..])
                .map_err(|err| XactBatchDecodeError::Req { err: err })?;

            curr += nbytes;

            let datalen = req.len as usize;
            let class = Uuid::from_slice(&req.domain)
                .map_err(|err| XactBatchDecodeError::UUID { err: err })?;
            let effects = match req.effects.len {
                Some(len) => {
                    if curr + len as usize <= buf.len() {
                        let (effects, _) = self
                            .effect_codec
                            .decode(&buf[curr..curr + len as usize])
                            .map_err(|err| XactBatchDecodeError::Effects {
                                err: err
                            })?;

                        curr += len as usize;

                        Ok(Some(effects))
                    } else {
                        Err(XactBatchDecodeError::TooShort)
                    }
                }
                None => Ok(None)
            }?;
            let effects = XactEffects {
                hard: req.effects.hard,
                effects: effects
            };

            curr += if curr + datalen <= buf.len() {
                let (payload, _) = self
                    .payload_codec
                    .decode(&buf[curr..curr + datalen])
                    .map_err(|err| XactBatchDecodeError::Payload {
                        err: err
                    })?;

                reqs.push(XactReq {
                    instance: req.instance,
                    version: req.version,
                    effects: effects,
                    payload: payload,
                    class: class
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

impl<H, Payload, Effect, PayloadCodec, EffectCodec>
    Codec<XactBatch<XactHashReq<H::HashID, Payload, Effect>>>
    for XactBatchCodec<H, Payload, Effect, PayloadCodec, EffectCodec>
where
    H: Default + HashAlgo,
    H::HashID: Clone,
    PayloadCodec: Codec<Payload>,
    EffectCodec: Codec<Effect>
{
    type CreateError = XactBatchCodecCreateError<
        PayloadCodec::CreateError,
        EffectCodec::CreateError
    >;
    type DecodeError = XactBatchDecodeError<
        PayloadCodec::DecodeError,
        EffectCodec::DecodeError
    >;
    type EncodeError = XactBatchEncodeError<
        PayloadCodec::EncodeError,
        EffectCodec::EncodeError
    >;
    type Param = (PayloadCodec::Param, EffectCodec::Param);

    #[inline]
    fn create(param: Self::Param) -> Result<Self, Self::CreateError> {
        let (payload, effect) = param;
        let payload_codec = PayloadCodec::create(payload)
            .map_err(|err| XactBatchCodecCreateError::Payload { err: err })?;
        let effect_codec = EffectCodec::create(effect)
            .map_err(|err| XactBatchCodecCreateError::Effect { err: err })?;

        Ok(XactBatchCodec {
            payload: PhantomData,
            effect: PhantomData,
            batch_codec: XactBatchHeaderPERCodec::default(),
            req_codec: XactReqHeaderPERCodec::default(),
            payload_codec: payload_codec,
            effect_codec: effect_codec,
            hash: H::default()
        })
    }

    #[inline]
    fn buf_size(
        &self,
        val: &XactBatch<XactHashReq<H::HashID, Payload, Effect>>
    ) -> usize {
        let reqs_len: usize = val
            .reqs
            .iter()
            .map(|req| {
                let hash = req.hash.hash_len();
                let payload = self.payload_codec.buf_size(&req.payload);
                let effects = match &req.effects.effects {
                    Some(effects) => self.effect_codec.buf_size(effects) + 2,
                    None => 2
                };
                let class = 64;
                let instance = 10;
                let version = 3;

                hash + payload + effects + class + instance + version
            })
            .sum();

        reqs_len + 18
    }

    fn encode(
        &mut self,
        val: &XactBatch<XactHashReq<H::HashID, Payload, Effect>>,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let metadata = XactBatchHeader {
            seqnum: val.seqnum,
            nreqs: val.reqs.len() as u32
        };
        let mut curr = self
            .batch_codec
            .encode(&metadata, buf)
            .map_err(|err| XactBatchEncodeError::Batch { err: err })?;

        for req in val.reqs.iter() {
            // XXX find a way to prevent copying here.
            let payload = self
                .payload_codec
                .encode_to_vec(&req.payload)
                .map_err(|err| XactBatchEncodeError::Payload { err: err })?;
            let payload_len = payload.len();

            match &req.effects.effects {
                Some(effects) => {
                    let effects =
                        self.effect_codec.encode_to_vec(effects).map_err(
                            |err| XactBatchEncodeError::Effects { err: err }
                        )?;
                    let effects_len = effects.len();
                    let effects_header = XactEffectsHeader {
                        len: Some(effects_len as u64),
                        hard: req.effects.hard
                    };
                    let header = XactReqHeader {
                        hash: req.hash.bytes().to_vec(),
                        version: req.version.clone(),
                        domain: req.class.into(),
                        effects: effects_header,
                        instance: req.instance,
                        len: payload_len as u64
                    };

                    curr += self
                        .req_codec
                        .encode(&header, &mut buf[curr..])
                        .map_err(|err| XactBatchEncodeError::Req {
                            err: err
                        })?;
                    curr += if curr + effects_len <= buf.len() {
                        buf[curr..curr + effects_len].copy_from_slice(&effects);

                        Ok(effects_len)
                    } else {
                        Err(XactBatchEncodeError::TooShort)
                    }?;
                }
                None => {
                    let effects_header = XactEffectsHeader {
                        hard: req.effects.hard,
                        len: None
                    };
                    let header = XactReqHeader {
                        hash: req.hash.bytes().to_vec(),
                        version: req.version.clone(),
                        domain: req.class.into(),
                        effects: effects_header,
                        instance: req.instance,
                        len: payload_len as u64
                    };

                    curr += self
                        .req_codec
                        .encode(&header, &mut buf[curr..])
                        .map_err(|err| XactBatchEncodeError::Req {
                            err: err
                        })?;
                }
            }

            curr += if curr + payload_len <= buf.len() {
                buf[curr..curr + payload_len].copy_from_slice(&payload);

                Ok(payload_len)
            } else {
                Err(XactBatchEncodeError::TooShort)
            }?;
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<
        (XactBatch<XactHashReq<H::HashID, Payload, Effect>>, usize),
        Self::DecodeError
    > {
        let (batch, mut curr) = self
            .batch_codec
            .decode(buf)
            .map_err(|err| XactBatchDecodeError::Batch { err: err })?;
        let nreqs = batch.nreqs;
        let mut reqs = Vec::with_capacity(nreqs as usize);

        for _ in 0..nreqs {
            let (req, nbytes) = self
                .req_codec
                .decode(&buf[curr..])
                .map_err(|err| XactBatchDecodeError::Req { err: err })?;

            curr += nbytes;

            let datalen = req.len as usize;
            let hash = self
                .hash
                .wrap_hashed_bytes(&req.hash)
                .map_err(|err| XactBatchDecodeError::Hash { err: err })?;
            let class = Uuid::from_slice(&req.domain)
                .map_err(|err| XactBatchDecodeError::UUID { err: err })?;
            let effects = match req.effects.len {
                Some(len) => {
                    if curr + len as usize <= buf.len() {
                        let (effects, _) = self
                            .effect_codec
                            .decode(&buf[curr..curr + len as usize])
                            .map_err(|err| XactBatchDecodeError::Effects {
                                err: err
                            })?;

                        curr += len as usize;

                        Ok(Some(effects))
                    } else {
                        Err(XactBatchDecodeError::TooShort)
                    }
                }
                None => Ok(None)
            }?;
            let effects = XactEffects {
                hard: req.effects.hard,
                effects: effects
            };

            curr += if curr + datalen <= buf.len() {
                let (payload, _) = self
                    .payload_codec
                    .decode(&buf[curr..curr + datalen])
                    .map_err(|err| XactBatchDecodeError::Payload {
                        err: err
                    })?;

                reqs.push(XactHashReq {
                    instance: req.instance,
                    version: req.version,
                    effects: effects,
                    payload: payload,
                    class: class,
                    hash: hash
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

impl<H> Codec<XactBatch<XactHashReq<H::HashID, Vec<u8>, Vec<u8>>>>
    for XactBatchBlobCodec<H>
where
    H: HashAlgo + Default,
    H::HashID: Clone
{
    type CreateError = Infallible;
    type DecodeError = XactBatchDecodeError<Infallible, Infallible>;
    type EncodeError = XactBatchEncodeError<Infallible, Infallible>;
    type Param = ();

    #[inline]
    fn create(_param: ()) -> Result<Self, Infallible> {
        Ok(Self::default())
    }

    #[inline]
    fn buf_size(
        &self,
        val: &XactBatch<XactHashReq<H::HashID, Vec<u8>, Vec<u8>>>
    ) -> usize {
        let reqs_len: usize = val
            .reqs
            .iter()
            .map(|req| {
                let hash = req.hash.hash_len();
                let payload = req.payload.len();
                let effects = match &req.effects.effects {
                    Some(effects) => effects.len() + 2,
                    None => 2
                };
                let class = 64;
                let instance = 10;
                let version = 3;

                hash + payload + effects + class + instance + version
            })
            .sum();

        reqs_len + 18
    }

    fn encode(
        &mut self,
        val: &XactBatch<XactHashReq<H::HashID, Vec<u8>, Vec<u8>>>,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let metadata = XactBatchHeader {
            seqnum: val.seqnum,
            nreqs: val.reqs.len() as u32
        };
        let mut curr = self
            .batch_codec
            .encode(&metadata, buf)
            .map_err(|err| XactBatchEncodeError::Batch { err: err })?;

        for req in val.reqs.iter() {
            let payload_len = req.payload.len();

            match &req.effects.effects {
                Some(data) => {
                    let effects_len = data.len();
                    let effects_header = XactEffectsHeader {
                        len: Some(effects_len as u64),
                        hard: req.effects.hard
                    };
                    let header = XactReqHeader {
                        hash: req.hash.bytes().to_vec(),
                        version: req.version.clone(),
                        domain: req.class.into(),
                        effects: effects_header,
                        instance: req.instance,
                        len: payload_len as u64
                    };

                    curr += self
                        .req_codec
                        .encode(&header, &mut buf[curr..])
                        .map_err(|err| XactBatchEncodeError::Req {
                            err: err
                        })?;
                    curr += if curr + effects_len <= buf.len() {
                        buf[curr..curr + effects_len].copy_from_slice(data);

                        Ok(effects_len)
                    } else {
                        Err(XactBatchEncodeError::TooShort)
                    }?;
                }
                None => {
                    let effects_header = XactEffectsHeader {
                        hard: req.effects.hard,
                        len: None
                    };
                    let header = XactReqHeader {
                        hash: req.hash.bytes().to_vec(),
                        version: req.version.clone(),
                        domain: req.class.into(),
                        effects: effects_header,
                        instance: req.instance,
                        len: payload_len as u64
                    };

                    curr += self
                        .req_codec
                        .encode(&header, &mut buf[curr..])
                        .map_err(|err| XactBatchEncodeError::Req {
                            err: err
                        })?;
                }
            }

            curr += if curr + payload_len <= buf.len() {
                buf[curr..curr + payload_len].copy_from_slice(&req.payload);

                Ok(payload_len)
            } else {
                Err(XactBatchEncodeError::TooShort)
            }?;
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<
        (XactBatch<XactHashReq<H::HashID, Vec<u8>, Vec<u8>>>, usize),
        Self::DecodeError
    > {
        let (batch, mut curr) = self
            .batch_codec
            .decode(buf)
            .map_err(|err| XactBatchDecodeError::Batch { err: err })?;
        let nreqs = batch.nreqs;
        let mut reqs = Vec::with_capacity(nreqs as usize);

        for _ in 0..nreqs {
            let (req, nbytes) = self
                .req_codec
                .decode(&buf[curr..])
                .map_err(|err| XactBatchDecodeError::Req { err: err })?;

            curr += nbytes;

            let datalen = req.len as usize;
            let hash = self
                .hash
                .wrap_hashed_bytes(&req.hash)
                .map_err(|err| XactBatchDecodeError::Hash { err: err })?;
            let class = Uuid::from_slice(&req.domain)
                .map_err(|err| XactBatchDecodeError::UUID { err: err })?;
            let effects_data = match req.effects.len {
                Some(len) => {
                    if curr + len as usize <= buf.len() {
                        let data = buf[curr..curr + len as usize].to_vec();

                        curr += len as usize;

                        Ok(Some(data))
                    } else {
                        Err(XactBatchDecodeError::TooShort)
                    }
                }
                None => Ok(None)
            }?;
            let effects = XactEffects {
                hard: req.effects.hard,
                effects: effects_data
            };

            curr += if curr + datalen <= buf.len() {
                let payload = buf[curr..curr + datalen].to_vec();

                reqs.push(XactHashReq {
                    instance: req.instance,
                    version: req.version,
                    effects: effects,
                    payload: payload,
                    class: class,
                    hash: hash
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

impl<H> Default for XactBatchBlobCodec<H>
where
    H: HashAlgo + Default,
    H::HashID: Clone
{
    #[inline]
    fn default() -> Self {
        XactBatchBlobCodec {
            req_codec: XactReqHeaderPERCodec::default(),
            batch_codec: XactBatchHeaderPERCodec::default(),
            hash: H::default()
        }
    }
}

impl<Payload, Effect> ScopedError for XactBatchCodecCreateError<Payload, Effect>
where
    Payload: ScopedError,
    Effect: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            XactBatchCodecCreateError::Payload { err } => err.scope(),
            XactBatchCodecCreateError::Effect { err } => err.scope()
        }
    }
}

impl<Payload, Effects> ScopedError for XactBatchEncodeError<Payload, Effects>
where
    Payload: ScopedError,
    Effects: ScopedError
{
    #[inline]
    fn scope(&self) -> ErrorScope {
        match self {
            XactBatchEncodeError::Payload { err } => err.scope(),
            XactBatchEncodeError::Effects { err } => err.scope(),
            XactBatchEncodeError::Batch { .. } |
            XactBatchEncodeError::Req { .. } |
            XactBatchEncodeError::TooShort => ErrorScope::Unrecoverable
        }
    }
}

impl<Payload, Effects> ScopedError for XactBatchDecodeError<Payload, Effects>
where
    Payload: ScopedError,
    Effects: ScopedError
{
    #[inline]
    fn scope(&self) -> ErrorScope {
        match self {
            XactBatchDecodeError::Payload { err } => err.scope(),
            XactBatchDecodeError::Effects { err } => err.scope(),
            XactBatchDecodeError::Batch { .. } |
            XactBatchDecodeError::Req { .. } |
            XactBatchDecodeError::Hash { .. } |
            XactBatchDecodeError::UUID { .. } |
            XactBatchDecodeError::TooShort => ErrorScope::Unrecoverable
        }
    }
}

impl<Payload, Effect> Display for XactBatchCodecCreateError<Payload, Effect>
where
    Payload: Display,
    Effect: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            XactBatchCodecCreateError::Payload { err } => err.fmt(f),
            XactBatchCodecCreateError::Effect { err } => err.fmt(f)
        }
    }
}

impl<Payload, Effects> Display for XactBatchEncodeError<Payload, Effects>
where
    Payload: Display,
    Effects: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            XactBatchEncodeError::Payload { err } => err.fmt(f),
            XactBatchEncodeError::Effects { err } => err.fmt(f),
            XactBatchEncodeError::Batch { err } => err.fmt(f),
            XactBatchEncodeError::Req { err } => err.fmt(f),
            XactBatchEncodeError::TooShort => {
                write!(f, "output buffer is too short")
            }
        }
    }
}

impl<Payload, Effects> Display for XactBatchDecodeError<Payload, Effects>
where
    Payload: Display,
    Effects: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            XactBatchDecodeError::Payload { err } => err.fmt(f),
            XactBatchDecodeError::Effects { err } => err.fmt(f),
            XactBatchDecodeError::Batch { err } => err.fmt(f),
            XactBatchDecodeError::Req { err } => err.fmt(f),
            XactBatchDecodeError::Hash { err } => err.fmt(f),
            XactBatchDecodeError::UUID { err } => err.fmt(f),
            XactBatchDecodeError::TooShort => {
                write!(f, "input buffer is too short")
            }
        }
    }
}
