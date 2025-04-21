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
use std::convert::TryInto;
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
use crate::generated::xact::XactCommittedReqHeader;
use crate::generated::xact::XactEffectsHeader;
use crate::generated::xact::XactHardNone;
use crate::generated::xact::XactLinPointHeader;
use crate::generated::xact::XactUncommittedEffectsHeader;
use crate::generated::xact::XactUncommittedReqHeader;

const XACT_UNCOMMITTED_REQ_HEADER_SIZE: usize = 55;
const XACT_UNCOMMITTED_REQ_HEADER_BITS: usize =
    XACT_UNCOMMITTED_REQ_HEADER_SIZE * 8;

const XACT_COMMITTED_REQ_HEADER_SIZE: usize = 48;
const XACT_COMMITTED_REQ_HEADER_BITS: usize =
    XACT_COMMITTED_REQ_HEADER_SIZE * 8;

type XactUncommittedReqHeaderPERCodec =
    PERCodec<XactUncommittedReqHeader, XACT_UNCOMMITTED_REQ_HEADER_BITS>;

type XactCommittedReqHeaderPERCodec =
    PERCodec<XactCommittedReqHeader, XACT_COMMITTED_REQ_HEADER_BITS>;

/// A point in logical time (linearization point) at which a
/// transaction occurs.
///
/// Logical time at the consensus level consists of rounds, each of
/// which is a batch having some number of indexes.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct XactLinPoint<RoundID>
where RoundID: Clone + From<u128> + Into<u128> {
    /// ID of the round in which this takes place.
    round: RoundID,
    /// Index within the round.
    idx: u8
}

/// Valid combinations of effects for an uncommitted request.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum XactEffects<RoundID, Effects>
where RoundID: Clone + From<u128> + Into<u128> {
    /// Effect constraints.
    Effects {
        /// Whether or not this is a hard effect.
        hard: bool,
        /// Raw data describing the effect, or `None` if there is none.
        effects: Effects
    },
    /// Hard no-effect constraint.
    HardNone {
        /// Linearization point, if provided.
        when: Option<XactLinPoint<RoundID>>
    },
    /// Soft no-effect constraint.
    SoftNone
}

/// Description of effects for a committed request.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct XactCommittedEffects<Effects> {
    /// Whether or not this is a hard effect.
    hard: bool,
    /// Raw data describing the effect, or `None` if there is none.
    effects: Effects
}

/// Uncommitted request with its hash.
///
/// This version is typically used by receivers of requests, where the
/// hash was already computed.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct XactUncommittedHashReq<RoundID, H, Payload, Effects>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: HashID {
    /// Hash of the entire request.
    ///
    /// This is computed by encoding the entire request with this as
    /// zero data, then hashing the encoded data.
    hash: H,
    /// Class of transactions.
    class: Uuid,
    /// Version of the transaction class.
    version: Version,
    /// Instance of the transaction class, if applicable.
    instance: Option<u64>,
    /// Effects for the transaction.
    effects: XactEffects<RoundID, Effects>,
    /// The request payload.
    payload: Payload,
}

/// Uncommitted request with no hash.
///
/// This version is typically used by clients or other originators of
/// requests, who will compute the hash as part of encoding.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct XactUncommittedReq<RoundID, Payload, Effects>
where RoundID: Clone + From<u128> + Into<u128> {
    /// Class of transactions.
    class: Uuid,
    /// Version of the transaction class.
    version: Version,
    /// Instance of the transaction class, if applicable.
    instance: Option<u64>,
    /// Effects for the transaction.
    effects: XactEffects<RoundID, Effects>,
    /// The request payload.
    payload: Payload,
}

/// Committed request.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct XactCommittedReq<Payload, Effects> {
    /// Class of transactions.
    class: Uuid,
    /// Version of the transaction class.
    version: Version,
    /// Instance of the transaction class, if applicable.
    instance: Option<u64>,
    /// Index within the transaction.
    idx: usize,
    /// Effects for the transaction.
    effects: Option<XactCommittedEffects<Effects>>,
    /// The request payload.
    payload: Payload,
}

/// A codec for [XactUncommittedReq]s that does not produce hashes upon
/// decoding.
///
/// This will only encode or decode [XactUncommittedReq]s, which do not
/// have a hash. This is typically used by clients.
#[derive(Clone)]
pub struct XactUncommittedReqCodec<RoundID, Payload, Effect,
                                   PayloadCodec, EffectCodec>
where
    RoundID: Clone + From<u128> + Into<u128>,
    PayloadCodec: Codec<Payload>,
    EffectCodec: Codec<Effect> {
    payload: PhantomData<Payload>,
    effect: PhantomData<Effect>,
    round: PhantomData<RoundID>,
    req_codec: XactUncommittedReqHeaderPERCodec,
    payload_codec: PayloadCodec,
    effect_codec: EffectCodec,
}

/// A codec for [XactUncommittedHashReq]s that produces hashes upon
/// decoding.
///
/// This will only encode or decode [XactUncommittedHashReq]s, which
/// have a hash. This is typically used by processors.
#[derive(Clone)]
pub struct XactUncommittedReqHashCodec<H, RoundID, Payload, Effect,
                                       PayloadCodec, EffectCodec>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: HashAlgo,
    H::HashID: Clone,
    PayloadCodec: Codec<Payload>,
    EffectCodec: Codec<Effect> {
    payload: PhantomData<Payload>,
    effect: PhantomData<Effect>,
    round: PhantomData<RoundID>,
    req_codec: XactUncommittedReqHeaderPERCodec,
    payload_codec: PayloadCodec,
    effect_codec: EffectCodec,
    hash: H
}

/// A codec for [XactUncommittedHashReq]s that produces hashes upon
/// decoding, but does not decode request effects or payloads
///
/// This will only encode or decode [XactUncommittedHashReq]s, which
/// have a hash, but will only allow `Vec<u8>` as the type for
/// payloads and effects. This is typically used by peers.
#[derive(Clone)]
pub struct XactUncommittedReqBlobCodec<H, RoundID>
where
    H: HashAlgo,
    H::HashID: Clone,
    RoundID: Clone + From<u128> + Into<u128>
{
    round: PhantomData<RoundID>,
    req_codec: XactUncommittedReqHeaderPERCodec,
    hash: H
}

/// A codec for [XactCommittedReq]s that decodes the payload and effects.
///
/// This is typically used by clients and processors.
#[derive(Clone)]
pub struct XactCommittedReqCodec<Payload, Effect, PayloadCodec, EffectCodec>
where
    PayloadCodec: Codec<Payload>,
    EffectCodec: Codec<Effect> {
    payload: PhantomData<Payload>,
    effect: PhantomData<Effect>,
    req_codec: XactCommittedReqHeaderPERCodec,
    payload_codec: PayloadCodec,
    effect_codec: EffectCodec,
}

/// A codec for [XactCommittedReq]s that does not decode the payload
/// and effects.
///
/// This is typically used by peers.
#[derive(Clone)]
pub struct XactCommittedReqBlobCodec {
    req_codec: XactCommittedReqHeaderPERCodec
}

/// Errors that can occur creating an [XactUncommittedReqCodec].
#[derive(Debug)]
pub enum XactReqCodecCreateError<Payload, Effect> {
    /// Error occurred creating the payload codec.
    Payload {
        /// The error that occurred creating the payload codec.
        err: Payload
    },
    /// Error occurred creating the effect codec.
    Effect {
        /// The error that occurred creating the effect codec.
        err: Effect
    }
}

/// Errors that can occur decoding an [XactUncommittedReq] or
/// [XactUncommittedHashReq].
#[derive(Debug)]
pub enum XactReqCodecDecodeError<Payload, Effects, Req> {
    /// Error occurred decoding the payload.
    Payload {
        /// The error that occurred decoding the payload.
        err: Payload
    },
    /// Error occurred decoding the effects.
    Effects {
        /// The error that occurred decoding the effects.
        err: Effects
    },
    /// Error occurred decoding the request header.
    Req {
        /// Error that occurred decoding the request header.
        err: Req
    },
    /// Error occurred deserializing the class UUID.
    ///
    /// This should normally never happen.
    UUID {
        /// Error that occurred deserializing the UUID.
        err: uuid::Error
    },
    /// Provided buffer was too short.
    TooShort
}

/// Errors that can occur encoding an [XactUncommittedReq] or
/// [XactUncommittedHashReq].
#[derive(Debug)]
pub enum XactReqCodecEncodeError<Payload, Effects, Req> {
    /// Error occurred encoding the payload.
    Payload {
        /// The error that occurred encoding the payload.
        err: Payload
    },
    /// Error occurred encoding the effects.
    Effects {
        /// The error that occurred encoding the effects.
        err: Effects
    },
    /// Error occurred encoding the request header.
    Req {
        /// Error that occurred encoding the request header.
        err: Req
    },
    /// Error occurred writing out the hash data.
    ///
    /// This should normally never happen.
    Hash {
        /// Error that occurred writing out the hash data.
        err: TryFromSliceError
    },
    /// Provided buffer was too short.
    TooShort
}

impl<RoundID> XactLinPoint<RoundID>
where RoundID: Clone + From<u128> + Into<u128> {
    /// Create a new `XactLinPoint` from components.
    #[inline]
    pub fn new(
        round: RoundID,
        idx: usize
    ) -> Self {
        XactLinPoint {
            round: round,
            idx: idx as u8
        }
    }

    /// Get the ID of the round in which this event occurs.
    #[inline]
    pub fn round(&self) -> &RoundID {
        &self.round
    }

    /// Get the index within the round at which the event occurs.
    #[inline]
    pub fn idx(&self) -> usize {
        self.idx as usize
    }

    /// Deconstruct this `XactLinPoint` into its components.
    #[inline]
    pub fn take(self) -> (RoundID, usize) {
        (self.round, self.idx as usize)
    }
}

impl<RoundID, Payload, Effect, PayloadCodec, EffectCodec>
    Codec<XactUncommittedReq<RoundID, Payload, Effect>>
    for XactUncommittedReqCodec<RoundID, Payload, Effect,
                                PayloadCodec, EffectCodec>
where
    RoundID: Clone + From<u128> + Into<u128>,
    PayloadCodec: Codec<Payload>,
    EffectCodec: Codec<Effect>
{
    type CreateError = XactReqCodecCreateError<
        PayloadCodec::CreateError,
        EffectCodec::CreateError,
    >;
    type DecodeError = XactReqCodecDecodeError<
        PayloadCodec::DecodeError,
        EffectCodec::DecodeError,
        <XactUncommittedReqHeaderPERCodec as Codec<XactUncommittedReqHeader>>::EncodeError
    >;
    type EncodeError = XactReqCodecEncodeError<
        PayloadCodec::EncodeError,
        EffectCodec::EncodeError,
        <XactUncommittedReqHeaderPERCodec as Codec<XactUncommittedReqHeader>>::EncodeError
    >;
    type Param = (PayloadCodec::Param, EffectCodec::Param);

    fn create(param: Self::Param) -> Result<Self, Self::CreateError> {
        let (payload, effect) = param;
        let payload_codec = PayloadCodec::create(payload)
            .map_err(|err| XactReqCodecCreateError::Payload {
                err: err
            })?;
        let effect_codec = EffectCodec::create(effect)
            .map_err(|err| XactReqCodecCreateError::Effect {
                err: err
            })?;

        Ok(XactUncommittedReqCodec {
            payload: PhantomData,
            effect: PhantomData,
            round: PhantomData,
            req_codec: XactUncommittedReqHeaderPERCodec::default(),
            payload_codec: payload_codec,
            effect_codec: effect_codec,
        })
    }

    #[inline]
    fn buf_size(
        &self,
        val: &XactUncommittedReq<RoundID, Payload, Effect>
    ) -> usize {
        let payload = self.payload_codec.buf_size(&val.payload) + 9;
        let effects = match &val.effects {
            XactEffects::Effects { effects, .. } =>
                self.effect_codec.buf_size(effects) + 11,
            XactEffects::HardNone { when: Some(_) } => 18,
            XactEffects::HardNone { when: None } => 2,
            XactEffects::SoftNone => 1
        };
        let class = 16;
        let instance = if val.instance.is_some() {
            10
        } else {
            1
        };
        let version = 3;

        payload + effects + class + instance + version
    }

    fn encode(
        &mut self,
        req: &XactUncommittedReq<RoundID, Payload, Effect>,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let payload = self
            .payload_codec
            .encode_to_vec(&req.payload)
            .map_err(|err| XactReqCodecEncodeError::Payload {
                err: err
            })?;
        let payload_len = payload.len();
        let mut curr = 0;

        // Write the header and any effects, then store the header.
        match &req.effects {
            XactEffects::Effects { hard, effects } => {
                let effects = self
                    .effect_codec
                    .encode_to_vec(effects)
                    .map_err(|err| XactReqCodecEncodeError::Effects {
                        err: err
                    })?;
                let effects_len = effects.len();
                let effects_header =
                    XactUncommittedEffectsHeader::Effects(XactEffectsHeader {
                        len: effects_len as u64,
                        hard: *hard
                    });
                let header = XactUncommittedReqHeader {
                    version: req.version.clone(),
                    class: req.class.into(),
                    effects: effects_header,
                    instance: req.instance,
                    len: payload_len as u64
                };

                curr += self
                    .req_codec
                    .encode(&header, &mut buf[curr..])
                    .map_err(|err| XactReqCodecEncodeError::Req {
                        err: err
                    })?;

                if curr + effects_len < buf.len() {
                    buf[curr..curr + effects_len]
                        .copy_from_slice(&effects[..]);

                    curr += effects_len;
                } else {
                    return Err(XactReqCodecEncodeError::TooShort)
                }
            }
            XactEffects::HardNone { when } => {
                let effects_header =
                    XactUncommittedEffectsHeader::HardNone(XactHardNone {
                        when: when.as_ref().map(|when| {
                            let round: u128 = when.round.clone().into();
                            let round = round.to_le_bytes().to_vec();

                            XactLinPointHeader {
                                round: round,
                                idx: when.idx
                            }
                        })
                    });
                let header = XactUncommittedReqHeader {
                    version: req.version.clone(),
                    class: req.class.into(),
                    effects: effects_header,
                    instance: req.instance,
                    len: payload_len as u64
                };

                curr += self
                    .req_codec
                    .encode(&header, &mut buf[curr..])
                    .map_err(|err| XactReqCodecEncodeError::Req {
                        err: err
                    })?;
            }
            XactEffects::SoftNone => {
                let effects =
                    XactUncommittedEffectsHeader::SoftNone(Default::default());
                let header = XactUncommittedReqHeader {
                    version: req.version.clone(),
                    class: req.class.into(),
                    effects: effects,
                    instance: req.instance,
                    len: payload_len as u64
                };

                curr += self
                    .req_codec
                    .encode(&header, &mut buf[curr..])
                    .map_err(|err| XactReqCodecEncodeError::Req {
                        err: err
                    })?;
            }
        };

        if curr + payload_len < buf.len() {
            buf[curr..curr + payload_len].copy_from_slice(&payload[..]);

            curr += payload_len;
        } else {
            return Err(XactReqCodecEncodeError::TooShort)
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(XactUncommittedReq<RoundID, Payload, Effect>, usize),
                Self::DecodeError>
    {
        let mut curr = 0;
        let (req, nbytes) = self
            .req_codec
            .decode(&buf[curr..])
            .map_err(|err| XactReqCodecDecodeError::Req {
                err: err
            })?;

        curr += nbytes;

        let class = Uuid::from_slice(&req.class)
            .map_err(|err| XactReqCodecDecodeError::UUID {
                err: err
            })?;
        let effects = match req.effects {
            XactUncommittedEffectsHeader::Effects(XactEffectsHeader {
                hard, len
            }) => {
                let (effects, _) = self
                    .effect_codec
                    .decode(&buf[curr..curr + len as usize])
                    .map_err(|err|
                             XactReqCodecDecodeError::Effects {
                                 err: err
                             })?;

                curr += len as usize;

                Ok(XactEffects::Effects {
                    effects: effects,
                    hard: hard
                })
            }
            XactUncommittedEffectsHeader::HardNone(XactHardNone { when }) => {
                let when = when.map(|when| {
                    let round = when.round.try_into()
                        .expect("Impossible case");
                    let round = u128::from_le_bytes(round);

                    XactLinPoint {
                        round: round.into(),
                        idx: when.idx
                    }
                });

                Ok(XactEffects::HardNone {
                    when: when
                })
            }
            XactUncommittedEffectsHeader::SoftNone(_) =>
                Ok(XactEffects::SoftNone)
        }?;

        let (payload, _) = self
            .payload_codec
            .decode(&buf[curr..curr + req.len as usize])
            .map_err(|err| XactReqCodecDecodeError::Payload {
                err: err
            })?;

        curr += req.len as usize;

        Ok((XactUncommittedReq {
            instance: req.instance,
            version: req.version,
            effects: effects,
            payload: payload,
            class: class
        }, curr))
    }
}

impl<H, RoundID>
    Codec<XactUncommittedHashReq<RoundID, H::HashID, Vec<u8>, Vec<u8>>>
    for XactUncommittedReqBlobCodec<H, RoundID>
where
    H: HashAlgo + Default,
    H::HashID: Clone,
    RoundID: Clone + From<u128> + Into<u128>,
{
    type CreateError = XactReqCodecCreateError<
        Infallible,
        Infallible
    >;
    type DecodeError = XactReqCodecDecodeError<
        Infallible,
        Infallible,
        <XactUncommittedReqHeaderPERCodec as Codec<XactUncommittedReqHeader>>::EncodeError
    >;
    type EncodeError = XactReqCodecEncodeError<
        Infallible,
        Infallible,
        <XactUncommittedReqHeaderPERCodec as Codec<XactUncommittedReqHeader>>::EncodeError
    >;
    type Param = ();

    fn create(_param: Self::Param) -> Result<Self, Self::CreateError> {
        let hash = H::default();

        Ok(XactUncommittedReqBlobCodec {
            round: PhantomData,
            req_codec: XactUncommittedReqHeaderPERCodec::default(),
            hash: hash
        })
    }

    #[inline]
    fn buf_size(
        &self,
        val: &XactUncommittedHashReq<RoundID, H::HashID, Vec<u8>, Vec<u8>>,
    ) -> usize {
        let payload = val.payload.len() + 9;
        let effects = match &val.effects {
            XactEffects::Effects { effects, .. } => effects.len() + 11,
            XactEffects::HardNone { when: Some(_) } => 18,
            XactEffects::HardNone { when: None } => 2,
            XactEffects::SoftNone => 1
        };
        let class = 16;
        let instance = if val.instance.is_some() {
            10
        } else {
            1
        };
        let version = 3;

        payload + effects + class + instance + version
    }

    fn encode(
        &mut self,
        req: &XactUncommittedHashReq<RoundID, H::HashID, Vec<u8>, Vec<u8>>,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let mut curr = 0;

        // Write the header and any effects, then store the header.
        match &req.effects {
            XactEffects::Effects { hard, effects } => {
                let effects_len = effects.len();
                let effects_header =
                    XactUncommittedEffectsHeader::Effects(XactEffectsHeader {
                        len: effects_len as u64,
                        hard: *hard,
                    });
                let header = XactUncommittedReqHeader {
                    version: req.version.clone(),
                    class: req.class.into(),
                    effects: effects_header,
                    instance: req.instance,
                    len: req.payload.len() as u64
                };

                curr += self
                    .req_codec
                    .encode(&header, &mut buf[curr..])
                    .map_err(|err| XactReqCodecEncodeError::Req {
                        err: err
                    })?;

                if curr + effects_len < buf.len() {
                    buf[curr..curr + effects_len].copy_from_slice(&effects[..]);

                    curr += effects_len;
                } else {
                    return Err(XactReqCodecEncodeError::TooShort)
                }
            }
            XactEffects::HardNone { when } => {
                let effects_header =
                    XactUncommittedEffectsHeader::HardNone(XactHardNone {
                        when: when.as_ref().map(|when| {
                            let round: u128 = when.round.clone().into();
                            let round = round.to_le_bytes().to_vec();

                            XactLinPointHeader {
                                round: round,
                                idx: when.idx
                            }
                        })
                    });
                let header = XactUncommittedReqHeader {
                    version: req.version.clone(),
                    class: req.class.into(),
                    effects: effects_header,
                    instance: req.instance,
                    len: req.payload.len() as u64
                };

                curr += self
                    .req_codec
                    .encode(&header, &mut buf[curr..])
                    .map_err(|err| XactReqCodecEncodeError::Req {
                        err: err
                    })?;
            }
            XactEffects::SoftNone => {
                let effects =
                    XactUncommittedEffectsHeader::SoftNone(Default::default());
                let header = XactUncommittedReqHeader {
                    version: req.version.clone(),
                    class: req.class.into(),
                    effects: effects,
                    instance: req.instance,
                    len: req.payload.len() as u64
                };

                curr += self
                    .req_codec
                    .encode(&header, &mut buf[curr..])
                    .map_err(|err| XactReqCodecEncodeError::Req {
                        err: err
                    })?;
            }
        };

        // Encode the actual payload.
        let payload_len = req.payload.len();

        if curr + payload_len < buf.len() {
            buf[curr..curr + payload_len].copy_from_slice(&req.payload[..]);
        } else {
            return Err(XactReqCodecEncodeError::TooShort)
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(XactUncommittedHashReq<RoundID, H::HashID, Vec<u8>, Vec<u8>>,
                 usize),
                Self::DecodeError>
    {
        let mut curr = 0;
        let (req, nbytes) = self
            .req_codec
            .decode(&buf[curr..])
            .map_err(|err| XactReqCodecDecodeError::Req {
                err: err
            })?;

        curr += nbytes;

        let class = Uuid::from_slice(&req.class)
            .map_err(|err| XactReqCodecDecodeError::UUID {
                err: err
            })?;
        let effects = match req.effects {
            XactUncommittedEffectsHeader::Effects(XactEffectsHeader {
                hard, len
            }) => {
                let effects = if curr + len as usize <= buf.len() {
                    let data = buf[curr..curr + len as usize].to_vec();

                    curr += len as usize;

                    Ok(data)
                } else {
                    Err(XactReqCodecDecodeError::TooShort)
                }?;

                Ok(XactEffects::Effects {
                    effects: effects,
                    hard: hard
                })
            }
            XactUncommittedEffectsHeader::HardNone(XactHardNone { when }) => {
                let when = when.map(|when| {
                    let round = when.round.try_into()
                        .expect("Impossible case");
                    let round = u128::from_le_bytes(round);

                    XactLinPoint {
                        round: round.into(),
                        idx: when.idx
                    }
                });

                Ok(XactEffects::HardNone {
                    when: when
                })
            }
            XactUncommittedEffectsHeader::SoftNone(_) =>
                Ok(XactEffects::SoftNone)
        }?;

        let payload = if curr + req.len as usize <= buf.len() {
            let data = buf[curr..curr + req.len as usize].to_vec();

            curr += req.len as usize;

            Ok(data)
        } else {
            Err(XactReqCodecDecodeError::TooShort)
        }?;

        // XXX We're encoding the lengths as well, which is
        // technically redundant.
        let hashid = self.hash.hash_bytes(once(&buf[..curr]));

        Ok((XactUncommittedHashReq {
            instance: req.instance,
            version: req.version,
            effects: effects,
            payload: payload,
            class: class,
            hash: hashid
        }, curr))
    }
}

impl<H, RoundID, Payload, Effect, PayloadCodec, EffectCodec>
    Codec<XactUncommittedHashReq<RoundID, H::HashID, Payload, Effect>>
    for XactUncommittedReqHashCodec<H, RoundID, Payload, Effect,
                                    PayloadCodec, EffectCodec>
where
    H: HashAlgo + Default,
    H::HashID: Clone,
    PayloadCodec: Codec<Payload>,
    EffectCodec: Codec<Effect>,
    RoundID: Clone + From<u128> + Into<u128>,
{
    type CreateError = XactReqCodecCreateError<
        PayloadCodec::CreateError,
        EffectCodec::CreateError,
    >;
    type DecodeError = XactReqCodecDecodeError<
        PayloadCodec::DecodeError,
        EffectCodec::DecodeError,
        <XactUncommittedReqHeaderPERCodec as Codec<XactUncommittedReqHeader>>::EncodeError
    >;
    type EncodeError = XactReqCodecEncodeError<
        PayloadCodec::EncodeError,
        EffectCodec::EncodeError,
        <XactUncommittedReqHeaderPERCodec as Codec<XactUncommittedReqHeader>>::EncodeError
    >;
    type Param = (PayloadCodec::Param, EffectCodec::Param);

    fn create(param: Self::Param) -> Result<Self, Self::CreateError> {
        let (payload, effect) = param;
        let payload_codec = PayloadCodec::create(payload)
            .map_err(|err| XactReqCodecCreateError::Payload {
                err: err
            })?;
        let effect_codec = EffectCodec::create(effect)
            .map_err(|err| XactReqCodecCreateError::Effect {
                err: err
            })?;
        let hash = H::default();

        Ok(XactUncommittedReqHashCodec {
            payload: PhantomData,
            effect: PhantomData,
            round: PhantomData,
            req_codec: XactUncommittedReqHeaderPERCodec::default(),
            payload_codec: payload_codec,
            effect_codec: effect_codec,
            hash: hash
        })
    }

    #[inline]
    fn buf_size(
        &self,
        val: &XactUncommittedHashReq<RoundID, H::HashID, Payload, Effect>,
    ) -> usize {
        let payload = self.payload_codec.buf_size(&val.payload) + 9;
        let effects = match &val.effects {
            XactEffects::Effects { effects, .. } =>
                self.effect_codec.buf_size(effects) + 11,
            XactEffects::HardNone { when: Some(_) } => 18,
            XactEffects::HardNone { when: None } => 2,
            XactEffects::SoftNone => 1
        };
        let class = 16;
        let instance = if val.instance.is_some() {
            10
        } else {
            1
        };
        let version = 3;

        payload + effects + class + instance + version
    }

    fn encode(
        &mut self,
        req: &XactUncommittedHashReq<RoundID, H::HashID, Payload, Effect>,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let payload = self
            .payload_codec
            .encode_to_vec(&req.payload)
            .map_err(|err| XactReqCodecEncodeError::Payload {
                err: err
            })?;
        let payload_len = payload.len();
        let mut curr = 0;

        // Write the header and any effects, then store the header.
        match &req.effects {
            XactEffects::Effects { hard, effects } => {
                let effects = self
                    .effect_codec
                    .encode_to_vec(effects)
                    .map_err(|err| XactReqCodecEncodeError::Effects {
                        err: err
                    })?;
                let effects_len = effects.len();
                let effects_header =
                    XactUncommittedEffectsHeader::Effects(XactEffectsHeader {
                        len: effects_len as u64,
                        hard: *hard
                    });
                let header = XactUncommittedReqHeader {
                    version: req.version.clone(),
                    class: req.class.into(),
                    effects: effects_header,
                    instance: req.instance,
                    len: payload_len as u64
                };

                curr += self
                    .req_codec
                    .encode(&header, &mut buf[curr..])
                    .map_err(|err| XactReqCodecEncodeError::Req {
                        err: err
                    })?;

                let effects_len = effects.len();

                if curr + effects_len < buf.len() {
                    buf[curr..curr + effects_len].copy_from_slice(&effects[..]);

                    curr += effects_len;
                } else {
                    return Err(XactReqCodecEncodeError::TooShort)
                }
            }
            XactEffects::HardNone { when } => {
                let effects_header =
                    XactUncommittedEffectsHeader::HardNone(XactHardNone {
                        when: when.as_ref().map(|when| {
                            let round: u128 = when.round.clone().into();
                            let round = round.to_le_bytes().to_vec();

                            XactLinPointHeader {
                                round: round,
                                idx: when.idx
                            }
                        })
                    });
                let header = XactUncommittedReqHeader {
                    version: req.version.clone(),
                    class: req.class.into(),
                    effects: effects_header,
                    instance: req.instance,
                    len: payload_len as u64
                };

                curr += self
                    .req_codec
                    .encode(&header, &mut buf[curr..])
                    .map_err(|err| XactReqCodecEncodeError::Req {
                        err: err
                    })?;
            }
            XactEffects::SoftNone => {
                let effects =
                    XactUncommittedEffectsHeader::SoftNone(Default::default());
                let header = XactUncommittedReqHeader {
                    version: req.version.clone(),
                    class: req.class.into(),
                    effects: effects,
                    instance: req.instance,
                    len: payload_len as u64
                };

                curr += self
                    .req_codec
                    .encode(&header, &mut buf[curr..])
                    .map_err(|err| XactReqCodecEncodeError::Req {
                        err: err
                    })?;
            }
        };

        if curr + payload_len < buf.len() {
            buf[curr..curr + payload_len].copy_from_slice(&payload[..]);

            curr += payload_len;
        } else {
            return Err(XactReqCodecEncodeError::TooShort)
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(XactUncommittedHashReq<RoundID, H::HashID, Payload, Effect>,
                 usize),
                Self::DecodeError>
    {
        let mut curr = 0;
        let (req, nbytes) = self
            .req_codec
            .decode(&buf[curr..])
            .map_err(|err| XactReqCodecDecodeError::Req {
                err: err
            })?;

        curr += nbytes;

        let class = Uuid::from_slice(&req.class)
            .map_err(|err| XactReqCodecDecodeError::UUID {
                err: err
            })?;
        let effects = match req.effects {
            XactUncommittedEffectsHeader::Effects(XactEffectsHeader {
                hard, len
            }) => {
                let (effects, _) = self
                    .effect_codec
                    .decode(&buf[curr..curr + len as usize])
                    .map_err(|err|
                             XactReqCodecDecodeError::Effects {
                                 err: err
                             })?;

                curr += len as usize;

                Ok(XactEffects::Effects {
                    effects: effects,
                    hard: hard
                })
            }
            XactUncommittedEffectsHeader::HardNone(XactHardNone { when }) => {
                let when = when.map(|when| {
                    let round = when.round.try_into()
                        .expect("Impossible case");
                    let round = u128::from_le_bytes(round);

                    XactLinPoint {
                        round: round.into(),
                        idx: when.idx
                    }
                });

                Ok(XactEffects::HardNone {
                    when: when
                })
            }
            XactUncommittedEffectsHeader::SoftNone(_) =>
                Ok(XactEffects::SoftNone)
        }?;


        let (payload, _) = self
            .payload_codec
            .decode(&buf[curr..curr + req.len as usize])
            .map_err(|err| XactReqCodecDecodeError::Payload {
                err: err
            })?;

        curr += req.len as usize;

        let hashid = self.hash.hash_bytes(once(&buf[..curr]));

        Ok((XactUncommittedHashReq {
            instance: req.instance,
            version: req.version,
            effects: effects,
            payload: payload,
            class: class,
            hash: hashid
        }, curr))
    }
}

impl<Payload, Effect, PayloadCodec, EffectCodec>
    Codec<XactCommittedReq<Payload, Effect>>
    for XactCommittedReqCodec<Payload, Effect, PayloadCodec, EffectCodec>
where
    PayloadCodec: Codec<Payload>,
    EffectCodec: Codec<Effect>
{
    type CreateError = XactReqCodecCreateError<
        PayloadCodec::CreateError,
        EffectCodec::CreateError,
    >;
    type DecodeError = XactReqCodecDecodeError<
        PayloadCodec::DecodeError,
        EffectCodec::DecodeError,
        <XactUncommittedReqHeaderPERCodec as Codec<XactUncommittedReqHeader>>::EncodeError
    >;
    type EncodeError = XactReqCodecEncodeError<
        PayloadCodec::EncodeError,
        EffectCodec::EncodeError,
        <XactUncommittedReqHeaderPERCodec as Codec<XactUncommittedReqHeader>>::EncodeError
    >;
    type Param = (PayloadCodec::Param, EffectCodec::Param);

    fn create(param: Self::Param) -> Result<Self, Self::CreateError> {
        let (payload, effect) = param;
        let payload_codec = PayloadCodec::create(payload)
            .map_err(|err| XactReqCodecCreateError::Payload {
                err: err
            })?;
        let effect_codec = EffectCodec::create(effect)
            .map_err(|err| XactReqCodecCreateError::Effect {
                err: err
            })?;

        Ok(XactCommittedReqCodec {
            payload: PhantomData,
            effect: PhantomData,
            req_codec: XactCommittedReqHeaderPERCodec::default(),
            payload_codec: payload_codec,
            effect_codec: effect_codec,
        })
    }

    #[inline]
    fn buf_size(
        &self,
        val: &XactCommittedReq<Payload, Effect>
    ) -> usize {
        let payload = self.payload_codec.buf_size(&val.payload) + 9;
        let effects = match &val.effects {
            Some(effects) => self.effect_codec.buf_size(&effects.effects) + 11,
            None => 1
        };
        let class = 16;
        let instance = if val.instance.is_some() {
            10
        } else {
            1
        };
        let version = 3;
        let idx = 1;

        payload + effects + class + instance + version + idx
    }

    fn encode(
        &mut self,
        req: &XactCommittedReq<Payload, Effect>,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let payload = self
            .payload_codec
            .encode_to_vec(&req.payload)
            .map_err(|err| XactReqCodecEncodeError::Payload {
                err: err
            })?;
        let payload_len = payload.len();
        let mut curr = 0;

        // Write the header and any effects, then store the header.
        match &req.effects {
            Some(XactCommittedEffects { hard, effects }) => {
                let effects = self
                    .effect_codec
                    .encode_to_vec(effects)
                    .map_err(|err| XactReqCodecEncodeError::Effects {
                        err: err
                    })?;
                let effects_len = effects.len();
                let effects_header = Some(XactEffectsHeader {
                    len: effects_len as u64,
                    hard: *hard
                });
                let header = XactCommittedReqHeader {
                    version: req.version.clone(),
                    class: req.class.into(),
                    effects: effects_header,
                    instance: req.instance,
                    len: payload_len as u64,
                    idx: req.idx as u8
                };

                curr += self
                    .req_codec
                    .encode(&header, &mut buf[curr..])
                    .map_err(|err| XactReqCodecEncodeError::Req {
                        err: err
                    })?;

                if curr + effects_len < buf.len() {
                    buf[curr..curr + effects_len]
                        .copy_from_slice(&effects[..]);

                    curr += effects_len;
                } else {
                    return Err(XactReqCodecEncodeError::TooShort)
                }
            }
            None => {
                let header = XactCommittedReqHeader {
                    version: req.version.clone(),
                    class: req.class.into(),
                    instance: req.instance,
                    idx: req.idx as u8,
                    effects: None,
                    len: payload_len as u64
                };

                curr += self
                    .req_codec
                    .encode(&header, &mut buf[curr..])
                    .map_err(|err| XactReqCodecEncodeError::Req {
                        err: err
                    })?;
            }
        };

        if curr + payload_len < buf.len() {
            buf[curr..curr + payload_len].copy_from_slice(&payload[..]);

            curr += payload_len;
        } else {
            return Err(XactReqCodecEncodeError::TooShort)
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(XactCommittedReq<Payload, Effect>, usize), Self::DecodeError>
    {
        let mut curr = 0;
        let (req, nbytes) = self
            .req_codec
            .decode(&buf[curr..])
            .map_err(|err| XactReqCodecDecodeError::Req {
                err: err
            })?;

        curr += nbytes;

        let class = Uuid::from_slice(&req.class)
            .map_err(|err| XactReqCodecDecodeError::UUID {
                err: err
            })?;
        let effects = match req.effects {
            Some(XactEffectsHeader { hard, len }) => {
                let (effects, _) = self
                    .effect_codec
                    .decode(&buf[curr..curr + len as usize])
                    .map_err(|err|
                             XactReqCodecDecodeError::Effects {
                                 err: err
                             })?;

                curr += len as usize;

                Ok(Some(XactCommittedEffects {
                    effects: effects,
                    hard: hard
                }))
            }
            None => Ok(None)
        }?;

        let (payload, _) = self
            .payload_codec
            .decode(&buf[curr..curr + req.len as usize])
            .map_err(|err| XactReqCodecDecodeError::Payload {
                err: err
            })?;

        curr += req.len as usize;

        Ok((XactCommittedReq {
            instance: req.instance,
            version: req.version,
            effects: effects,
            payload: payload,
            idx: req.idx as usize,
            class: class
        }, curr))
    }
}




impl Codec<XactCommittedReq<Vec<u8>, Vec<u8>>> for XactCommittedReqBlobCodec {
    type CreateError = XactReqCodecCreateError<
        Infallible,
        Infallible
    >;
    type DecodeError = XactReqCodecDecodeError<
        Infallible,
        Infallible,
        <XactUncommittedReqHeaderPERCodec as Codec<XactUncommittedReqHeader>>::EncodeError
    >;
    type EncodeError = XactReqCodecEncodeError<
        Infallible,
        Infallible,
        <XactUncommittedReqHeaderPERCodec as Codec<XactUncommittedReqHeader>>::EncodeError
    >;
    type Param = ();

    fn create(_param: Self::Param) -> Result<Self, Self::CreateError> {
        Ok(XactCommittedReqBlobCodec {
            req_codec: XactCommittedReqHeaderPERCodec::default(),
        })
    }

    #[inline]
    fn buf_size(
        &self,
        val: &XactCommittedReq<Vec<u8>, Vec<u8>>
    ) -> usize {
        let payload = val.payload.len() + 9;
        let effects = match &val.effects {
            Some(effects) => effects.effects.len() + 11,
            None => 1
        };
        let class = 16;
        let instance = if val.instance.is_some() {
            10
        } else {
            1
        };
        let version = 3;
        let idx = 1;

        payload + effects + class + instance + version + idx
    }

    fn encode(
        &mut self,
        req: &XactCommittedReq<Vec<u8>, Vec<u8>>,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let mut curr = 0;
        let payload_len = req.payload.len();

        // Write the header and any effects, then store the header.
        match &req.effects {
            Some(XactCommittedEffects { hard, effects }) => {
                let effects_len = effects.len();
                let effects_header = Some(XactEffectsHeader {
                    len: effects_len as u64,
                    hard: *hard
                });
                let header = XactCommittedReqHeader {
                    version: req.version.clone(),
                    class: req.class.into(),
                    effects: effects_header,
                    instance: req.instance,
                    len: payload_len as u64,
                    idx: req.idx as u8
                };

                curr += self
                    .req_codec
                    .encode(&header, &mut buf[curr..])
                    .map_err(|err| XactReqCodecEncodeError::Req {
                        err: err
                    })?;

                if curr + effects_len < buf.len() {
                    buf[curr..curr + effects_len].copy_from_slice(&effects[..]);

                    curr += effects_len;
                } else {
                    return Err(XactReqCodecEncodeError::TooShort)
                }
            }
            None => {
                let header = XactCommittedReqHeader {
                    version: req.version.clone(),
                    class: req.class.into(),
                    instance: req.instance,
                    idx: req.idx as u8,
                    effects: None,
                    len: payload_len as u64
                };

                curr += self
                    .req_codec
                    .encode(&header, &mut buf[curr..])
                    .map_err(|err| XactReqCodecEncodeError::Req {
                        err: err
                    })?;
            }
        };

        if curr + payload_len < buf.len() {
            buf[curr..curr + payload_len].copy_from_slice(&req.payload[..]);
        } else {
            return Err(XactReqCodecEncodeError::TooShort)
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(XactCommittedReq<Vec<u8>, Vec<u8>>, usize), Self::DecodeError>
    {
        let mut curr = 0;
        let (req, nbytes) = self
            .req_codec
            .decode(&buf[curr..])
            .map_err(|err| XactReqCodecDecodeError::Req {
                err: err
            })?;

        curr += nbytes;

        let class = Uuid::from_slice(&req.class)
            .map_err(|err| XactReqCodecDecodeError::UUID {
                err: err
            })?;
        let effects = match req.effects {
            Some(XactEffectsHeader { hard, len }) => {
                let effects = if curr + len as usize <= buf.len() {
                    let data = buf[curr..curr + len as usize].to_vec();

                    curr += len as usize;

                    Ok(data)
                } else {
                    Err(XactReqCodecDecodeError::TooShort)
                }?;

                Ok(Some(XactCommittedEffects {
                    effects: effects,
                    hard: hard
                }))
            }
            None => Ok(None)
        }?;

        let payload = if curr + req.len as usize <= buf.len() {
            let data = buf[curr..curr + req.len as usize].to_vec();

            curr += req.len as usize;

            Ok(data)
        } else {
            Err(XactReqCodecDecodeError::TooShort)
        }?;

        Ok((XactCommittedReq {
            instance: req.instance,
            version: req.version,
            effects: effects,
            payload: payload,
            idx: req.idx as usize,
            class: class
        }, curr))
    }
}




impl<RoundID> Display for XactLinPoint<RoundID>
where RoundID: Clone + Display + From<u128> + Into<u128> {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        write!(f, "{}, idx {}", self.round, self.idx)
    }
}

impl<RoundID, Effects> Display for XactEffects<RoundID, Effects>
where RoundID: Clone + Display + From<u128> + Into<u128>,
      Effects: Display {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            XactEffects::Effects { hard: true, effects } =>
                write!(f, "hard {}", effects),
            XactEffects::Effects { hard: false, effects } =>
                write!(f, "soft {}", effects),
            XactEffects::HardNone { when: Some(when) } =>
                write!(f, "hard none, when: {{ {} }}", when),
            XactEffects::HardNone { when: None } => write!(f, "hard none"),
            XactEffects::SoftNone => write!(f, "soft none")
        }
    }
}

impl<Payload, Effect> ScopedError
    for XactReqCodecCreateError<Payload, Effect>
where
    Payload: ScopedError,
    Effect: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            XactReqCodecCreateError::Payload { err } => err.scope(),
            XactReqCodecCreateError::Effect { err } => err.scope()
        }
    }
}

impl<Payload, Effects, Req> ScopedError
    for XactReqCodecDecodeError<Payload, Effects, Req>
where
    Payload: ScopedError,
    Effects: ScopedError,
    Req: ScopedError
{
    #[inline]
    fn scope(&self) -> ErrorScope {
        match self {
            XactReqCodecDecodeError::Payload { err } => err.scope(),
            XactReqCodecDecodeError::Effects { err } => err.scope(),
            XactReqCodecDecodeError::UUID { .. } |
            XactReqCodecDecodeError::Req { .. } |
            XactReqCodecDecodeError::TooShort =>
                ErrorScope::Unrecoverable
        }
    }
}

impl<Payload, Effects, Req> ScopedError
    for XactReqCodecEncodeError<Payload, Effects, Req>
where
    Payload: ScopedError,
    Effects: ScopedError,
    Req: ScopedError
{
    #[inline]
    fn scope(&self) -> ErrorScope {
        match self {
            XactReqCodecEncodeError::Payload { err } => err.scope(),
            XactReqCodecEncodeError::Effects { err } => err.scope(),
            XactReqCodecEncodeError::Req { .. } |
            XactReqCodecEncodeError::Hash { .. } |
            XactReqCodecEncodeError::TooShort =>
                ErrorScope::Unrecoverable
        }
    }
}

impl<Payload, Effect> Display
    for XactReqCodecCreateError<Payload, Effect>
where
    Payload: Display,
    Effect: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            XactReqCodecCreateError::Payload { err } => err.fmt(f),
            XactReqCodecCreateError::Effect { err } => err.fmt(f)
        }
    }
}

impl<Payload, Effects, Req> Display
    for XactReqCodecDecodeError<Payload, Effects, Req>
where
    Payload: Display,
    Effects: Display,
    Req: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            XactReqCodecDecodeError::Payload { err } => err.fmt(f),
            XactReqCodecDecodeError::Effects { err } => err.fmt(f),
            XactReqCodecDecodeError::UUID { err } => err.fmt(f),
            XactReqCodecDecodeError::Req { err } => err.fmt(f),
            XactReqCodecDecodeError::TooShort => {
                write!(f, "output buffer is too short")
            }
        }
    }
}

impl<Payload, Effects, Req> Display
    for XactReqCodecEncodeError<Payload, Effects, Req>
where
    Payload: Display,
    Effects: Display,
    Req: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            XactReqCodecEncodeError::Payload { err } => err.fmt(f),
            XactReqCodecEncodeError::Effects { err } => err.fmt(f),
            XactReqCodecEncodeError::Req { err } => err.fmt(f),
            XactReqCodecEncodeError::Hash { err } => err.fmt(f),
            XactReqCodecEncodeError::TooShort => {
                write!(f, "input buffer is too short")
            }
        }
    }
}


#[cfg(test)]
use constellation_common::codec::DatagramCodec;
#[cfg(test)]
use constellation_common::hashid::SHA3Algo;

#[cfg(test)]
const TEST_SERVICE_NAME: &str = "org.constellation.test";

#[cfg(test)]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TestEffects {
    effects: Vec<u8>
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TestPayload {
    effects: Vec<u8>
}

#[cfg(test)]
#[derive(Clone)]
pub struct TestEffectsCodec;

#[cfg(test)]
#[derive(Clone)]
pub struct TestPayloadCodec;

#[cfg(test)]
impl Codec<TestEffects> for TestEffectsCodec {
    type CreateError = Infallible;
    type EncodeError = Infallible;
    type DecodeError = Infallible;
    type Param = ();

    #[inline]
    fn create(_param: ()) -> Result<Self, Infallible> {
        Ok(TestEffectsCodec)
    }

    #[inline]
    fn buf_size(
        &self,
        val: &TestEffects
    ) -> usize {
        val.effects.len()
    }

    #[inline]
    fn encode(
        &mut self,
        val: &TestEffects,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let len = val.effects.len();

        buf[..len].copy_from_slice(&val.effects[..]);

        Ok(len)
    }

    #[inline]
    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(TestEffects, usize), Self::DecodeError> {
        let effects = buf[..].to_vec();
        let len = effects.len();

        Ok((TestEffects {
            effects: effects
        }, len))
    }
}

#[cfg(test)]
impl Codec<TestPayload> for TestPayloadCodec {
    type CreateError = Infallible;
    type EncodeError = Infallible;
    type DecodeError = Infallible;
    type Param = ();

    #[inline]
    fn create(_param: ()) -> Result<Self, Infallible> {
        Ok(TestPayloadCodec)
    }

    #[inline]
    fn buf_size(
        &self,
        val: &TestPayload
    ) -> usize {
        val.effects.len()
    }

    #[inline]
    fn encode(
        &mut self,
        val: &TestPayload,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let len = val.effects.len();

        buf[..len].copy_from_slice(&val.effects[..]);

        Ok(len)
    }

    #[inline]
    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(TestPayload, usize), Self::DecodeError> {
        let effects = buf[..].to_vec();
        let len = effects.len();

        Ok((TestPayload {
            effects: effects
        }, len))
    }
}

#[test]
fn test_uncommitted_req_header_hard_effects_no_instance() {
    let effects_header =
        XactUncommittedEffectsHeader::Effects(XactEffectsHeader {
            len: 0xfff0000ffff000,
            hard: true,
        });
    let header = XactUncommittedReqHeader {
        version: Version::new(1, 2, 3),
        class: vec![0x55; 16],
        effects: effects_header,
        instance: None,
        len: 0xaaaa5555aaaa5555,
    };
    let mut codec = XactUncommittedReqHeaderPERCodec::default();
    let mut buf = [0; XactUncommittedReqHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_uncommitted_req_header_soft_effects_no_instance() {
    let effects_header =
        XactUncommittedEffectsHeader::Effects(XactEffectsHeader {
            len: 0xfff0000ffff000,
            hard: false
        });
    let header = XactUncommittedReqHeader {
        version: Version::new(1, 2, 3),
        class: vec![0x55; 16],
        effects: effects_header,
        len: 0xaaaa5555aaaa5555,
        instance: None,
    };
    let mut codec = XactUncommittedReqHeaderPERCodec::default();
    let mut buf = [0; XactUncommittedReqHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_uncommitted_req_header_hard_effects_instance() {
    let effects_header =
        XactUncommittedEffectsHeader::Effects(XactEffectsHeader {
            len: 0xfff0000ffff000,
            hard: true
        });
    let header = XactUncommittedReqHeader {
        version: Version::new(1, 2, 3),
        class: vec![0x55; 16],
        effects: effects_header,
        len: 0xaaaa5555aaaa5555,
        instance: Some(0x1234567890abcdef),
    };
    let mut codec = XactUncommittedReqHeaderPERCodec::default();
    let mut buf = [0; XactUncommittedReqHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_uncommitted_req_header_soft_effects_instance() {
    let effects_header =
        XactUncommittedEffectsHeader::Effects(XactEffectsHeader {
            len: 0xfff0000ffff000,
            hard: false
        });
    let header = XactUncommittedReqHeader {
        version: Version::new(1, 2, 3),
        class: vec![0x55; 16],
        effects: effects_header,
        len: 0xaaaa5555aaaa5555,
        instance: Some(0x1234567890abcdef)
    };
    let mut codec = XactUncommittedReqHeaderPERCodec::default();
    let mut buf = [0; XactUncommittedReqHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_uncommitted_req_header_hard_none_no_linpoint_no_instance() {
    let effects_header =
        XactUncommittedEffectsHeader::HardNone(XactHardNone { when: None });
    let header = XactUncommittedReqHeader {
        version: Version::new(1, 2, 3),
        class: vec![0x55; 16],
        effects: effects_header,
        len: 0xaaaa5555aaaa5555,
        instance: None
    };
    let mut codec = XactUncommittedReqHeaderPERCodec::default();
    let mut buf = [0; XactUncommittedReqHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_uncommitted_req_header_hard_none_linpoint_no_instance() {
    let effects_header =
        XactUncommittedEffectsHeader::HardNone(XactHardNone {
            when: Some(XactLinPointHeader {
                round: vec![0x88; 16],
                idx: 0x7
            })
        });
    let header = XactUncommittedReqHeader {
        version: Version::new(1, 2, 3),
        class: vec![0x55; 16],
        effects: effects_header,
        len: 0xaaaa5555aaaa5555,
        instance: None
    };
    let mut codec = XactUncommittedReqHeaderPERCodec::default();
    let mut buf = [0; XactUncommittedReqHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_uncommitted_req_header_hard_none_no_linpoint_instance() {
    let effects_header =
        XactUncommittedEffectsHeader::HardNone(XactHardNone { when: None });
    let header = XactUncommittedReqHeader {
        version: Version::new(1, 2, 3),
        class: vec![0x55; 16],
        effects: effects_header,
        len: 0xaaaa5555aaaa5555,
        instance: Some(0x1234567890abcdef)
    };
    let mut codec = XactUncommittedReqHeaderPERCodec::default();
    let mut buf = [0; XactUncommittedReqHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_uncommitted_req_header_hard_none_linpoint_instance() {
    let effects_header =
        XactUncommittedEffectsHeader::HardNone(XactHardNone {
            when: Some(XactLinPointHeader {
                round: vec![0x88; 16],
                idx: 0x7
            })
        });
    let header = XactUncommittedReqHeader {
        version: Version::new(1, 2, 3),
        class: vec![0x55; 16],
        effects: effects_header,
        len: 0xaaaa5555aaaa5555,
        instance: Some(0x1234567890abcdef)
    };
    let mut codec = XactUncommittedReqHeaderPERCodec::default();
    let mut buf = [0; XactUncommittedReqHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_uncommitted_req_header_soft_none_no_linpoint_no_instance() {
    let effects_header =
        XactUncommittedEffectsHeader::SoftNone(Default::default());
    let header = XactUncommittedReqHeader {
        version: Version::new(1, 2, 3),
        class: vec![0x55; 16],
        effects: effects_header,
        len: 0xaaaa5555aaaa5555,
        instance: None
    };
    let mut codec = XactUncommittedReqHeaderPERCodec::default();
    let mut buf = [0; XactUncommittedReqHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_uncommitted_req_header_soft_none_instance() {
    let effects_header =
        XactUncommittedEffectsHeader::SoftNone(Default::default());
    let header = XactUncommittedReqHeader {
        version: Version::new(1, 2, 3),
        class: vec![0x55; 16],
        effects: effects_header,
        len: 0xaaaa5555aaaa5555,
        instance: Some(0x1234567890abcdef)
    };
    let mut codec = XactUncommittedReqHeaderPERCodec::default();
    let mut buf = [0; XactUncommittedReqHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_uncommitted_req_hard_effects_no_instance() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::Effects {
        effects: TestEffects {
            effects: vec![0, 1, 2]
        },
        hard: true
    };
    let req = XactUncommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: None,
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let mut codec: XactUncommittedReqCodec<u128, _, _,
                                           TestPayloadCodec,
                                           TestEffectsCodec> =
        XactUncommittedReqCodec::create(((), ()))
        .expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_soft_effects_no_instance() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::Effects {
        effects: TestEffects {
            effects: vec![0, 1, 2]
        },
        hard: false
    };
    let req = XactUncommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: None,
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let mut codec: XactUncommittedReqCodec<u128, _, _,
                                           TestPayloadCodec,
                                           TestEffectsCodec> =
        XactUncommittedReqCodec::create(((), ()))
        .expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_hard_effects_instance() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::Effects {
        effects: TestEffects {
            effects: vec![0, 1, 2]
        },
        hard: true
    };
    let req = XactUncommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: Some(0x1234567890abcdef),
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let mut codec: XactUncommittedReqCodec<u128, _, _,
                                           TestPayloadCodec,
                                           TestEffectsCodec> =
        XactUncommittedReqCodec::create(((), ()))
        .expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_soft_effects_instance() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::Effects {
        effects: TestEffects {
            effects: vec![0, 1, 2]
        },
        hard: false
    };
    let req = XactUncommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: Some(0x1234567890abcdef),
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let mut codec: XactUncommittedReqCodec<u128, _, _,
                                           TestPayloadCodec,
                                           TestEffectsCodec> =
        XactUncommittedReqCodec::create(((), ()))
        .expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_hard_none_no_linpoint_no_instance() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::HardNone {
        when: None
    };
    let req = XactUncommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: None,
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let mut codec: XactUncommittedReqCodec<u128, _, _,
                                           TestPayloadCodec,
                                           TestEffectsCodec> =
        XactUncommittedReqCodec::create(((), ()))
        .expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_hard_none_linpoint_no_instance() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::HardNone {
        when: Some(XactLinPoint {
            round: 0x1234567890abcdef,
            idx: 0x0f
        })
    };
    let req = XactUncommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: None,
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let mut codec: XactUncommittedReqCodec<u128, _, _,
                                           TestPayloadCodec,
                                           TestEffectsCodec> =
        XactUncommittedReqCodec::create(((), ()))
        .expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_hard_none_no_linpoint_instance() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::HardNone {
        when: None
    };
    let req = XactUncommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: Some(0x1234567890abcdef),
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let mut codec: XactUncommittedReqCodec<u128, _, _,
                                           TestPayloadCodec,
                                           TestEffectsCodec> =
        XactUncommittedReqCodec::create(((), ()))
        .expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_hard_none_linpoint_instance() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::HardNone {
        when: Some(XactLinPoint {
            round: 0x1234567890abcdef,
            idx: 0x0f
        })
    };
    let req = XactUncommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: Some(0x1234567890abcdef),
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let mut codec: XactUncommittedReqCodec<u128, _, _,
                                           TestPayloadCodec,
                                           TestEffectsCodec> =
        XactUncommittedReqCodec::create(((), ()))
        .expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}




#[test]
fn test_uncommitted_req_soft_none_no_linpoint_no_instance() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::SoftNone;
    let req = XactUncommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: None,
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let mut codec: XactUncommittedReqCodec<u128, _, _,
                                           TestPayloadCodec,
                                           TestEffectsCodec> =
        XactUncommittedReqCodec::create(((), ()))
        .expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_soft_none_no_linpoint_instance() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::SoftNone;
    let req = XactUncommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: Some(0x1234567890abcdef),
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let mut codec: XactUncommittedReqCodec<u128, _, _,
                                           TestPayloadCodec,
                                           TestEffectsCodec> =
        XactUncommittedReqCodec::create(((), ()))
        .expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_hard_effects_no_instance_blob() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::Effects {
        effects: vec![2, 1, 0],
        hard: true
    };
    let mut codec: XactUncommittedReqBlobCodec<SHA3Algo, u128> =
        XactUncommittedReqBlobCodec::create(())
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(
        &[0x2a, 0x8b, 0xef, 0x99, 0x3f, 0x68, 0xc3, 0x71,
          0x7f, 0xea, 0x5d, 0xeb, 0x06, 0x14, 0x9a, 0xaa,
          0xe4, 0x59, 0x55, 0x7f, 0x84, 0x7d, 0x74, 0x0a,
          0x37, 0xb5, 0xa8, 0x39, 0xa5, 0xb5, 0x0a, 0x0c,
          0xd4, 0x19, 0xf8, 0x36, 0x46, 0xa5, 0xf0, 0xda,
          0xbf, 0xae, 0x60, 0x69, 0x4f, 0xfb, 0x11, 0x19,
          0x64, 0x7b, 0xfa, 0x32, 0x86, 0xbf, 0x5b, 0x5a,
          0xe1, 0x09, 0xe4, 0x38, 0x9b, 0x20, 0x0a, 0x83]
    ).expect("Expected success");
    let req = XactUncommittedHashReq {
        hash: hash,
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: None,
        payload: vec![0, 1, 2, 3, 4, 5]
    };
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}



/*

#[test]
fn test_uncommitted_req_soft_effects_no_instance() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::Effects {
        effects: TestEffects {
            effects: vec![0, 1, 2]
        },
        hard: false
    };
    let req = XactUncommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: None,
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let mut codec: XactUncommittedReqCodec<u128, _, _,
                                           TestPayloadCodec,
                                           TestEffectsCodec> =
        XactUncommittedReqCodec::create(((), ()))
        .expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_hard_effects_instance() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::Effects {
        effects: TestEffects {
            effects: vec![0, 1, 2]
        },
        hard: true
    };
    let req = XactUncommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: Some(0x1234567890abcdef),
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let mut codec: XactUncommittedReqCodec<u128, _, _,
                                           TestPayloadCodec,
                                           TestEffectsCodec> =
        XactUncommittedReqCodec::create(((), ()))
        .expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_soft_effects_instance() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::Effects {
        effects: TestEffects {
            effects: vec![0, 1, 2]
        },
        hard: false
    };
    let req = XactUncommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: Some(0x1234567890abcdef),
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let mut codec: XactUncommittedReqCodec<u128, _, _,
                                           TestPayloadCodec,
                                           TestEffectsCodec> =
        XactUncommittedReqCodec::create(((), ()))
        .expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_hard_none_no_linpoint_no_instance() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::HardNone {
        when: None
    };
    let req = XactUncommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: None,
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let mut codec: XactUncommittedReqCodec<u128, _, _,
                                           TestPayloadCodec,
                                           TestEffectsCodec> =
        XactUncommittedReqCodec::create(((), ()))
        .expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_hard_none_linpoint_no_instance() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::HardNone {
        when: Some(XactLinPoint {
            round: 0x1234567890abcdef,
            idx: 0x0f
        })
    };
    let req = XactUncommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: None,
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let mut codec: XactUncommittedReqCodec<u128, _, _,
                                           TestPayloadCodec,
                                           TestEffectsCodec> =
        XactUncommittedReqCodec::create(((), ()))
        .expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_hard_none_no_linpoint_instance() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::HardNone {
        when: None
    };
    let req = XactUncommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: Some(0x1234567890abcdef),
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let mut codec: XactUncommittedReqCodec<u128, _, _,
                                           TestPayloadCodec,
                                           TestEffectsCodec> =
        XactUncommittedReqCodec::create(((), ()))
        .expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_hard_none_linpoint_instance() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::HardNone {
        when: Some(XactLinPoint {
            round: 0x1234567890abcdef,
            idx: 0x0f
        })
    };
    let req = XactUncommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: Some(0x1234567890abcdef),
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let mut codec: XactUncommittedReqCodec<u128, _, _,
                                           TestPayloadCodec,
                                           TestEffectsCodec> =
        XactUncommittedReqCodec::create(((), ()))
        .expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}




#[test]
fn test_uncommitted_req_soft_none_no_linpoint_no_instance() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::SoftNone;
    let req = XactUncommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: None,
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let mut codec: XactUncommittedReqCodec<u128, _, _,
                                           TestPayloadCodec,
                                           TestEffectsCodec> =
        XactUncommittedReqCodec::create(((), ()))
        .expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_soft_none_no_linpoint_instance() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::SoftNone;
    let req = XactUncommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: Some(0x1234567890abcdef),
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let mut codec: XactUncommittedReqCodec<u128, _, _,
                                           TestPayloadCodec,
                                           TestEffectsCodec> =
        XactUncommittedReqCodec::create(((), ()))
        .expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}
*/


#[test]
fn test_uncommitted_req_hard_effects_no_instance_hash() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::Effects {
        effects: TestEffects {
            effects: vec![2, 1, 0]
        },
        hard: true
    };
    let mut codec: XactUncommittedReqHashCodec<SHA3Algo, u128, _, _,
                                               TestPayloadCodec,
                                               TestEffectsCodec> =
        XactUncommittedReqHashCodec::create(((), ()))
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(
        &[0x2a, 0x8b, 0xef, 0x99, 0x3f, 0x68, 0xc3, 0x71,
          0x7f, 0xea, 0x5d, 0xeb, 0x06, 0x14, 0x9a, 0xaa,
          0xe4, 0x59, 0x55, 0x7f, 0x84, 0x7d, 0x74, 0x0a,
          0x37, 0xb5, 0xa8, 0x39, 0xa5, 0xb5, 0x0a, 0x0c,
          0xd4, 0x19, 0xf8, 0x36, 0x46, 0xa5, 0xf0, 0xda,
          0xbf, 0xae, 0x60, 0x69, 0x4f, 0xfb, 0x11, 0x19,
          0x64, 0x7b, 0xfa, 0x32, 0x86, 0xbf, 0x5b, 0x5a,
          0xe1, 0x09, 0xe4, 0x38, 0x9b, 0x20, 0x0a, 0x83]
    ).expect("Expected success");
    let req = XactUncommittedHashReq {
        hash: hash,
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: None,
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}






#[test]
fn test_committed_req_header_no_effects_no_instance() {
    let header = XactCommittedReqHeader {
        version: Version::new(1, 2, 3),
        class: vec![0x55; 16],
        instance: None,
        idx: 0x0e,
        effects: None,
        len: 0xaaaa5555aaaa5555,
    };
    let mut codec = XactCommittedReqHeaderPERCodec::default();
    let mut buf = [0; XactCommittedReqHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_committed_req_header_no_effects_instance() {
    let header = XactCommittedReqHeader {
        version: Version::new(1, 2, 3),
        class: vec![0x55; 16],
        instance: Some(0x1234567890abcdef),
        idx: 0x0e,
        effects: None,
        len: 0xaaaa5555aaaa5555,
    };
    let mut codec = XactCommittedReqHeaderPERCodec::default();
    let mut buf = [0; XactCommittedReqHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_committed_req_header_effects_no_instance() {
    let header = XactCommittedReqHeader {
        version: Version::new(1, 2, 3),
        class: vec![0x55; 16],
        instance: None,
        idx: 0x0e,
        effects: Some(XactEffectsHeader {
            len: 0xfff0000ffff000,
            hard: true,
        }),
        len: 0xaaaa5555aaaa5555,
    };
    let mut codec = XactCommittedReqHeaderPERCodec::default();
    let mut buf = [0; XactCommittedReqHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_committed_req_header_effects_instance() {
    let header = XactCommittedReqHeader {
        version: Version::new(1, 2, 3),
        class: vec![0x55; 16],
        instance: Some(0x1234567890abcdef),
        idx: 0x0e,
        effects: Some(XactEffectsHeader {
            len: 0xfff0000ffff000,
            hard: true,
        }),
        len: 0xaaaa5555aaaa5555,
    };
    let mut codec = XactCommittedReqHeaderPERCodec::default();
    let mut buf = [0; XactCommittedReqHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_committed_no_effects_no_instance() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let req = XactCommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: None,
        instance: None,
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        },
        idx: 0x0e
    };
    let mut codec: XactCommittedReqCodec<_, _,
                                         TestPayloadCodec,
                                         TestEffectsCodec> =
        XactCommittedReqCodec::create(((), ()))
        .expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_committed_effects_no_instance() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let req = XactCommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: Some(XactCommittedEffects {
            effects: TestEffects {
                effects: vec![0, 1, 2]
            },
            hard: true
        }),
        instance: None,
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        },
        idx: 0x0e
    };
    let mut codec: XactCommittedReqCodec<_, _,
                                         TestPayloadCodec,
                                         TestEffectsCodec> =
        XactCommittedReqCodec::create(((), ()))
        .expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_committed_no_effects_instance() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let req = XactCommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: None,
        instance: Some(0x1234567890abcdef),
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        },
        idx: 0x0e
    };
    let mut codec: XactCommittedReqCodec<_, _,
                                         TestPayloadCodec,
                                         TestEffectsCodec> =
        XactCommittedReqCodec::create(((), ()))
        .expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_committed_effects_instance() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let req = XactCommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: Some(XactCommittedEffects {
            effects: TestEffects {
                effects: vec![0, 1, 2]
            },
            hard: true
        }),
        instance: Some(0x1234567890abcdef),
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        },
        idx: 0x0e
    };
    let mut codec: XactCommittedReqCodec<_, _,
                                         TestPayloadCodec,
                                         TestEffectsCodec> =
        XactCommittedReqCodec::create(((), ()))
        .expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_committed_no_effects_no_instance_blob() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let req = XactCommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: None,
        instance: None,
        payload: vec![0, 1, 2, 3, 4, 5],
        idx: 0x0e
    };
    let mut codec: XactCommittedReqBlobCodec =
        XactCommittedReqBlobCodec::create(())
        .expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_committed_effects_no_instance_blob() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let req = XactCommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: Some(XactCommittedEffects {
            effects: vec![0, 1, 2],
            hard: true
        }),
        instance: None,
        payload: vec![0, 1, 2, 3, 4, 5],
        idx: 0x0e
    };
    let mut codec: XactCommittedReqBlobCodec =
        XactCommittedReqBlobCodec::create(())
        .expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_committed_no_effects_instance_blob() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let req = XactCommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: None,
        instance: Some(0x1234567890abcdef),
        payload: vec![0, 1, 2, 3, 4, 5],
        idx: 0x0e
    };
    let mut codec: XactCommittedReqBlobCodec =
        XactCommittedReqBlobCodec::create(())
        .expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_committed_effects_instance_blob() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let req = XactCommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: Some(XactCommittedEffects {
            effects: vec![0, 1, 2],
            hard: true
        }),
        instance: Some(0x1234567890abcdef),
        payload: vec![0, 1, 2, 3, 4, 5],
        idx: 0x0e
    };
    let mut codec: XactCommittedReqBlobCodec =
        XactCommittedReqBlobCodec::create(())
        .expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}
