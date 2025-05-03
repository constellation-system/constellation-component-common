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
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;
use std::iter::once;
use std::marker::PhantomData;

use constellation_common::codec::per::PERCodec;
use constellation_common::codec::Codec;
use constellation_common::codec::DatagramCodec;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::hashid::HashAlgo;
use constellation_common::hashid::HashID;
use constellation_common::version::Version;
use uuid::Uuid;

use crate::generated::xact::XactBatchHeader;
use crate::generated::xact::XactCommittedReqHeader;
use crate::generated::xact::XactCommittedRoundHeader;
use crate::generated::xact::XactConsensusSealHeader;
use crate::generated::xact::XactEffectsHeader;
use crate::generated::xact::XactErrorHeader;
use crate::generated::xact::XactHardNone;
use crate::generated::xact::XactNotifyHeader;
use crate::generated::xact::XactNotifyStateHeader;
use crate::generated::xact::XactResultHeader;
use crate::generated::xact::XactResultValueHeader;
use crate::generated::xact::XactSealHeader;
use crate::generated::xact::XactUncommittedEffectsHeader;
use crate::generated::xact::XactUncommittedReqHeader;
use crate::generated::xact::XactValueHeader;

const XACT_UNCOMMITTED_REQ_HEADER_SIZE: usize = 55;
const XACT_UNCOMMITTED_REQ_HEADER_BITS: usize =
    XACT_UNCOMMITTED_REQ_HEADER_SIZE * 8;

const XACT_COMMITTED_REQ_HEADER_SIZE: usize = 48;
const XACT_COMMITTED_REQ_HEADER_BITS: usize =
    XACT_COMMITTED_REQ_HEADER_SIZE * 8;

const XACT_RESULT_HEADER_SIZE: usize = 74;
const XACT_RESULT_HEADER_BITS: usize = XACT_RESULT_HEADER_SIZE * 8;

const XACT_SEAL_HEADER_SIZE: usize = 9;
const XACT_SEAL_HEADER_BITS: usize = XACT_SEAL_HEADER_SIZE * 8;

const XACT_COMMITTED_ROUND_HEADER_SIZE: usize = 1051;
const XACT_COMMITTED_ROUND_HEADER_BITS: usize =
    XACT_COMMITTED_ROUND_HEADER_SIZE * 8;

const XACT_NOTIFY_HEADER_SIZE: usize = 81;
const XACT_NOTIFY_HEADER_BITS: usize = XACT_NOTIFY_HEADER_SIZE * 8;

const XACT_BATCH_HEADER_SIZE: usize = 12;
const XACT_BATCH_HEADER_BITS: usize = XACT_BATCH_HEADER_SIZE * 8;

type XactUncommittedReqHeaderPERCodec =
    PERCodec<XactUncommittedReqHeader, XACT_UNCOMMITTED_REQ_HEADER_BITS>;

type XactCommittedReqHeaderPERCodec =
    PERCodec<XactCommittedReqHeader, XACT_COMMITTED_REQ_HEADER_BITS>;

type XactCommittedRoundHeaderPERCodec =
    PERCodec<XactCommittedRoundHeader, XACT_COMMITTED_ROUND_HEADER_BITS>;

type XactResultHeaderPERCodec =
    PERCodec<XactResultHeader, XACT_RESULT_HEADER_BITS>;

type XactSealHeaderPERCodec =
    PERCodec<XactSealHeader, XACT_SEAL_HEADER_BITS>;

type XactNotifyHeaderPERCodec =
    PERCodec<XactNotifyHeader, XACT_NOTIFY_HEADER_BITS>;

type XactBatchHeaderPERCodec =
    PERCodec<XactBatchHeader, XACT_BATCH_HEADER_BITS>;

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

/// Object carrying a seal.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct XactSealed<Seal, Inner> {
    /// The inner object.
    inner: Inner,
    /// The seal type.
    seal: Seal
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

/// Consensus seal information.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct XactConsensusSeal<H, Seal> {
    /// The hashes in the consensus round.
    hashes: Vec<H>,
    /// The seals.
    seals: Vec<Seal>
}

/// Committed round together with some number of the transactions.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct XactCommittedRound<RoundID, H, Seal, Payload, Effects> {
    /// ID of the round.
    round: RoundID,
    /// Consensus seal, if present.
    seal: Option<XactConsensusSeal<H, Seal>>,
    /// Transaction requests.
    reqs: Vec<XactCommittedReq<Payload, Effects>>
}

/// Errors that can occur executing a transaction request.
///
/// These represent errors that occurred at the processor, and were
/// reported back to the requestor.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum XactError<Err> {
    /// Application-level error.
    Error {
        /// The application-level error.
        err: Err
    },
    /// Transaction class was not known to the processor or peer.
    UnknownClass,
    /// Transaction class was known, but the requested version was not
    /// supported.
    UnknownVersion,
    /// Transaction class and version were known, but the instance was not.
    UnknownInstance,
    /// Errors occurred parsing the request.
    InvalidPayload,
    /// Errors occurred parsing the effect descriptions.
    InvalidEffect,
    /// A hard effect constraint was violated during execution.
    EffectViolation,
    /// Transaction was not properly authorized.
    Unauthorized,
    /// Internal error occurred during execution.
    Internal
}

/// Result for a transaction request.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct XactResult<H, Res, Err>
where
    H: HashID {
    /// Hash of the transaction request that produced the result.
    hash: H,
    /// The result of execution.
    res: Result<Res, XactError<Err>>
}

/// Notifications that can occur for a transaction request.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum XactNotifyState<RoundID>
where RoundID: Clone + From<u128> + Into<u128> {
    /// The transaction has been accepted by a peer.
    Accept,
    /// The transaction has been submitted to a consensus pool.
    Consensus,
    /// A batch containing the transaction has been committed by the
    /// consensus pool.
    Commit {
        when: XactLinPoint<RoundID>
    },
    /// The transaction has been dispatched to a processor.
    Dispatch,
    /// The transaction has been executed by at least one processor.
    Complete {
        when: XactLinPoint<RoundID>
    }
}

/// Notifications about the state of a transaction request.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct XactNotify<RoundID, H>
where RoundID: Clone + From<u128> + Into<u128>,
      H: HashID {
    /// Notification state.
    state: XactNotifyState<RoundID>,
    /// Hash of the request.
    hash: H
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct XactBatch<RoundID, H, Seal, Payload, Effects, Res, Err>
where RoundID: Clone + From<u128> + Into<u128>,
      H: HashID {
    committed: Vec<XactCommittedRound<RoundID, H, Seal, Payload, Effects>>,
    reqs: Vec<XactSealed<Seal, XactUncommittedReq<RoundID, Payload, Effects>>>,
    results: Vec<XactResult<H, Res, Err>>,
    notifies: Vec<XactNotify<RoundID, H>>
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct XactHashBatch<RoundID, H, Seal, Payload, Effects, Res, Err>
where RoundID: Clone + From<u128> + Into<u128>,
      H: HashID {
    committed: Vec<XactCommittedRound<RoundID, H, Seal, Payload, Effects>>,
    reqs: Vec<
        XactSealed<Seal, XactUncommittedHashReq<RoundID, H, Payload, Effects>>
    >,
    results: Vec<XactResult<H, Res, Err>>,
    notifies: Vec<XactNotify<RoundID, H>>
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
pub struct XactUncommittedReqHashCodec<RoundID, H, Payload, Effect,
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
pub struct XactUncommittedReqBlobCodec<RoundID, H>
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

#[derive(Clone)]
pub struct XactCommittedRoundCodec<RoundID, H, Seal, Payload, Effect,
                                   SealCodec, PayloadCodec, EffectCodec>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: HashAlgo,
    H::HashID: Clone,
    PayloadCodec: Codec<Payload>,
    EffectCodec: Codec<Effect>,
    SealCodec: Codec<Seal> {
    payload: PhantomData<Payload>,
    effect: PhantomData<Effect>,
    seal: PhantomData<Seal>,
    round: PhantomData<RoundID>,
    header_codec: XactCommittedRoundHeaderPERCodec,
    seal_header_codec: XactSealHeaderPERCodec,
    req_codec: XactCommittedReqCodec<Payload, Effect,
                                     PayloadCodec, EffectCodec>,
    seal_codec: SealCodec,
    hash: H
}

#[derive(Clone)]
pub struct XactCommittedRoundBlobCodec<RoundID, H, Seal, SealCodec>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: HashAlgo,
    H::HashID: Clone,
    SealCodec: Codec<Seal> {
    seal: PhantomData<Seal>,
    round: PhantomData<RoundID>,
    header_codec: XactCommittedRoundHeaderPERCodec,
    seal_header_codec: XactSealHeaderPERCodec,
    req_codec: XactCommittedReqBlobCodec,
    seal_codec: SealCodec,
    hash: H
}

#[derive(Clone)]
pub struct XactSealedCodec<Seal, Inner, SealCodec, InnerCodec>
where
    InnerCodec: Codec<Inner>,
    SealCodec: Codec<Seal> {
    inner: PhantomData<Inner>,
    seal: PhantomData<Seal>,
    header_codec: XactSealHeaderPERCodec,
    inner_codec: InnerCodec,
    seal_codec: SealCodec,
}

#[derive(Clone)]
pub struct XactSealedBlobCodec<Inner, InnerCodec>
where
    InnerCodec: Codec<Inner> {
    inner: PhantomData<Inner>,
    header_codec: XactSealHeaderPERCodec,
    inner_codec: InnerCodec,
}

#[derive(Clone)]
pub struct XactResultCodec<H, Res, Err, ResCodec, ErrCodec>
where
    H: HashAlgo,
    H::HashID: Clone,
    ResCodec: Codec<Res>,
    ErrCodec: Codec<Err> {
    res: PhantomData<Res>,
    err: PhantomData<Err>,
    res_codec: ResCodec,
    err_codec: ErrCodec,
    header_codec: XactResultHeaderPERCodec,
    hash: H
}

#[derive(Clone)]
pub struct XactResultBlobCodec<H>
where
    H: Clone + HashAlgo,
    H::HashID: Clone {
    header_codec: XactResultHeaderPERCodec,
    hash: H
}

#[derive(Clone)]
pub struct XactBatchCodec<RoundID, H, Seal, Payload, Effect, Res, Err,
                          SealCodec, PayloadCodec, EffectCodec,
                          ResCodec, ErrCodec>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: HashAlgo,
    H::HashID: Clone,
    PayloadCodec: Codec<Payload>,
    EffectCodec: Codec<Effect>,
    SealCodec: Codec<Seal>,
    ResCodec: Codec<Res>,
    ErrCodec: Codec<Err> {
    header_codec: XactBatchHeaderPERCodec,
    committed_codec: XactCommittedRoundCodec<RoundID, H, Seal, Payload, Effect,
                                             SealCodec, PayloadCodec,
                                             EffectCodec>,
    req_codec: XactSealedCodec<
        Seal,
        XactUncommittedReq<RoundID, Payload, Effect>,
        SealCodec,
        XactUncommittedReqCodec<RoundID, Payload, Effect,
                                PayloadCodec, EffectCodec>
    >,
    res_codec: XactResultCodec<H, Res, Err, ResCodec, ErrCodec>,
    notify_codec: XactNotifyHeaderPERCodec,
    hash: H
}

#[derive(Clone)]
pub struct XactBatchHashCodec<RoundID, H, Seal, Payload, Effect, Res, Err,
                              SealCodec, PayloadCodec, EffectCodec,
                              ResCodec, ErrCodec>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: Default + HashAlgo,
    H::HashID: Clone,
    PayloadCodec: Codec<Payload>,
    EffectCodec: Codec<Effect>,
    SealCodec: Codec<Seal>,
    ResCodec: Codec<Res>,
    ErrCodec: Codec<Err> {
    header_codec: XactBatchHeaderPERCodec,
    committed_codec: XactCommittedRoundCodec<RoundID, H, Seal, Payload, Effect,
                                             SealCodec, PayloadCodec,
                                             EffectCodec>,
    req_codec: XactSealedCodec<
        Seal,
        XactUncommittedHashReq<RoundID, H::HashID, Payload, Effect>,
        SealCodec,
        XactUncommittedReqHashCodec<RoundID, H, Payload, Effect,
                                    PayloadCodec, EffectCodec>
    >,
    res_codec: XactResultCodec<H, Res, Err, ResCodec, ErrCodec>,
    notify_codec: XactNotifyHeaderPERCodec,
    hash: H
}

#[derive(Clone)]
pub struct XactBatchBlobCodec<RoundID, H, Seal, SealCodec>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: Clone + Default + HashAlgo,
    H::HashID: Clone,
    SealCodec: Codec<Seal> {
    header_codec: XactBatchHeaderPERCodec,
    committed_codec: XactCommittedRoundBlobCodec<RoundID, H, Seal,
                                                 SealCodec>,
    req_codec: XactSealedCodec<
        Seal,
        XactUncommittedHashReq<RoundID, H::HashID, Vec<u8>, Vec<u8>>,
        SealCodec,
        XactUncommittedReqBlobCodec<RoundID, H>
    >,
    res_codec: XactResultBlobCodec<H>,
    notify_codec: XactNotifyHeaderPERCodec,
    hash: H
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
    /// Provided buffer was too short.
    TooShort
}

/// Errors that can occur creating an [XactCommittedRoundCodec].
#[derive(Debug)]
pub enum XactCommittedRoundCodecCreateError<Seal, Req> {
    /// Error occurred creating the seal codec.
    Seal {
        /// The error that occurred creating the seal codec.
        err: Seal
    },
    /// Error occurred creating the req codec.
    Req {
        /// The error that occurred creating the req codec.
        err: Req
    },
}

/// Errors that can occur in an [XactCommittedRoundCodec].
#[derive(Debug)]
pub enum XactCommittedRoundCodecEncodeError<Header, Seal, Req> {
    /// Error occurred writing the header.
    Header {
        /// Error that occurred writing the header.
        err: Header
    },
    /// Error occurred in the seal codec.
    Seal {
        /// The error that occurred in the seal codec.
        err: Seal
    },
    /// Error occurred in the req codec.
    Req {
        /// The error that occurred in the req codec.
        err: Req
    },
    /// Provided buffer was too short.
    TooShort
}

/// Errors that can occur in an [XactCommittedRoundCodec].
#[derive(Debug)]
pub enum XactCommittedRoundCodecDecodeError<Header, Seal, Req> {
    /// Error occurred parsing the round ID.
    Round {
        /// Error that occurred parsing the round ID.
        err: Vec<u8>
    },
    /// Error occurred writing the header.
    Header {
        /// Error that occurred writing the header.
        err: Header
    },
    /// Error occurred in the seal codec.
    Seal {
        /// The error that occurred in the seal codec.
        err: Seal
    },
    /// Error occurred decoding the hash data.
    ///
    /// This should normally never happen.
    Hash {
        /// Error that occurred decoding out the hash data.
        err: TryFromSliceError
    },
    /// Error occurred in the req codec.
    Req {
        /// The error that occurred in the req codec.
        err: Req
    },
    /// Provided buffer was too short.
    TooShort
}

/// Errors that can occur creating an [XactSealedCodec].
#[derive(Debug)]
pub enum XactSealedCodecCreateError<Seal, Inner> {
    /// Error occurred creating the seal codec.
    Seal {
        /// The error that occurred creating the seal codec.
        err: Seal
    },
    /// Error occurred creating the inner codec.
    Inner {
        /// The error that occurred creating the inner codec.
        err: Inner
    }
}

/// Errors that can occur in an [XactSealedCodec].
#[derive(Debug)]
pub enum XactSealedCodecError<Header, Seal, Inner> {
    /// Error occurred writing the header.
    Header {
        /// Error that occurred writing the header.
        err: Header
    },
    /// Error occurred in the seal codec.
    Seal {
        /// The error that occurred in the seal codec.
        err: Seal
    },
    /// Error occurred in the inner codec.
    Inner {
        /// The error that occurred in the inner codec.
        err: Inner
    },
    /// Provided buffer was too short.
    TooShort
}

/// Errors that can occur creating an [XactResultCodec].
#[derive(Debug)]
pub enum XactResultCodecCreateError<Res, Err> {
    /// Error occurred creating the result codec.
    Res {
        /// The error that occurred creating the result codec.
        err: Res
    },
    /// Error occurred creating the error codec.
    Err {
        /// The error that occurred creating the error codec.
        err: Err
    }
}

/// Errors that can occur in an [XactResultCodec].
#[derive(Debug)]
pub enum XactResultCodecEncodeError<Header, Res, Err> {
    /// Error occurred writing the header.
    Header {
        /// Error that occurred writing the header.
        err: Header
    },
    /// Error occurred in the result codec.
    Res {
        /// The error that occurred in the result codec.
        err: Res
    },
    /// Error occurred in the error codec.
    Err {
        /// The error that occurred in the error codec.
        err: Err
    },
    /// Supplied buffer was too short.
    TooShort
}

/// Errors that can occur in an [XactResultCodec].
#[derive(Debug)]
pub enum XactResultCodecDecodeError<Header, Res, Err> {
    /// Error occurred writing the header.
    Header {
        /// Error that occurred writing the header.
        err: Header
    },
    /// Error occurred in the result codec.
    Res {
        /// The error that occurred in the result codec.
        err: Res
    },
    /// Error occurred in the error codec.
    Err {
        /// The error that occurred in the error codec.
        err: Err
    },
    /// Error occurred decoding the hash data.
    ///
    /// This should normally never happen.
    Hash {
        /// Error that occurred decoding out the hash data.
        err: TryFromSliceError
    },
    /// Supplied buffer was too short.
    TooShort
}

/// Errors that can occur creating an [XactBatchCodec].
#[derive(Debug)]
pub enum XactBatchCodecCreateError<Req, Committed, Res> {
    /// Error occurred creating the uncommitted request codec.
    Req {
        /// The error that occurred creating the uncommitted request codec.
        err: Req
    },
    /// Error occurred creating the committed round codec.
    Committed {
        /// The error that occurred creating the committed round codec.
        err: Committed
    },
    /// Error occurred creating the result codec.
    Res {
        /// The error that occurred creating the result codec.
        err: Res
    }
}

/// Errors that can occur encoding in an [XactBatchCodec].
#[derive(Debug)]
pub enum XactBatchCodecEncodeError<Header, Req, Committed, Res, Notify> {
    /// Error occurred writing the header.
    Header {
        /// Error that occurred writing the header.
        err: Header
    },
    /// Error occurred writing the uncommitted request.
    Req {
        /// The error that occurred writing the uncommitted request.
        err: Req
    },
    /// Error occurred writing the round codec.
    Committed {
        /// The error that occurred writing the committed round.
        err: Committed
    },
    /// Error occurred writing the result.
    Res {
        /// The error that occurred writing the result.
        err: Res
    },
    /// Error occurred writing the notification.
    Notify {
        /// The error that occurred writing the notification.
        err: Notify
    },
}

/// Errors that can occur decoding in an [XactBatchCodec].
#[derive(Debug)]
pub enum XactBatchCodecDecodeError<Header, Req, Committed, Res, Notify> {
    /// Error occurred writing the header.
    Header {
        /// Error that occurred writing the header.
        err: Header
    },
    /// Error occurred creating the uncommitted request codec.
    Req {
        /// The error that occurred creating the uncommitted request codec.
        err: Req
    },
    /// Error occurred creating the committed request codec.
    Committed {
        /// The error that occurred creating the committed request codec.
        err: Committed
    },
    /// Error occurred creating the result request codec.
    Res {
        /// The error that occurred creating the result request codec.
        err: Res
    },
    /// Error occurred creating the notify request codec.
    Notify {
        /// The error that occurred creating the Notify request codec.
        err: Notify
    },
    Hash {
        err: TryFromSliceError
    },
    State {
        err: Vec<u8>
    }
}

impl<RoundID, H, Seal, Payload, Effects>
    XactCommittedRound<RoundID, H, Seal, Payload, Effects> {
    #[inline]
    pub fn new(
        round: RoundID,
        seal: Option<XactConsensusSeal<H, Seal>>,
        reqs: Vec<XactCommittedReq<Payload, Effects>>
    ) -> Self {
        XactCommittedRound {
            round: round,
            seal: seal,
            reqs: reqs
        }
    }

    #[inline]
    pub fn round(&self) -> &RoundID {
        &self.round
    }

    #[inline]
    pub fn seal(&self) -> Option<&XactConsensusSeal<H, Seal>> {
        self.seal.as_ref()
    }

    #[inline]
    pub fn reqs(&self) -> &[XactCommittedReq<Payload, Effects>] {
        &self.reqs
    }

    #[inline]
    pub fn take(
        self
    ) -> (RoundID,
          Option<XactConsensusSeal<H, Seal>>,
          Vec<XactCommittedReq<Payload, Effects>>) {
        (self.round, self.seal, self.reqs)
    }
}

impl<Payload, Effects> XactCommittedReq<Payload, Effects> {
    #[inline]
    pub fn new(
        class: Uuid,
        version: Version,
        idx: usize,
        payload: Payload,
        effects: Option<XactCommittedEffects<Effects>>,
    ) -> Self {
        XactCommittedReq {
            class: class,
            version: version,
            instance: None,
            idx: idx,
            effects: effects,
            payload: payload
        }
    }

    #[inline]
    pub fn new_with_instance(
        class: Uuid,
        version: Version,
        instance: u64,
        idx: usize,
        payload: Payload,
        effects: Option<XactCommittedEffects<Effects>>,
    ) -> Self {
        XactCommittedReq {
            class: class,
            version: version,
            instance: Some(instance),
            idx: idx,
            effects: effects,
            payload: payload
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
    pub fn idx(&self) -> usize {
        self.idx
    }

    #[inline]
    pub fn effects(&self) -> Option<&XactCommittedEffects<Effects>> {
        self.effects.as_ref()
    }

    #[inline]
    pub fn payload(&self) -> &Payload {
        &self.payload
    }

    #[inline]
    pub fn take(self) -> (Uuid, Version, Option<u64>, usize,
                          Option<XactCommittedEffects<Effects>>, Payload) {
        (self.class, self.version, self.instance,
         self.idx, self.effects, self.payload)
    }
}

impl<RoundID, Payload, Effects> XactUncommittedReq<RoundID, Payload, Effects>
where RoundID: Clone + From<u128> + Into<u128> {
    #[inline]
    pub fn new(
        class: Uuid,
        version: Version,
        payload: Payload,
        effects: XactEffects<RoundID, Effects>,
    ) -> Self {
        XactUncommittedReq {
            class: class,
            version: version,
            instance: None,
            effects: effects,
            payload: payload
        }
    }

    #[inline]
    pub fn new_with_instance(
        class: Uuid,
        version: Version,
        instance: u64,
        payload: Payload,
        effects: XactEffects<RoundID, Effects>,
    ) -> Self {
        XactUncommittedReq {
            class: class,
            version: version,
            instance: Some(instance),
            effects: effects,
            payload: payload
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
    pub fn effects(&self) -> &XactEffects<RoundID, Effects> {
        &self.effects
    }

    #[inline]
    pub fn payload(&self) -> &Payload {
        &self.payload
    }

    #[inline]
    pub fn take(self) -> (Uuid, Version, Option<u64>,
                          XactEffects<RoundID, Effects>, Payload) {
        (self.class, self.version, self.instance, self.effects, self.payload)
    }
}

impl<RoundID, H, Payload, Effects>
    XactUncommittedHashReq<RoundID, H, Payload, Effects>
where RoundID: Clone + From<u128> + Into<u128>,
      H: HashID {
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
    pub fn hash(&self) -> &H {
        &self.hash
    }

    #[inline]
    pub fn effects(&self) -> &XactEffects<RoundID, Effects> {
        &self.effects
    }

    #[inline]
    pub fn payload(&self) -> &Payload {
        &self.payload
    }

    #[inline]
    pub fn take(self) -> (Uuid, Version, Option<u64>, H,
                          XactEffects<RoundID, Effects>, Payload) {
        (self.class, self.version, self.instance,
         self.hash, self.effects, self.payload)
    }
}

impl<Seal, Inner> XactSealed<Seal, Inner> {
    #[inline]
    pub fn new(
        seal: Seal,
        inner: Inner,
    ) -> Self {
        XactSealed {
            inner: inner,
            seal: seal
        }
    }

    #[inline]
    pub fn seal(&self) -> &Seal {
        &self.seal
    }

    #[inline]
    pub fn inner(&self) -> &Inner {
        &self.inner
    }

    #[inline]
    pub fn take(self) -> (Seal, Inner) {
        (self.seal, self.inner)
    }
}

impl<Effects> XactCommittedEffects<Effects> {
    #[inline]
    pub fn new(
        hard: bool,
        effects: Effects
    ) -> Self {
        XactCommittedEffects {
            effects: effects,
            hard: hard
        }
    }

    #[inline]
    pub fn hard(&self) -> bool {
        self.hard
    }

    #[inline]
    pub fn effects(&self) -> &Effects {
        &self.effects
    }

    #[inline]
    pub fn take(self) -> (bool, Effects) {
        (self.hard, self.effects)
    }
}

impl<H, Res, Err> XactResult<H, Res, Err>
where
    H: HashID {
    #[inline]
    pub fn new(
        hash: H,
        res: Result<Res, XactError<Err>>
    ) -> Self {
        XactResult {
            hash: hash,
            res: res
        }
    }

    #[inline]
    pub fn hash(&self) -> &H {
        &self.hash
    }

    #[inline]
    pub fn result(&self) -> Result<&Res, &XactError<Err>> {
        self.res.as_ref()
    }

    #[inline]
    pub fn take(self) -> (H, Result<Res, XactError<Err>>) {
        (self.hash, self.res)
    }
}

impl<RoundID, H> XactNotify<RoundID, H>
where RoundID: Clone + From<u128> + Into<u128>,
      H: HashID {
    #[inline]
    pub fn new(
        hash: H,
        state: XactNotifyState<RoundID>,
    ) -> Self {
        XactNotify {
            hash: hash,
            state: state
        }
    }

    #[inline]
    pub fn hash(&self) -> &H {
        &self.hash
    }

    #[inline]
    pub fn state(&self) -> &XactNotifyState<RoundID> {
        &self.state
    }

    #[inline]
    pub fn take(self) -> (H, XactNotifyState<RoundID>) {
        (self.hash, self.state)
    }
}

impl<RoundID, H, Seal, Payload, Effects, Res, Err>
    XactBatch<RoundID, H, Seal, Payload, Effects, Res, Err>
where RoundID: Clone + From<u128> + Into<u128>,
      H: HashID {
    #[inline]
    pub fn new(
        committed: Vec<XactCommittedRound<RoundID, H, Seal, Payload, Effects>>,
        reqs: Vec<XactSealed<Seal, XactUncommittedReq<RoundID, Payload, Effects>>>,
        results: Vec<XactResult<H, Res, Err>>,
        notifies: Vec<XactNotify<RoundID, H>>
    ) -> Self {
        XactBatch {
            committed: committed,
            reqs: reqs,
            results: results,
            notifies: notifies
        }
    }

    #[inline]
    pub fn committed(
        &self
    ) -> &[XactCommittedRound<RoundID, H, Seal, Payload, Effects>] {
        &self.committed
    }

    #[inline]
    pub fn uncommitted(
        &self
    ) -> &[XactSealed<Seal, XactUncommittedReq<RoundID, Payload, Effects>>] {
        &self.reqs
    }

    #[inline]
    pub fn results(
        &self
    ) -> &[XactResult<H, Res, Err>] {
        &self.results
    }

    #[inline]
    pub fn notifies(
        &self
    ) -> &[XactNotify<RoundID, H>] {
        &self.notifies
    }

    #[inline]
    pub fn take(
        self
    ) -> (Vec<XactCommittedRound<RoundID, H, Seal, Payload, Effects>>,
          Vec<XactSealed<Seal, XactUncommittedReq<RoundID, Payload, Effects>>>,
          Vec<XactResult<H, Res, Err>>,
          Vec<XactNotify<RoundID, H>>) {
        (self.committed, self.reqs, self.results, self.notifies)
    }
}

impl<RoundID, H, Seal, Payload, Effects, Res, Err>
    XactHashBatch<RoundID, H, Seal, Payload, Effects, Res, Err>
where RoundID: Clone + From<u128> + Into<u128>,
      H: HashID {
    #[inline]
    pub fn new(
        committed: Vec<XactCommittedRound<RoundID, H, Seal, Payload, Effects>>,
        reqs: Vec<XactSealed<Seal, XactUncommittedHashReq<RoundID, H, Payload,
                                                          Effects>>>,
        results: Vec<XactResult<H, Res, Err>>,
        notifies: Vec<XactNotify<RoundID, H>>
    ) -> Self {
        XactHashBatch {
            committed: committed,
            reqs: reqs,
            results: results,
            notifies: notifies
        }
    }

    #[inline]
    pub fn committed(
        &self
    ) -> &[XactCommittedRound<RoundID, H, Seal, Payload, Effects>] {
        &self.committed
    }

    #[inline]
    pub fn uncommitted(
        &self
    ) -> &[XactSealed<Seal, XactUncommittedHashReq<RoundID, H, Payload,
                                                   Effects>>] {
        &self.reqs
    }

    #[inline]
    pub fn results(
        &self
    ) -> &[XactResult<H, Res, Err>] {
        &self.results
    }

    #[inline]
    pub fn notifies(
        &self
    ) -> &[XactNotify<RoundID, H>] {
        &self.notifies
    }

    #[inline]
    pub fn take(
        self
    ) -> (Vec<XactCommittedRound<RoundID, H, Seal, Payload, Effects>>,
          Vec<XactSealed<Seal, XactUncommittedHashReq<RoundID, H,
                                                      Payload, Effects>>>,
          Vec<XactResult<H, Res, Err>>,
          Vec<XactNotify<RoundID, H>>) {
        (self.committed, self.reqs, self.results, self.notifies)
    }
}

impl<RoundID> TryFrom<&'_ crate::generated::xact::XactLinPoint>
    for XactLinPoint<RoundID>
where RoundID: Clone + From<u128> + Into<u128> {
    type Error = Vec<u8>;

    #[inline]
    fn try_from(
        val: &crate::generated::xact::XactLinPoint
    ) -> Result<Self, Self::Error> {
        let round = val.round.clone().try_into()?;
        let round = u128::from_le_bytes(round);

        Ok(XactLinPoint {
            round: round.into(),
            idx: val.idx
        })
    }
}

impl<RoundID> TryFrom<crate::generated::xact::XactLinPoint>
    for XactLinPoint<RoundID>
where RoundID: Clone + From<u128> + Into<u128> {
    type Error = Vec<u8>;

    #[inline]
    fn try_from(
        val: crate::generated::xact::XactLinPoint
    ) -> Result<Self, Self::Error> {
        Self::try_from(&val)
    }
}

impl<RoundID> From<&'_ XactLinPoint<RoundID>>
    for crate::generated::xact::XactLinPoint
where RoundID: Clone + From<u128> + Into<u128> {
    #[inline]
    fn from(val: &XactLinPoint<RoundID>) -> Self {
        let round: u128 = val.round.clone().into();
        let round = round.to_le_bytes().to_vec();

        crate::generated::xact::XactLinPoint {
            round: round,
            idx: val.idx
        }
    }
}

impl<RoundID> From<XactLinPoint<RoundID>>
    for crate::generated::xact::XactLinPoint
where RoundID: Clone + From<u128> + Into<u128> {
    #[inline]
    fn from(val: XactLinPoint<RoundID>) -> Self {
        Self::from(&val)
    }
}

impl<RoundID> TryFrom<XactNotifyStateHeader> for XactNotifyState<RoundID>
where RoundID: Clone + From<u128> + Into<u128> {
    type Error = Vec<u8>;

    #[inline]
    fn try_from(
        val: XactNotifyStateHeader
    ) -> Result<Self, Self::Error> {
        match val {
            XactNotifyStateHeader::Accept(_) =>
                Ok(XactNotifyState::Accept),
            XactNotifyStateHeader::Consensus(_) =>
                Ok(XactNotifyState::Consensus),
            XactNotifyStateHeader::Commit(state) =>
                Ok(XactNotifyState::Commit {
                    when: state.when.try_into()?
                }),
            XactNotifyStateHeader::Dispatch(_) =>
                Ok(XactNotifyState::Dispatch),
            XactNotifyStateHeader::Complete(state) =>
                Ok(XactNotifyState::Complete {
                    when: state.when.try_into()?
                }),
        }
    }
}

impl<RoundID> From<&'_ XactNotifyState<RoundID>>
    for XactNotifyStateHeader
where RoundID: Clone + From<u128> + Into<u128> {
    #[inline]
    fn from(
        val: &XactNotifyState<RoundID>
    ) -> Self {
        match val {
            XactNotifyState::Accept =>
                XactNotifyStateHeader::Accept(Default::default()),
            XactNotifyState::Consensus =>
                XactNotifyStateHeader::Consensus(Default::default()),
            XactNotifyState::Commit { when } => {
                let state = crate::generated::xact::XactCommitState {
                    when: when.into()
                };

                XactNotifyStateHeader::Commit(state)
            },
            XactNotifyState::Dispatch =>
                XactNotifyStateHeader::Dispatch(Default::default()),
            XactNotifyState::Complete { when } => {
                let state = crate::generated::xact::XactCommitState {
                    when: when.into()
                };

                XactNotifyStateHeader::Complete(state)
            },
        }
    }
}

impl<RoundID> From<XactNotifyState<RoundID>>
    for XactNotifyStateHeader
where RoundID: Clone + From<u128> + Into<u128> {
    #[inline]
    fn from(
        val: XactNotifyState<RoundID>
    ) -> Self {
        XactNotifyStateHeader::from(&val)
    }
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
        <XactUncommittedReqHeaderPERCodec as Codec<XactUncommittedReqHeader>>::DecodeError
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
                        when: when.as_ref().map(|when| when.into())
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

impl<RoundID, H>
    Codec<XactUncommittedHashReq<RoundID, H::HashID, Vec<u8>, Vec<u8>>>
    for XactUncommittedReqBlobCodec<RoundID, H>
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
        <XactUncommittedReqHeaderPERCodec as Codec<XactUncommittedReqHeader>>::DecodeError
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
                        when: when.as_ref().map(|when| when.into())
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
    for XactUncommittedReqHashCodec<RoundID, H, Payload, Effect,
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
        <XactUncommittedReqHeaderPERCodec as Codec<XactUncommittedReqHeader>>::DecodeError
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
                        when: when.as_ref().map(|when| when.into())
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
        <XactUncommittedReqHeaderPERCodec as Codec<XactUncommittedReqHeader>>::DecodeError
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
        <XactUncommittedReqHeaderPERCodec as Codec<XactUncommittedReqHeader>>::DecodeError
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

impl<Seal, Inner, SealCodec, InnerCodec> Codec<XactSealed<Seal, Inner>>
    for XactSealedCodec<Seal, Inner, SealCodec, InnerCodec>
where
    SealCodec: Codec<Seal>,
    InnerCodec: Codec<Inner>
{
    type CreateError = XactSealedCodecCreateError<
        SealCodec::CreateError,
        InnerCodec::CreateError,
    >;
    type DecodeError = XactSealedCodecError<
        <XactSealHeaderPERCodec as Codec<XactSealHeader>>::DecodeError,
        SealCodec::DecodeError,
        InnerCodec::DecodeError,
    >;
    type EncodeError = XactSealedCodecError<
        <XactSealHeaderPERCodec as Codec<XactSealHeader>>::EncodeError,
        SealCodec::EncodeError,
        InnerCodec::EncodeError,
    >;
    type Param = (SealCodec::Param, InnerCodec::Param);

    fn create(param: Self::Param) -> Result<Self, Self::CreateError> {
        let (seal, inner) = param;
        let seal_codec = SealCodec::create(seal)
            .map_err(|err| XactSealedCodecCreateError::Seal {
                err: err
            })?;
        let inner_codec = InnerCodec::create(inner)
            .map_err(|err| XactSealedCodecCreateError::Inner {
                err: err
            })?;

        Ok(XactSealedCodec {
            seal: PhantomData,
            inner: PhantomData,
            header_codec: XactSealHeaderPERCodec::default(),
            seal_codec: seal_codec,
            inner_codec: inner_codec,
        })
    }

    #[inline]
    fn buf_size(
        &self,
        val: &XactSealed<Seal, Inner>
    ) -> usize {
        let seal = self.seal_codec.buf_size(&val.seal) + 9;
        let inner = self.inner_codec.buf_size(&val.inner);

        seal + inner
    }

    fn encode(
        &mut self,
        val: &XactSealed<Seal, Inner>,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let mut curr = 0;

        curr += self
            .inner_codec
            .encode(&val.inner, &mut buf[curr..])
            .map_err(|err| XactSealedCodecError::Inner {
                err: err
            })?;

        let seal = self
            .seal_codec
            .encode_to_vec(&val.seal)
            .map_err(|err| XactSealedCodecError::Seal {
                err: err
            })?;
        let seal_len = seal.len();
        let header = XactSealHeader {
            len: seal_len as u64
        };

        curr += self
            .header_codec
            .encode(&header, &mut buf[curr..])
            .map_err(|err| XactSealedCodecError::Header {
                err: err
            })?;

        if curr + seal_len < buf.len() {
            buf[curr..curr + seal_len].copy_from_slice(&seal[..]);

            curr += seal_len;
        } else {
            return Err(XactSealedCodecError::TooShort)
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(XactSealed<Seal, Inner>, usize), Self::DecodeError>
    {
        let mut curr = 0;
        let (inner, nbytes) = self
            .inner_codec
            .decode(&buf[curr..])
            .map_err(|err| XactSealedCodecError::Inner {
                err: err
            })?;

        curr += nbytes;

        let (header, nbytes) = self
            .header_codec
            .decode(&buf[curr..])
            .map_err(|err| XactSealedCodecError::Header {
                err: err
            })?;

        curr += nbytes;

        let (seal, nbytes) = self
            .seal_codec
            .decode(&buf[curr..curr + header.len as usize])
            .map_err(|err| XactSealedCodecError::Seal {
                err: err
            })?;

        curr += nbytes;

        Ok((XactSealed {
            inner: inner,
            seal: seal
        }, curr))
    }
}

impl<Inner, InnerCodec> Codec<XactSealed<Vec<u8>, Inner>>
    for XactSealedBlobCodec<Inner, InnerCodec>
where
    InnerCodec: Codec<Inner>
{
    type CreateError = XactSealedCodecCreateError<
        Infallible,
        InnerCodec::CreateError,
    >;
    type DecodeError = XactSealedCodecError<
        <XactSealHeaderPERCodec as Codec<XactSealHeader>>::DecodeError,
        Infallible,
        InnerCodec::DecodeError,
    >;
    type EncodeError = XactSealedCodecError<
        <XactSealHeaderPERCodec as Codec<XactSealHeader>>::EncodeError,
        Infallible,
        InnerCodec::EncodeError,
    >;
    type Param = InnerCodec::Param;

    fn create(param: Self::Param) -> Result<Self, Self::CreateError> {
        let inner_codec = InnerCodec::create(param)
            .map_err(|err| XactSealedCodecCreateError::Inner {
                err: err
            })?;

        Ok(XactSealedBlobCodec {
            inner: PhantomData,
            header_codec: XactSealHeaderPERCodec::default(),
            inner_codec: inner_codec,
        })
    }

    #[inline]
    fn buf_size(
        &self,
        val: &XactSealed<Vec<u8>, Inner>
    ) -> usize {
        let seal = val.seal.len() + 9;
        let inner = self.inner_codec.buf_size(&val.inner);

        seal + inner
    }

    fn encode(
        &mut self,
        val: &XactSealed<Vec<u8>, Inner>,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let mut curr = 0;

        curr += self
            .inner_codec
            .encode(&val.inner, &mut buf[curr..])
            .map_err(|err| XactSealedCodecError::Inner {
                err: err
            })?;

        let seal_len = val.seal.len();
        let header = XactSealHeader {
            len: seal_len as u64
        };

        curr += self
            .header_codec
            .encode(&header, &mut buf[curr..])
            .map_err(|err| XactSealedCodecError::Header {
                err: err
            })?;

        if curr + seal_len < buf.len() {
            buf[curr..curr + seal_len].copy_from_slice(&val.seal[..]);

            curr += seal_len;
        } else {
            return Err(XactSealedCodecError::TooShort)
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(XactSealed<Vec<u8>, Inner>, usize), Self::DecodeError>
    {
        let mut curr = 0;
        let (inner, nbytes) = self
            .inner_codec
            .decode(&buf[curr..])
            .map_err(|err| XactSealedCodecError::Inner {
                err: err
            })?;

        curr += nbytes;

        let (header, nbytes) = self
            .header_codec
            .decode(&buf[curr..])
            .map_err(|err| XactSealedCodecError::Header {
                err: err
            })?;

        curr += nbytes;

        let seal = if curr + header.len as usize <= buf.len() {
            let data = buf[curr..curr + header.len as usize].to_vec();

            curr += header.len as usize;

            Ok(data)
        } else {
            Err(XactSealedCodecError::TooShort)
        }?;

        Ok((XactSealed {
            inner: inner,
            seal: seal
        }, curr))
    }
}

impl<RoundID, H, Seal, Payload, Effect, SealCodec, PayloadCodec, EffectCodec>
    Codec<XactCommittedRound<RoundID, H::HashID, Seal, Payload, Effect>>
    for XactCommittedRoundCodec<RoundID, H, Seal, Payload, Effect,
                                SealCodec, PayloadCodec, EffectCodec>
where
    H: Default + HashAlgo,
    H::HashID: Clone,
    RoundID: Clone + From<u128> + Into<u128>,
    PayloadCodec: Codec<Payload>,
    EffectCodec: Codec<Effect>,
    SealCodec: Codec<Seal>,
{
    type CreateError = XactCommittedRoundCodecCreateError<
        SealCodec::CreateError,
        XactReqCodecCreateError<
            PayloadCodec::CreateError,
            EffectCodec::CreateError
        >
    >;
    type DecodeError = XactCommittedRoundCodecDecodeError<
        <XactCommittedRoundHeaderPERCodec as Codec<XactCommittedRoundHeader>>::DecodeError,
        SealCodec::DecodeError,
        XactReqCodecDecodeError<
            PayloadCodec::DecodeError,
            EffectCodec::DecodeError,
            <XactCommittedReqHeaderPERCodec as Codec<XactCommittedReqHeader>>::DecodeError
        >
    >;
    type EncodeError = XactCommittedRoundCodecEncodeError<
        <XactCommittedRoundHeaderPERCodec as Codec<XactCommittedRoundHeader>>::EncodeError,
        SealCodec::EncodeError,
        XactReqCodecEncodeError<
            PayloadCodec::EncodeError,
            EffectCodec::EncodeError,
            <XactCommittedReqHeaderPERCodec as Codec<XactCommittedReqHeader>>::EncodeError
        >
    >;
    type Param = (SealCodec::Param, PayloadCodec::Param, EffectCodec::Param);

    fn create(param: Self::Param) -> Result<Self, Self::CreateError> {
        let (seal, payload, effect) = param;
        let seal_codec = SealCodec::create(seal)
            .map_err(|err| XactCommittedRoundCodecCreateError::Seal {
                err: err
            })?;
        let req_codec = XactCommittedReqCodec::create((payload, effect))
            .map_err(|err| XactCommittedRoundCodecCreateError::Req {
                err: err
            })?;
        let hash = H::default();

        Ok(XactCommittedRoundCodec {
            payload: PhantomData,
            effect: PhantomData,
            round: PhantomData,
            seal: PhantomData,
            header_codec: XactCommittedRoundHeaderPERCodec::default(),
            seal_header_codec: XactSealHeaderPERCodec::default(),
            req_codec: req_codec,
            seal_codec: seal_codec,
            hash: hash
        })
    }

    #[inline]
    fn buf_size(
        &self,
        val: &XactCommittedRound<RoundID, H::HashID, Seal, Payload, Effect>
    ) -> usize {
        let round = 16;
        let seal = match &val.seal {
            Some(XactConsensusSeal { hashes, seals }) => {
                let nhashes = hashes.len();
                let hashes = 64 * nhashes;
                let mut len = 1;

                for seal in seals.iter() {
                    len += self.seal_codec.buf_size(seal)
                }

                hashes + len
            }
            None => 1
        };
        let mut reqs = 1;

        for req in val.reqs.iter() {
            reqs += self.req_codec.buf_size(req)
        }

        round + seal + reqs
    }

    fn encode(
        &mut self,
        val: &XactCommittedRound<RoundID, H::HashID, Seal, Payload, Effect>,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let round: u128 = val.round.clone().into();
        let round = round.to_le_bytes().to_vec();
        let mut curr = 0;

        // First encode the header.
        if let Some(seal) = &val.seal {
            let hashes = seal.hashes.iter()
                .map(|hash| hash.bytes().to_vec())
                .collect();
            let header = XactCommittedRoundHeader {
                seal: Some(XactConsensusSealHeader {
                    hashes: hashes,
                    nseals: seal.seals.len() as u64
                }),
                round: round,
                nreqs: val.reqs.len() as u8
            };

            curr += self
                .header_codec
                .encode(&header, &mut buf[curr..])
                .map_err(|err| XactCommittedRoundCodecEncodeError::Header {
                    err: err
                })?;

            // Encode the seals
            for seal in seal.seals.iter() {
                let seal = self
                    .seal_codec
                    .encode_to_vec(&seal)
                    .map_err(|err| XactCommittedRoundCodecEncodeError::Seal {
                        err: err
                    })?;
                let seal_len = seal.len();
                let header = XactSealHeader {
                    len: seal_len as u64
                };

                curr += self
                    .seal_header_codec
                    .encode(&header, &mut buf[curr..])
                    .map_err(|err| XactCommittedRoundCodecEncodeError::Header {
                        err: err
                    })?;

                if curr + seal_len < buf.len() {
                    buf[curr..curr + seal_len].copy_from_slice(&seal[..]);

                    curr += seal_len;
                } else {
                    return Err(XactCommittedRoundCodecEncodeError::TooShort)
                }
            }
        } else {
            let header = XactCommittedRoundHeader {
                round: round,
                seal: None,
                nreqs: val.reqs.len() as u8
            };

            curr += self
                .header_codec
                .encode(&header, &mut buf[curr..])
                .map_err(|err| XactCommittedRoundCodecEncodeError::Header {
                    err: err
                })?;
        }

        // Encode the requests.
        for req in val.reqs.iter() {
            curr += self
                .req_codec
                .encode(&req, &mut buf[curr..])
                .map_err(|err| XactCommittedRoundCodecEncodeError::Req {
                    err: err
                })?;
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<
            (XactCommittedRound<RoundID, H::HashID, Seal, Payload, Effect>,
             usize),
        Self::DecodeError
    > {
        let mut curr = 0;
        let (header, nbytes) = self
            .header_codec
            .decode(&buf[curr..])
            .map_err(|err| XactCommittedRoundCodecDecodeError::Header {
                err: err
            })?;
        let round = header.round.clone().try_into()
            .map_err(|err| XactCommittedRoundCodecDecodeError::Round {
                err: err
            })?;
        let round = u128::from_le_bytes(round);
        let round = round.into();

        curr += nbytes;

        let seal = match &header.seal {
            Some(seal) => {
                let mut hashes = Vec::with_capacity(seal.hashes.len());

                for hash in seal.hashes.iter() {
                    let hash = self.hash.wrap_hashed_bytes(hash)
                        .map_err(|err|
                                 XactCommittedRoundCodecDecodeError::Hash {
                                     err: err
                                 })?;

                    hashes.push(hash);
                }

                let mut seals = Vec::with_capacity(seal.nseals as usize);

                for _ in 0..seal.nseals {
                    let (header, nbytes) = self
                        .seal_header_codec
                        .decode(&buf[curr..])
                        .map_err(|err|
                                 XactCommittedRoundCodecDecodeError::Header {
                                     err: err
                                 })?;

                    curr += nbytes;

                    let (seal, nbytes) = self
                        .seal_codec
                        .decode(&buf[curr..curr + header.len as usize])
                        .map_err(|err|
                                 XactCommittedRoundCodecDecodeError::Seal {
                                     err: err
                                 })?;

                    curr += nbytes;
                    seals.push(seal)
                }

                Some(XactConsensusSeal {
                    hashes: hashes,
                    seals: seals
                })
            }
            None => None
        };

        let nreqs = header.nreqs as usize;
        let mut reqs = Vec::with_capacity(nreqs);

        for _ in 0..nreqs {
            let (req, nbytes) = self
                .req_codec
                .decode(&buf[curr..])
                .map_err(|err| XactCommittedRoundCodecDecodeError::Req {
                    err: err
                })?;

            curr += nbytes;
            reqs.push(req);
        }

        Ok((XactCommittedRound {
            round: round,
            seal: seal,
            reqs: reqs,
        }, curr))
    }
}

impl<RoundID, H, Seal, SealCodec>
    Codec<XactCommittedRound<RoundID, H::HashID, Seal, Vec<u8>, Vec<u8>>>
    for XactCommittedRoundBlobCodec<RoundID, H, Seal, SealCodec>
where
    H: Default + HashAlgo,
    H::HashID: Clone,
    RoundID: Clone + From<u128> + Into<u128>,
    SealCodec: Codec<Seal>,
{
    type CreateError = XactCommittedRoundCodecCreateError<
        SealCodec::CreateError,
        XactReqCodecCreateError<
            Infallible,
            Infallible
        >
    >;
    type DecodeError = XactCommittedRoundCodecDecodeError<
        <XactCommittedRoundHeaderPERCodec as Codec<XactCommittedRoundHeader>>::DecodeError,
        SealCodec::DecodeError,
        XactReqCodecDecodeError<
            Infallible,
            Infallible,
            <XactCommittedReqHeaderPERCodec as Codec<XactCommittedReqHeader>>::DecodeError
        >
    >;
    type EncodeError = XactCommittedRoundCodecEncodeError<
        <XactCommittedRoundHeaderPERCodec as Codec<XactCommittedRoundHeader>>::EncodeError,
        SealCodec::EncodeError,
        XactReqCodecEncodeError<
            Infallible,
            Infallible,
            <XactCommittedReqHeaderPERCodec as Codec<XactCommittedReqHeader>>::EncodeError
        >
    >;
    type Param = SealCodec::Param;

    fn create(param: Self::Param) -> Result<Self, Self::CreateError> {
        let seal_codec = SealCodec::create(param)
            .map_err(|err| XactCommittedRoundCodecCreateError::Seal {
                err: err
            })?;
        let req_codec = XactCommittedReqBlobCodec::create(())
            .map_err(|err| XactCommittedRoundCodecCreateError::Req {
                err: err
            })?;
        let hash = H::default();

        Ok(XactCommittedRoundBlobCodec {
            round: PhantomData,
            seal: PhantomData,
            header_codec: XactCommittedRoundHeaderPERCodec::default(),
            seal_header_codec: XactSealHeaderPERCodec::default(),
            req_codec: req_codec,
            seal_codec: seal_codec,
            hash: hash
        })
    }

    #[inline]
    fn buf_size(
        &self,
        val: &XactCommittedRound<RoundID, H::HashID, Seal, Vec<u8>, Vec<u8>>
    ) -> usize {
        let round = 16;
        let seal = match &val.seal {
            Some(XactConsensusSeal { hashes, seals }) => {
                let nhashes = hashes.len();
                let hashes = 64 * nhashes;
                let mut len = 1;

                for seal in seals.iter() {
                    len += self.seal_codec.buf_size(seal)
                }

                hashes + len
            }
            None => 1
        };
        let mut reqs = 1;

        for req in val.reqs.iter() {
            reqs += self.req_codec.buf_size(req)
        }

        round + seal + reqs
    }

    fn encode(
        &mut self,
        val: &XactCommittedRound<RoundID, H::HashID, Seal, Vec<u8>, Vec<u8>>,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let round: u128 = val.round.clone().into();
        let round = round.to_le_bytes().to_vec();
        let mut curr = 0;

        // First encode the header.
        if let Some(seal) = &val.seal {
            let hashes = seal.hashes.iter()
                .map(|hash| hash.bytes().to_vec())
                .collect();
            let header = XactCommittedRoundHeader {
                seal: Some(XactConsensusSealHeader {
                    hashes: hashes,
                    nseals: seal.seals.len() as u64
                }),
                round: round,
                nreqs: val.reqs.len() as u8
            };

            curr += self
                .header_codec
                .encode(&header, &mut buf[curr..])
                .map_err(|err| XactCommittedRoundCodecEncodeError::Header {
                    err: err
                })?;

            // Encode the seals
            for seal in seal.seals.iter() {
                let seal = self
                    .seal_codec
                    .encode_to_vec(&seal)
                    .map_err(|err| XactCommittedRoundCodecEncodeError::Seal {
                        err: err
                    })?;
                let seal_len = seal.len();
                let header = XactSealHeader {
                    len: seal_len as u64
                };

                curr += self
                    .seal_header_codec
                    .encode(&header, &mut buf[curr..])
                    .map_err(|err| XactCommittedRoundCodecEncodeError::Header {
                        err: err
                    })?;

                if curr + seal_len < buf.len() {
                    buf[curr..curr + seal_len].copy_from_slice(&seal[..]);

                    curr += seal_len;
                } else {
                    return Err(XactCommittedRoundCodecEncodeError::TooShort)
                }
            }
        } else {
            let header = XactCommittedRoundHeader {
                round: round,
                seal: None,
                nreqs: val.reqs.len() as u8
            };

            curr += self
                .header_codec
                .encode(&header, &mut buf[curr..])
                .map_err(|err| XactCommittedRoundCodecEncodeError::Header {
                    err: err
                })?;
        }

        // Encode the requests.
        for req in val.reqs.iter() {
            curr += self
                .req_codec
                .encode(&req, &mut buf[curr..])
                .map_err(|err| XactCommittedRoundCodecEncodeError::Req {
                    err: err
                })?;
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<
            (XactCommittedRound<RoundID, H::HashID, Seal, Vec<u8>, Vec<u8>>,
             usize),
        Self::DecodeError
    > {
        let mut curr = 0;
        let (header, nbytes) = self
            .header_codec
            .decode(&buf[curr..])
            .map_err(|err| XactCommittedRoundCodecDecodeError::Header {
                err: err
            })?;
        let round = header.round.clone().try_into()
            .map_err(|err| XactCommittedRoundCodecDecodeError::Round {
                err: err
            })?;
        let round = u128::from_le_bytes(round);
        let round = round.into();

        curr += nbytes;

        let seal = match &header.seal {
            Some(seal) => {
                let mut hashes = Vec::with_capacity(seal.hashes.len());

                for hash in seal.hashes.iter() {
                    let hash = self.hash.wrap_hashed_bytes(hash)
                        .map_err(|err|
                                 XactCommittedRoundCodecDecodeError::Hash {
                                     err: err
                                 })?;

                    hashes.push(hash);
                }

                let mut seals = Vec::with_capacity(seal.nseals as usize);

                for _ in 0..seal.nseals {
                    let (header, nbytes) = self
                        .seal_header_codec
                        .decode(&buf[curr..])
                        .map_err(|err|
                                 XactCommittedRoundCodecDecodeError::Header {
                                     err: err
                                 })?;

                    curr += nbytes;

                    let (seal, nbytes) = self
                        .seal_codec
                        .decode(&buf[curr..curr + header.len as usize])
                        .map_err(|err|
                                 XactCommittedRoundCodecDecodeError::Seal {
                                     err: err
                                 })?;

                    curr += nbytes;
                    seals.push(seal)
                }

                Some(XactConsensusSeal {
                    hashes: hashes,
                    seals: seals
                })
            }
            None => None
        };

        let nreqs = header.nreqs as usize;
        let mut reqs = Vec::with_capacity(nreqs);

        for _ in 0..nreqs {
            let (req, nbytes) = self
                .req_codec
                .decode(&buf[curr..])
                .map_err(|err| XactCommittedRoundCodecDecodeError::Req {
                    err: err
                })?;

            curr += nbytes;
            reqs.push(req);
        }

        Ok((XactCommittedRound {
            round: round,
            seal: seal,
            reqs: reqs,
        }, curr))
    }
}

impl<H, Res, Err, ResCodec, ErrCodec> Codec<XactResult<H::HashID, Res, Err>>
    for XactResultCodec<H, Res, Err, ResCodec, ErrCodec>
where
    H: HashAlgo + Default,
    H::HashID: Clone,
    ResCodec: Codec<Res>,
    ErrCodec: Codec<Err>
{
    type CreateError = XactResultCodecCreateError<
        ResCodec::CreateError,
        ErrCodec::CreateError,
    >;
    type DecodeError = XactResultCodecDecodeError<
        <XactResultHeaderPERCodec as Codec<XactResultHeader>>::DecodeError,
        ResCodec::DecodeError,
        ErrCodec::DecodeError,
    >;
    type EncodeError = XactResultCodecEncodeError<
        <XactResultHeaderPERCodec as Codec<XactResultHeader>>::EncodeError,
        ResCodec::EncodeError,
        ErrCodec::EncodeError,
    >;
    type Param = (ResCodec::Param, ErrCodec::Param);

    fn create(param: Self::Param) -> Result<Self, Self::CreateError> {
        let (res, err) = param;
        let res_codec = ResCodec::create(res)
            .map_err(|err| XactResultCodecCreateError::Res {
                err: err
            })?;
        let err_codec = ErrCodec::create(err)
            .map_err(|err| XactResultCodecCreateError::Err {
                err: err
            })?;
        let hash = H::default();

        Ok(XactResultCodec {
            res: PhantomData,
            err: PhantomData,
            header_codec: XactResultHeaderPERCodec::default(),
            res_codec: res_codec,
            err_codec: err_codec,
            hash: hash
        })
    }

    #[inline]
    fn buf_size(
        &self,
        val: &XactResult<H::HashID, Res, Err>
    ) -> usize {
        let hash = 64;
        let val = match &val.res {
            Ok(res) => self.res_codec.buf_size(&res) + 9,
            Err(XactError::Error { err }) => self.err_codec.buf_size(&err) + 9,
            Err(XactError::UnknownClass) |
            Err(XactError::UnknownVersion) |
            Err(XactError::UnknownInstance) |
            Err(XactError::InvalidPayload) |
            Err(XactError::InvalidEffect) |
            Err(XactError::EffectViolation) |
            Err(XactError::Unauthorized) |
            Err(XactError::Internal) => 1
        };

        hash + val
    }

    fn encode(
        &mut self,
        val: &XactResult<H::HashID, Res, Err>,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        match &val.res {
            Ok(res) => {
                let res = self
                    .res_codec
                    .encode_to_vec(res)
                    .map_err(|err| XactResultCodecEncodeError::Res {
                        err: err
                    })?;
                let res_len = res.len();
                let header = XactResultHeader {
                    hash: val.hash.bytes().to_vec(),
                    value: XactResultValueHeader::Ok(XactValueHeader {
                        len: res.len() as u64
                    })
                };
                let mut curr = 0;

                curr += self
                    .header_codec
                    .encode(&header, &mut buf[curr..])
                    .map_err(|err| XactResultCodecEncodeError::Header {
                        err: err
                    })?;

                if res_len != 0 {
                    if curr + res_len < buf.len() {
                        buf[curr..curr + res_len].copy_from_slice(&res[..]);

                        curr += res_len;
                    } else {
                        return Err(XactResultCodecEncodeError::TooShort)
                    }
                }

                Ok(curr)
            }
            Err(err) => {
                let (err, data) = match err {
                    XactError::Error { err } => {
                        let err = self
                            .err_codec
                            .encode_to_vec(err)
                            .map_err(|err| XactResultCodecEncodeError::Err {
                                err: err
                            })?;

                        Ok((XactResultValueHeader::Error(XactErrorHeader {
                            len: err.len() as u64
                        }),
                            Some(err)
                        ))
                    }
                    XactError::UnknownClass => Ok((
                        XactResultValueHeader::UnknownClass(Default::default()),
                        None
                    )),
                    XactError::UnknownVersion => Ok((
                        XactResultValueHeader::UnknownVersion(Default::default()),
                        None
                    )),
                    XactError::UnknownInstance => Ok((
                        XactResultValueHeader::UnknownInstance(Default::default()),
                        None
                    )),
                    XactError::InvalidPayload => Ok((
                        XactResultValueHeader::InvalidPayload(Default::default()),
                        None
                    )),
                    XactError::InvalidEffect => Ok((
                        XactResultValueHeader::InvalidEffect(Default::default()),
                        None
                    )),
                    XactError::EffectViolation => Ok((
                        XactResultValueHeader::EffectViolation(Default::default()),
                        None
                    )),
                    XactError::Unauthorized => Ok((
                        XactResultValueHeader::Unauthorized(Default::default()),
                        None
                    )),
                    XactError::Internal => Ok((
                        XactResultValueHeader::Internal(Default::default()),
                        None
                    ))
                }?;
                let header = XactResultHeader {
                    hash: val.hash.bytes().to_vec(),
                    value: err,
                };
                let mut curr = 0;

                curr += self
                    .header_codec
                    .encode(&header, &mut buf[curr..])
                    .map_err(|err| XactResultCodecEncodeError::Header {
                        err: err
                    })?;

                if let Some(data) = data {
                    let err_len = data.len();

                    if curr + err_len < buf.len() {
                        buf[curr..curr + err_len].copy_from_slice(&data[..]);

                        curr += err_len;
                    } else {
                        return Err(XactResultCodecEncodeError::TooShort)
                    }
                }

                Ok(curr)

            }
        }
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(XactResult<H::HashID, Res, Err>, usize), Self::DecodeError>
    {
        let mut curr = 0;
        let (header, nbytes) = self
            .header_codec
            .decode(&buf[curr..])
            .map_err(|err| XactResultCodecDecodeError::Header {
                err: err
            })?;
        let hash = self.hash.wrap_hashed_bytes(&header.hash)
            .map_err(|err| XactResultCodecDecodeError::Hash {
                err: err
            })?;

        curr += nbytes;

        match &header.value {
            XactResultValueHeader::Ok(XactValueHeader { len }) => {
                let len = *len as usize;
                let (res, _) = self
                    .res_codec
                    .decode(&buf[curr..curr + len])
                    .map_err(|err| XactResultCodecDecodeError::Res {
                        err: err
                    })?;

                curr += len;

                let res = XactResult {
                    hash: hash,
                    res: Ok(res)
                };

                Ok((res, curr))
            }
            XactResultValueHeader::Error(XactErrorHeader { len }) => {
                let len = *len as usize;
                let (err, _) = self
                    .err_codec
                    .decode(&buf[curr..curr + len])
                    .map_err(|err| XactResultCodecDecodeError::Err {
                        err: err
                    })?;

                curr += len;

                let res = XactResult {
                    hash: hash,
                    res: Err(XactError::Error {
                        err: err
                    })
                };

                Ok((res, curr))
            }
            XactResultValueHeader::UnknownClass(_) => {
                let res = XactResult {
                    res: Err(XactError::UnknownClass),
                    hash: hash,
                };

                Ok((res, curr))
            }
            XactResultValueHeader::UnknownVersion(_) => {
                let res = XactResult {
                    res: Err(XactError::UnknownVersion),
                    hash: hash,
                };

                Ok((res, curr))
            }
            XactResultValueHeader::UnknownInstance(_) => {
                let res = XactResult {
                    res: Err(XactError::UnknownInstance),
                    hash: hash,
                };

                Ok((res, curr))
            }
            XactResultValueHeader::InvalidPayload(_) => {
                let res = XactResult {
                    res: Err(XactError::InvalidPayload),
                    hash: hash,
                };

                Ok((res, curr))
            }
            XactResultValueHeader::InvalidEffect(_) => {
                let res = XactResult {
                    res: Err(XactError::InvalidEffect),
                    hash: hash,
                };

                Ok((res, curr))
            }
            XactResultValueHeader::EffectViolation(_) => {
                let res = XactResult {
                    res: Err(XactError::EffectViolation),
                    hash: hash,
                };

                Ok((res, curr))
            }
            XactResultValueHeader::Unauthorized(_) => {
                let res = XactResult {
                    res: Err(XactError::Unauthorized),
                    hash: hash,
                };

                Ok((res, curr))
            }
            XactResultValueHeader::Internal(_) => {
                let res = XactResult {
                    res: Err(XactError::Internal),
                    hash: hash,
                };

                Ok((res, curr))
            }
        }
    }
}

impl<H> Codec<XactResult<H::HashID, Vec<u8>, Vec<u8>>>
    for XactResultBlobCodec<H>
where
    H: HashAlgo + Clone + Default,
    H::HashID: Clone,
{
    type CreateError = XactResultCodecCreateError<
        Infallible,
        Infallible
    >;
    type DecodeError = XactResultCodecDecodeError<
        <XactResultHeaderPERCodec as Codec<XactResultHeader>>::DecodeError,
        Infallible,
        Infallible
    >;
    type EncodeError = XactResultCodecEncodeError<
        <XactResultHeaderPERCodec as Codec<XactResultHeader>>::EncodeError,
        Infallible,
        Infallible
    >;
    type Param = ();

    fn create(_param: Self::Param) -> Result<Self, Self::CreateError> {
        let hash = H::default();

        Ok(XactResultBlobCodec {
            header_codec: XactResultHeaderPERCodec::default(),
            hash: hash
        })
    }

    #[inline]
    fn buf_size(
        &self,
        val: &XactResult<H::HashID, Vec<u8>, Vec<u8>>
    ) -> usize {
        let hash = 64;
        let val = match &val.res {
            Ok(res) => res.len() + 9,
            Err(XactError::Error { err }) => err.len() + 9,
            Err(XactError::UnknownClass) |
            Err(XactError::UnknownVersion) |
            Err(XactError::UnknownInstance) |
            Err(XactError::InvalidPayload) |
            Err(XactError::InvalidEffect) |
            Err(XactError::EffectViolation) |
            Err(XactError::Unauthorized) |
            Err(XactError::Internal) => 1
        };

        hash + val
    }

    fn encode(
        &mut self,
        val: &XactResult<H::HashID, Vec<u8>, Vec<u8>>,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        match &val.res {
            Ok(res) => {
                let res_len = res.len();
                let header = XactResultHeader {
                    hash: val.hash.bytes().to_vec(),
                    value: XactResultValueHeader::Ok(XactValueHeader {
                        len: res.len() as u64
                    })
                };
                let mut curr = 0;

                curr += self
                    .header_codec
                    .encode(&header, &mut buf[curr..])
                    .map_err(|err| XactResultCodecEncodeError::Header {
                        err: err
                    })?;

                if res_len != 0 {
                    if curr + res_len < buf.len() {
                        buf[curr..curr + res_len].copy_from_slice(&res[..]);

                        curr += res_len;
                    } else {
                        return Err(XactResultCodecEncodeError::TooShort)
                    }
                }

                Ok(curr)
            }
            Err(err) => {
                let (err, data) = match err {
                    XactError::Error { err } => {
                        Ok((XactResultValueHeader::Error(XactErrorHeader {
                            len: err.len() as u64
                        }),
                            Some(err.to_vec())
                        ))
                    }
                    XactError::UnknownClass => Ok((
                        XactResultValueHeader::UnknownClass(Default::default()),
                        None
                    )),
                    XactError::UnknownVersion => Ok((
                        XactResultValueHeader::UnknownVersion(Default::default()),
                        None
                    )),
                    XactError::UnknownInstance => Ok((
                        XactResultValueHeader::UnknownInstance(Default::default()),
                        None
                    )),
                    XactError::InvalidPayload => Ok((
                        XactResultValueHeader::InvalidPayload(Default::default()),
                        None
                    )),
                    XactError::InvalidEffect => Ok((
                        XactResultValueHeader::InvalidEffect(Default::default()),
                        None
                    )),
                    XactError::EffectViolation => Ok((
                        XactResultValueHeader::EffectViolation(Default::default()),
                        None
                    )),
                    XactError::Unauthorized => Ok((
                        XactResultValueHeader::Unauthorized(Default::default()),
                        None
                    )),
                    XactError::Internal => Ok((
                        XactResultValueHeader::Internal(Default::default()),
                        None
                    ))
                }?;
                let header = XactResultHeader {
                    hash: val.hash.bytes().to_vec(),
                    value: err,
                };
                let mut curr = 0;

                curr += self
                    .header_codec
                    .encode(&header, &mut buf[curr..])
                    .map_err(|err| XactResultCodecEncodeError::Header {
                        err: err
                    })?;

                if let Some(data) = data {
                    let err_len = data.len();

                    if curr + err_len < buf.len() {
                        buf[curr..curr + err_len].copy_from_slice(&data[..]);

                        curr += err_len;
                    } else {
                        return Err(XactResultCodecEncodeError::TooShort)
                    }
                }

                Ok(curr)

            }
        }
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(XactResult<H::HashID, Vec<u8>, Vec<u8>>, usize),
                Self::DecodeError>
    {
        let mut curr = 0;
        let (header, nbytes) = self
            .header_codec
            .decode(&buf[curr..])
            .map_err(|err| XactResultCodecDecodeError::Header {
                err: err
            })?;
        let hash = self.hash.wrap_hashed_bytes(&header.hash)
            .map_err(|err| XactResultCodecDecodeError::Hash {
                err: err
            })?;

        curr += nbytes;

        match &header.value {
            XactResultValueHeader::Ok(XactValueHeader { len }) => {
                let len = *len as usize;

                if curr + len <= buf.len() {
                    let res = buf[curr..curr + len].to_vec();

                    curr += len;

                    let res = XactResult {
                        hash: hash,
                        res: Ok(res)
                    };

                    Ok((res, curr))
                } else {
                    Err(XactResultCodecDecodeError::TooShort)
                }
            }
            XactResultValueHeader::Error(XactErrorHeader { len }) => {
                let len = *len as usize;

                if curr + len <= buf.len() {
                    let err = buf[curr..curr + len].to_vec();

                    curr += len;

                    let res = XactResult {
                        hash: hash,
                        res: Err(XactError::Error {
                            err: err
                        })
                    };

                    Ok((res, curr))
                } else {
                    Err(XactResultCodecDecodeError::TooShort)
                }
            }
            XactResultValueHeader::UnknownClass(_) => {
                let res = XactResult {
                    res: Err(XactError::UnknownClass),
                    hash: hash,
                };

                Ok((res, curr))
            }
            XactResultValueHeader::UnknownVersion(_) => {
                let res = XactResult {
                    res: Err(XactError::UnknownVersion),
                    hash: hash,
                };

                Ok((res, curr))
            }
            XactResultValueHeader::UnknownInstance(_) => {
                let res = XactResult {
                    res: Err(XactError::UnknownInstance),
                    hash: hash,
                };

                Ok((res, curr))
            }
            XactResultValueHeader::InvalidPayload(_) => {
                let res = XactResult {
                    res: Err(XactError::InvalidPayload),
                    hash: hash,
                };

                Ok((res, curr))
            }
            XactResultValueHeader::InvalidEffect(_) => {
                let res = XactResult {
                    res: Err(XactError::InvalidEffect),
                    hash: hash,
                };

                Ok((res, curr))
            }
            XactResultValueHeader::EffectViolation(_) => {
                let res = XactResult {
                    res: Err(XactError::EffectViolation),
                    hash: hash,
                };

                Ok((res, curr))
            }
            XactResultValueHeader::Unauthorized(_) => {
                let res = XactResult {
                    res: Err(XactError::Unauthorized),
                    hash: hash,
                };

                Ok((res, curr))
            }
            XactResultValueHeader::Internal(_) => {
                let res = XactResult {
                    res: Err(XactError::Internal),
                    hash: hash,
                };

                Ok((res, curr))
            }
        }
    }
}

impl<RoundID, H, Seal, Payload, Effect, Res, Err,
     SealCodec, PayloadCodec, EffectCodec, ResCodec, ErrCodec>
    Codec<XactBatch<RoundID, H::HashID, Seal, Payload, Effect, Res, Err>>
    for XactBatchCodec<RoundID, H, Seal, Payload, Effect, Res, Err,
                       SealCodec, PayloadCodec, EffectCodec,
                       ResCodec, ErrCodec>
where
    H: Default + HashAlgo,
    H::HashID: Clone,
    RoundID: Clone + From<u128> + Into<u128>,
    PayloadCodec: Codec<Payload>,
    PayloadCodec::Param: Clone,
    EffectCodec: Codec<Effect>,
    EffectCodec::Param: Clone,
    SealCodec: Codec<Seal>,
    SealCodec::Param: Clone,
    ResCodec: Codec<Res>,
    ResCodec::Param: Clone,
    ErrCodec: Codec<Err>,
    ErrCodec::Param: Clone,
{
    type CreateError = XactBatchCodecCreateError<
        XactSealedCodecCreateError<
            SealCodec::CreateError,
            XactReqCodecCreateError<
                PayloadCodec::CreateError,
                EffectCodec::CreateError,
            >
        >,
        XactCommittedRoundCodecCreateError<
            SealCodec::CreateError,
            XactReqCodecCreateError<
                PayloadCodec::CreateError,
                EffectCodec::CreateError
            >
        >,
        XactResultCodecCreateError<
            ResCodec::CreateError,
            ErrCodec::CreateError,
        >,
    >;
    type DecodeError = XactBatchCodecDecodeError<
        <XactBatchHeaderPERCodec as Codec<XactBatchHeader>>::DecodeError,
        XactSealedCodecError<
            <XactSealHeaderPERCodec as Codec<XactSealHeader>>::DecodeError,
            SealCodec::DecodeError,
            XactReqCodecDecodeError<
                PayloadCodec::DecodeError,
                EffectCodec::DecodeError,
                <XactUncommittedReqHeaderPERCodec as Codec<XactUncommittedReqHeader>>::DecodeError
            >
        >,
        XactCommittedRoundCodecDecodeError<
            <XactCommittedRoundHeaderPERCodec as Codec<XactCommittedRoundHeader>>::DecodeError,
            SealCodec::DecodeError,
            XactReqCodecDecodeError<
                PayloadCodec::DecodeError,
                EffectCodec::DecodeError,
                <XactCommittedReqHeaderPERCodec as Codec<XactCommittedReqHeader>>::DecodeError
            >
        >,
        XactResultCodecDecodeError<
            <XactResultHeaderPERCodec as Codec<XactResultHeader>>::DecodeError,
            ResCodec::DecodeError,
            ErrCodec::DecodeError,
        >,
        <XactNotifyHeaderPERCodec as Codec<XactNotifyHeader>>::DecodeError
    >;
    type EncodeError = XactBatchCodecEncodeError<
        <XactBatchHeaderPERCodec as Codec<XactBatchHeader>>::EncodeError,
        XactSealedCodecError<
            <XactSealHeaderPERCodec as Codec<XactSealHeader>>::EncodeError,
            SealCodec::EncodeError,
            XactReqCodecEncodeError<
                PayloadCodec::EncodeError,
                EffectCodec::EncodeError,
                <XactUncommittedReqHeaderPERCodec as Codec<XactUncommittedReqHeader>>::EncodeError
            >
        >,
        XactCommittedRoundCodecEncodeError<
            <XactCommittedRoundHeaderPERCodec as Codec<XactCommittedRoundHeader>>::EncodeError,
            SealCodec::EncodeError,
            XactReqCodecEncodeError<
                PayloadCodec::EncodeError,
                EffectCodec::EncodeError,
                <XactCommittedReqHeaderPERCodec as Codec<XactCommittedReqHeader>>::EncodeError
            >
        >,
        XactResultCodecEncodeError<
            <XactResultHeaderPERCodec as Codec<XactResultHeader>>::EncodeError,
            ResCodec::EncodeError,
            ErrCodec::EncodeError,
        >,
        <XactNotifyHeaderPERCodec as Codec<XactNotifyHeader>>::EncodeError
    >;
    type Param = (SealCodec::Param, PayloadCodec::Param, EffectCodec::Param,
                  ResCodec::Param, ErrCodec::Param);

    fn create(param: Self::Param) -> Result<Self, Self::CreateError> {
        let (seal, payload, effect, res, err) = param;
        let req_codec = XactSealedCodec::create((seal.clone(),
                                                 (payload.clone(),
                                                  effect.clone())))
            .map_err(|err| XactBatchCodecCreateError::Req {
                err: err
            })?;
        let committed_codec = XactCommittedRoundCodec::create((seal.clone(),
                                                               payload.clone(),
                                                               effect.clone()))
            .map_err(|err| XactBatchCodecCreateError::Committed {
                err: err
            })?;
        let res_codec = XactResultCodec::create((res.clone(), err.clone()))
            .map_err(|err| XactBatchCodecCreateError::Res {
                err: err
            })?;
        let hash = H::default();

        Ok(XactBatchCodec {
            header_codec: XactBatchHeaderPERCodec::default(),
            notify_codec: XactNotifyHeaderPERCodec::default(),
            committed_codec: committed_codec,
            req_codec: req_codec,
            res_codec: res_codec,
            hash: hash
        })
    }

    #[inline]
    fn buf_size(
        &self,
        val: &XactBatch<RoundID, H::HashID, Seal, Payload, Effect, Res, Err>,
    ) -> usize {
        let req: usize = val.reqs.iter()
            .map(|req| self.req_codec.buf_size(req)).sum();
        let committed: usize = val.committed.iter()
            .map(|committed| self.committed_codec.buf_size(committed))
            .sum();
        let res: usize = val.results.iter()
            .map(|res| self.res_codec.buf_size(res)).sum();
        let notify: usize = val.notifies.iter()
            .map(|_| XactNotifyHeaderPERCodec::MAX_BYTES).sum();

        req + committed + res + notify + 12
    }

    fn encode(
        &mut self,
        val: &XactBatch<RoundID, H::HashID, Seal, Payload, Effect, Res, Err>,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let header = XactBatchHeader {
            ncommitted: val.committed.len() as u32,
            nreqs: val.reqs.len() as u32,
            nresults: val.results.len() as u32,
            nnotifies: val.notifies.len() as u32,
        };
        let mut curr = 0;

        curr += self
            .header_codec
            .encode(&header, &mut buf[curr..])
            .map_err(|err| XactBatchCodecEncodeError::Header {
                err: err
            })?;

        for committed in val.committed.iter() {
            curr += self
                .committed_codec
                .encode(&committed, &mut buf[curr..])
                .map_err(|err| XactBatchCodecEncodeError::Committed {
                    err: err
                })?;
        }

        for req in val.reqs.iter() {
            curr += self
                .req_codec
                .encode(&req, &mut buf[curr..])
                .map_err(|err| XactBatchCodecEncodeError::Req {
                    err: err
                })?;
        }

        for result in val.results.iter() {
            curr += self
                .res_codec
                .encode(&result, &mut buf[curr..])
                .map_err(|err| XactBatchCodecEncodeError::Res {
                    err: err
                })?;
        }

        for notify in val.notifies.iter() {
            let hash = notify.hash.bytes().to_vec();
            let state = (&notify.state).into();
            let notify = XactNotifyHeader {
                hash: hash,
                state: state
            };

            curr += self
                .notify_codec
                .encode(&notify, &mut buf[curr..])
                .map_err(|err| XactBatchCodecEncodeError::Notify {
                    err: err
                })?;
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<
            (XactBatch<RoundID, H::HashID, Seal, Payload, Effect, Res, Err>,
             usize),
        Self::DecodeError
    > {
        let mut curr = 0;
        let (header, nbytes) = self
            .header_codec
            .decode(&buf[curr..])
            .map_err(|err| XactBatchCodecDecodeError::Header {
                err: err
            })?;

        curr += nbytes;

        let mut committed = Vec::with_capacity(header.ncommitted as usize);

        for _ in 0..header.ncommitted {
            let (round, nbytes) = self
                .committed_codec
                .decode(&buf[curr..])
                .map_err(|err| XactBatchCodecDecodeError::Committed {
                    err: err
                })?;

            committed.push(round);
            curr += nbytes;
        }


        let mut reqs = Vec::with_capacity(header.nreqs as usize);

        for _ in 0..header.nreqs {
            let (req, nbytes) = self
                .req_codec
                .decode(&buf[curr..])
                .map_err(|err| XactBatchCodecDecodeError::Req {
                    err: err
                })?;

            reqs.push(req);
            curr += nbytes;
        }

        let mut results = Vec::with_capacity(header.nresults as usize);

        for _ in 0..header.nresults {
            let (res, nbytes) = self
                .res_codec
                .decode(&buf[curr..])
                .map_err(|err| XactBatchCodecDecodeError::Res {
                    err: err
                })?;

            results.push(res);
            curr += nbytes;
        }

        let mut notifies = Vec::with_capacity(header.nnotifies as usize);

        for _ in 0..header.nnotifies {
            let (notify, nbytes) = self
                .notify_codec
                .decode(&buf[curr..])
                .map_err(|err| XactBatchCodecDecodeError::Notify {
                    err: err
                })?;
            let hash = self.hash.wrap_hashed_bytes(&notify.hash)
                .map_err(|err| XactBatchCodecDecodeError::Hash {
                    err: err
                })?;
            let state = notify.state.try_into()
                .map_err(|err| XactBatchCodecDecodeError::State {
                    err: err
                })?;
            let notify = XactNotify {
                hash: hash,
                state: state
            };

            notifies.push(notify);
            curr += nbytes;
        }

        Ok((XactBatch {
            committed: committed,
            reqs: reqs,
            notifies: notifies,
            results: results
        }, curr))
    }
}

impl<RoundID, H, Seal, Payload, Effect, Res, Err,
     SealCodec, PayloadCodec, EffectCodec, ResCodec, ErrCodec>
    Codec<XactHashBatch<RoundID, H::HashID, Seal, Payload, Effect, Res, Err>>
    for XactBatchHashCodec<RoundID, H, Seal, Payload, Effect, Res, Err,
                           SealCodec, PayloadCodec, EffectCodec,
                           ResCodec, ErrCodec>
where
    H: Default + HashAlgo,
    H::HashID: Clone,
    RoundID: Clone + From<u128> + Into<u128>,
    PayloadCodec: Codec<Payload>,
    PayloadCodec::Param: Clone,
    EffectCodec: Codec<Effect>,
    EffectCodec::Param: Clone,
    SealCodec: Codec<Seal>,
    SealCodec::Param: Clone,
    ResCodec: Codec<Res>,
    ResCodec::Param: Clone,
    ErrCodec: Codec<Err>,
    ErrCodec::Param: Clone,
{
    type CreateError = XactBatchCodecCreateError<
        XactSealedCodecCreateError<
            SealCodec::CreateError,
            XactReqCodecCreateError<
                PayloadCodec::CreateError,
                EffectCodec::CreateError,
            >
        >,
        XactCommittedRoundCodecCreateError<
            SealCodec::CreateError,
            XactReqCodecCreateError<
                PayloadCodec::CreateError,
                EffectCodec::CreateError
            >
        >,
        XactResultCodecCreateError<
            ResCodec::CreateError,
            ErrCodec::CreateError,
        >,
    >;
    type DecodeError = XactBatchCodecDecodeError<
        <XactBatchHeaderPERCodec as Codec<XactBatchHeader>>::DecodeError,
        XactSealedCodecError<
            <XactSealHeaderPERCodec as Codec<XactSealHeader>>::DecodeError,
            SealCodec::DecodeError,
            XactReqCodecDecodeError<
                PayloadCodec::DecodeError,
                EffectCodec::DecodeError,
                <XactUncommittedReqHeaderPERCodec as Codec<XactUncommittedReqHeader>>::DecodeError
            >
        >,
        XactCommittedRoundCodecDecodeError<
            <XactCommittedRoundHeaderPERCodec as Codec<XactCommittedRoundHeader>>::DecodeError,
            SealCodec::DecodeError,
            XactReqCodecDecodeError<
                PayloadCodec::DecodeError,
                EffectCodec::DecodeError,
                <XactCommittedReqHeaderPERCodec as Codec<XactCommittedReqHeader>>::DecodeError
            >
        >,
        XactResultCodecDecodeError<
            <XactResultHeaderPERCodec as Codec<XactResultHeader>>::DecodeError,
            ResCodec::DecodeError,
            ErrCodec::DecodeError,
        >,
        <XactNotifyHeaderPERCodec as Codec<XactNotifyHeader>>::DecodeError
    >;
    type EncodeError = XactBatchCodecEncodeError<
        <XactBatchHeaderPERCodec as Codec<XactBatchHeader>>::EncodeError,
        XactSealedCodecError<
            <XactSealHeaderPERCodec as Codec<XactSealHeader>>::EncodeError,
            SealCodec::EncodeError,
            XactReqCodecEncodeError<
                PayloadCodec::EncodeError,
                EffectCodec::EncodeError,
                <XactUncommittedReqHeaderPERCodec as Codec<XactUncommittedReqHeader>>::EncodeError
            >
        >,
        XactCommittedRoundCodecEncodeError<
            <XactCommittedRoundHeaderPERCodec as Codec<XactCommittedRoundHeader>>::EncodeError,
            SealCodec::EncodeError,
            XactReqCodecEncodeError<
                PayloadCodec::EncodeError,
                EffectCodec::EncodeError,
                <XactCommittedReqHeaderPERCodec as Codec<XactCommittedReqHeader>>::EncodeError
            >
        >,
        XactResultCodecEncodeError<
            <XactResultHeaderPERCodec as Codec<XactResultHeader>>::EncodeError,
            ResCodec::EncodeError,
            ErrCodec::EncodeError,
        >,
        <XactNotifyHeaderPERCodec as Codec<XactNotifyHeader>>::EncodeError
    >;
    type Param = (SealCodec::Param, PayloadCodec::Param, EffectCodec::Param,
                  ResCodec::Param, ErrCodec::Param);

    fn create(param: Self::Param) -> Result<Self, Self::CreateError> {
        let (seal, payload, effect, res, err) = param;
        let req_codec = XactSealedCodec::create((seal.clone(),
                                                 (payload.clone(),
                                                  effect.clone())))
            .map_err(|err| XactBatchCodecCreateError::Req {
                err: err
            })?;
        let committed_codec = XactCommittedRoundCodec::create((seal.clone(),
                                                               payload.clone(),
                                                               effect.clone()))
            .map_err(|err| XactBatchCodecCreateError::Committed {
                err: err
            })?;
        let res_codec = XactResultCodec::create((res.clone(), err.clone()))
            .map_err(|err| XactBatchCodecCreateError::Res {
                err: err
            })?;
        let hash = H::default();

        Ok(XactBatchHashCodec {
            header_codec: XactBatchHeaderPERCodec::default(),
            notify_codec: XactNotifyHeaderPERCodec::default(),
            committed_codec: committed_codec,
            req_codec: req_codec,
            res_codec: res_codec,
            hash: hash
        })
    }

    #[inline]
    fn buf_size(
        &self,
        val: &XactHashBatch<RoundID, H::HashID, Seal, Payload, Effect, Res, Err>,
    ) -> usize {
        let req: usize = val.reqs.iter()
            .map(|req| self.req_codec.buf_size(req)).sum();
        let committed: usize = val.committed.iter()
            .map(|committed| self.committed_codec.buf_size(committed))
            .sum();
        let res: usize = val.results.iter()
            .map(|res| self.res_codec.buf_size(res)).sum();
        let notify: usize = val.notifies.iter()
            .map(|_| XactBatchHeaderPERCodec::MAX_BYTES).sum();

        req + committed + res + notify + 12
    }

    fn encode(
        &mut self,
        val: &XactHashBatch<RoundID, H::HashID, Seal, Payload, Effect, Res, Err>,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let header = XactBatchHeader {
            ncommitted: val.committed.len() as u32,
            nreqs: val.reqs.len() as u32,
            nresults: val.results.len() as u32,
            nnotifies: val.notifies.len() as u32,
        };
        let mut curr = 0;

        curr += self
            .header_codec
            .encode(&header, &mut buf[curr..])
            .map_err(|err| XactBatchCodecEncodeError::Header {
                err: err
            })?;

        for committed in val.committed.iter() {
            curr += self
                .committed_codec
                .encode(&committed, &mut buf[curr..])
                .map_err(|err| XactBatchCodecEncodeError::Committed {
                    err: err
                })?;
        }

        for req in val.reqs.iter() {
            curr += self
                .req_codec
                .encode(&req, &mut buf[curr..])
                .map_err(|err| XactBatchCodecEncodeError::Req {
                    err: err
                })?;
        }

        for result in val.results.iter() {
            curr += self
                .res_codec
                .encode(&result, &mut buf[curr..])
                .map_err(|err| XactBatchCodecEncodeError::Res {
                    err: err
                })?;
        }

        for notify in val.notifies.iter() {
            let hash = notify.hash.bytes().to_vec();
            let state = (&notify.state).into();
            let notify = XactNotifyHeader {
                hash: hash,
                state: state
            };

            curr += self
                .notify_codec
                .encode(&notify, &mut buf[curr..])
                .map_err(|err| XactBatchCodecEncodeError::Notify {
                    err: err
                })?;
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<
            (XactHashBatch<RoundID, H::HashID, Seal, Payload, Effect, Res, Err>,
             usize),
        Self::DecodeError
    > {
        let mut curr = 0;
        let (header, nbytes) = self
            .header_codec
            .decode(&buf[curr..])
            .map_err(|err| XactBatchCodecDecodeError::Header {
                err: err
            })?;

        curr += nbytes;

        let mut committed = Vec::with_capacity(header.ncommitted as usize);

        for _ in 0..header.ncommitted {
            let (round, nbytes) = self
                .committed_codec
                .decode(&buf[curr..])
                .map_err(|err| XactBatchCodecDecodeError::Committed {
                    err: err
                })?;

            committed.push(round);
            curr += nbytes;
        }


        let mut reqs = Vec::with_capacity(header.nreqs as usize);

        for _ in 0..header.nreqs {
            let (req, nbytes) = self
                .req_codec
                .decode(&buf[curr..])
                .map_err(|err| XactBatchCodecDecodeError::Req {
                    err: err
                })?;

            reqs.push(req);
            curr += nbytes;
        }

        let mut results = Vec::with_capacity(header.nresults as usize);

        for _ in 0..header.nresults {
            let (res, nbytes) = self
                .res_codec
                .decode(&buf[curr..])
                .map_err(|err| XactBatchCodecDecodeError::Res {
                    err: err
                })?;

            results.push(res);
            curr += nbytes;
        }

        let mut notifies = Vec::with_capacity(header.nnotifies as usize);

        for _ in 0..header.nnotifies {
            let (notify, nbytes) = self
                .notify_codec
                .decode(&buf[curr..])
                .map_err(|err| XactBatchCodecDecodeError::Notify {
                    err: err
                })?;
            let hash = self.hash.wrap_hashed_bytes(&notify.hash)
                .map_err(|err| XactBatchCodecDecodeError::Hash {
                    err: err
                })?;
            let state = notify.state.try_into()
                .map_err(|err| XactBatchCodecDecodeError::State {
                    err: err
                })?;
            let notify = XactNotify {
                hash: hash,
                state: state
            };

            notifies.push(notify);
            curr += nbytes;
        }

        Ok((XactHashBatch {
            committed: committed,
            reqs: reqs,
            notifies: notifies,
            results: results
        }, curr))
    }
}

impl<RoundID, H, Seal, SealCodec>
    Codec<XactHashBatch<RoundID, H::HashID, Seal,
                        Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>>>
    for XactBatchBlobCodec<RoundID, H, Seal, SealCodec>
where
    H: Clone + Default + HashAlgo,
    H::HashID: Clone,
    RoundID: Clone + From<u128> + Into<u128>,
    SealCodec: Codec<Seal>,
    SealCodec::Param: Clone,
{
    type CreateError = XactBatchCodecCreateError<
        XactSealedCodecCreateError<
            SealCodec::CreateError,
            XactReqCodecCreateError<
                Infallible,
                Infallible
            >
        >,
        XactCommittedRoundCodecCreateError<
            SealCodec::CreateError,
            XactReqCodecCreateError<
                Infallible,
                Infallible
            >
        >,
        XactResultCodecCreateError<
            Infallible,
            Infallible
        >,
    >;
    type DecodeError = XactBatchCodecDecodeError<
        <XactBatchHeaderPERCodec as Codec<XactBatchHeader>>::DecodeError,
        XactSealedCodecError<
            <XactSealHeaderPERCodec as Codec<XactSealHeader>>::DecodeError,
            SealCodec::DecodeError,
            XactReqCodecDecodeError<
                Infallible,
                Infallible,
                <XactUncommittedReqHeaderPERCodec as Codec<XactUncommittedReqHeader>>::DecodeError
            >
        >,
        XactCommittedRoundCodecDecodeError<
            <XactCommittedRoundHeaderPERCodec as Codec<XactCommittedRoundHeader>>::DecodeError,
            SealCodec::DecodeError,
            XactReqCodecDecodeError<
                Infallible,
                Infallible,
                <XactCommittedReqHeaderPERCodec as Codec<XactCommittedReqHeader>>::DecodeError
            >
        >,
        XactResultCodecDecodeError<
            <XactResultHeaderPERCodec as Codec<XactResultHeader>>::DecodeError,
            Infallible,
            Infallible,
        >,
        <XactNotifyHeaderPERCodec as Codec<XactNotifyHeader>>::DecodeError
    >;
    type EncodeError = XactBatchCodecEncodeError<
        <XactBatchHeaderPERCodec as Codec<XactBatchHeader>>::EncodeError,
        XactSealedCodecError<
            <XactSealHeaderPERCodec as Codec<XactSealHeader>>::EncodeError,
            SealCodec::EncodeError,
            XactReqCodecEncodeError<
                Infallible,
                Infallible,
                <XactUncommittedReqHeaderPERCodec as Codec<XactUncommittedReqHeader>>::EncodeError
            >
        >,
        XactCommittedRoundCodecEncodeError<
            <XactCommittedRoundHeaderPERCodec as Codec<XactCommittedRoundHeader>>::EncodeError,
            SealCodec::EncodeError,
            XactReqCodecEncodeError<
                Infallible,
                Infallible,
                <XactCommittedReqHeaderPERCodec as Codec<XactCommittedReqHeader>>::EncodeError
            >
        >,
        XactResultCodecEncodeError<
            <XactResultHeaderPERCodec as Codec<XactResultHeader>>::EncodeError,
            Infallible,
            Infallible,
        >,
        <XactNotifyHeaderPERCodec as Codec<XactNotifyHeader>>::EncodeError
    >;
    type Param = SealCodec::Param;

    fn create(param: Self::Param) -> Result<Self, Self::CreateError> {
        let req_codec = XactSealedCodec::create((param.clone(), ()))
            .map_err(|err| XactBatchCodecCreateError::Req {
                err: err
            })?;
        let committed_codec = XactCommittedRoundBlobCodec::create(param.clone())
            .map_err(|err| XactBatchCodecCreateError::Committed {
                err: err
            })?;
        let res_codec = XactResultBlobCodec::create(())
            .map_err(|err| XactBatchCodecCreateError::Res {
                err: err
            })?;
        let hash = H::default();

        Ok(XactBatchBlobCodec {
            header_codec: XactBatchHeaderPERCodec::default(),
            notify_codec: XactNotifyHeaderPERCodec::default(),
            committed_codec: committed_codec,
            req_codec: req_codec,
            res_codec: res_codec,
            hash: hash
        })
    }

    #[inline]
    fn buf_size(
        &self,
        val: &XactHashBatch<RoundID, H::HashID, Seal,
                            Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>>,
    ) -> usize {
        let req: usize = val.reqs.iter()
            .map(|req| self.req_codec.buf_size(req)).sum();
        let committed: usize = val.committed.iter()
            .map(|committed| self.committed_codec.buf_size(committed))
            .sum();
        let res: usize = val.results.iter()
            .map(|res| self.res_codec.buf_size(res)).sum();
        let notify: usize = val.notifies.iter()
            .map(|_| XactBatchHeaderPERCodec::MAX_BYTES).sum();

        req + committed + res + notify + 12
    }

    fn encode(
        &mut self,
        val: &XactHashBatch<RoundID, H::HashID, Seal,
                            Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>>,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let header = XactBatchHeader {
            ncommitted: val.committed.len() as u32,
            nreqs: val.reqs.len() as u32,
            nresults: val.results.len() as u32,
            nnotifies: val.notifies.len() as u32,
        };
        let mut curr = 0;

        curr += self
            .header_codec
            .encode(&header, &mut buf[curr..])
            .map_err(|err| XactBatchCodecEncodeError::Header {
                err: err
            })?;

        for committed in val.committed.iter() {
            curr += self
                .committed_codec
                .encode(&committed, &mut buf[curr..])
                .map_err(|err| XactBatchCodecEncodeError::Committed {
                    err: err
                })?;
        }

        for req in val.reqs.iter() {
            curr += self
                .req_codec
                .encode(&req, &mut buf[curr..])
                .map_err(|err| XactBatchCodecEncodeError::Req {
                    err: err
                })?;
        }

        for result in val.results.iter() {
            curr += self
                .res_codec
                .encode(&result, &mut buf[curr..])
                .map_err(|err| XactBatchCodecEncodeError::Res {
                    err: err
                })?;
        }

        for notify in val.notifies.iter() {
            let hash = notify.hash.bytes().to_vec();
            let state = (&notify.state).into();
            let notify = XactNotifyHeader {
                hash: hash,
                state: state
            };

            curr += self
                .notify_codec
                .encode(&notify, &mut buf[curr..])
                .map_err(|err| XactBatchCodecEncodeError::Notify {
                    err: err
                })?;
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<
            (XactHashBatch<RoundID, H::HashID, Seal,
                           Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>>,
             usize),
        Self::DecodeError
    > {
        let mut curr = 0;
        let (header, nbytes) = self
            .header_codec
            .decode(&buf[curr..])
            .map_err(|err| XactBatchCodecDecodeError::Header {
                err: err
            })?;

        curr += nbytes;

        let mut committed = Vec::with_capacity(header.ncommitted as usize);

        for _ in 0..header.ncommitted {
            let (round, nbytes) = self
                .committed_codec
                .decode(&buf[curr..])
                .map_err(|err| XactBatchCodecDecodeError::Committed {
                    err: err
                })?;

            committed.push(round);
            curr += nbytes;
        }


        let mut reqs = Vec::with_capacity(header.nreqs as usize);

        for _ in 0..header.nreqs {
            let (req, nbytes) = self
                .req_codec
                .decode(&buf[curr..])
                .map_err(|err| XactBatchCodecDecodeError::Req {
                    err: err
                })?;

            reqs.push(req);
            curr += nbytes;
        }

        let mut results = Vec::with_capacity(header.nresults as usize);

        for _ in 0..header.nresults {
            let (res, nbytes) = self
                .res_codec
                .decode(&buf[curr..])
                .map_err(|err| XactBatchCodecDecodeError::Res {
                    err: err
                })?;

            results.push(res);
            curr += nbytes;
        }

        let mut notifies = Vec::with_capacity(header.nnotifies as usize);

        for _ in 0..header.nnotifies {
            let (notify, nbytes) = self
                .notify_codec
                .decode(&buf[curr..])
                .map_err(|err| XactBatchCodecDecodeError::Notify {
                    err: err
                })?;
            let hash = self.hash.wrap_hashed_bytes(&notify.hash)
                .map_err(|err| XactBatchCodecDecodeError::Hash {
                    err: err
                })?;
            let state = notify.state.try_into()
                .map_err(|err| XactBatchCodecDecodeError::State {
                    err: err
                })?;
            let notify = XactNotify {
                hash: hash,
                state: state
            };

            notifies.push(notify);
            curr += nbytes;
        }

        Ok((XactHashBatch {
            committed: committed,
            reqs: reqs,
            notifies: notifies,
            results: results
        }, curr))
    }
}


impl<Err> Display for XactError<Err>
where Err: Display {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            XactError::Error { err } => err.fmt(f),
            XactError::UnknownClass => write!(f, "unknown transaction class"),
            XactError::UnknownVersion =>
                write!(f, "unsupported version of transaction class"),
            XactError::UnknownInstance =>
                write!(f, "unknown instance of transaction class"),
            XactError::InvalidPayload =>
                write!(f, "error parsing transaction request"),
            XactError::InvalidEffect =>
                write!(f, "error parsing effects constraint"),
            XactError::EffectViolation =>
                write!(f, "violated effects constraint"),
            XactError::Unauthorized =>
                write!(f, "transaction request was unauthorization"),
            XactError::Internal =>
                write!(f, "internal error processing transaction request"),
        }
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

impl<RoundID> Display for XactNotifyState<RoundID>
where RoundID: Clone + Display + From<u128> + Into<u128> {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            XactNotifyState::Accept => write!(f, "accepted"),
            XactNotifyState::Consensus => write!(f, "submitted to consensus"),
            XactNotifyState::Commit { when } =>
                write!(f, "committed at {}", when),
            XactNotifyState::Dispatch => write!(f, "dispatched to processor"),
            XactNotifyState::Complete { when } =>
                write!(f, "completed at {}", when),
        }
    }
}

impl<RoundID, H> Display for XactNotify<RoundID, H>
where RoundID: Clone + Display + From<u128> + Into<u128>,
      H: Display + HashID {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        write!(f, "{}: {}", self.hash, self.state)
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
            XactReqCodecEncodeError::TooShort =>
                ErrorScope::Unrecoverable
        }
    }
}

impl<Seal, Inner> ScopedError for XactSealedCodecCreateError<Seal, Inner>
where
    Seal: ScopedError,
    Inner: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            XactSealedCodecCreateError::Seal { err } => err.scope(),
            XactSealedCodecCreateError::Inner { err } => err.scope()
        }
    }
}

impl<Header, Seal, Inner> ScopedError
    for XactSealedCodecError<Header, Seal, Inner>
where
    Header: ScopedError,
    Seal: ScopedError,
    Inner: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            XactSealedCodecError::Header { err } => err.scope(),
            XactSealedCodecError::Seal { err } => err.scope(),
            XactSealedCodecError::Inner { err } => err.scope(),
            XactSealedCodecError::TooShort => ErrorScope::Unrecoverable
        }
    }
}

impl<Seal, Req> ScopedError
    for XactCommittedRoundCodecCreateError<Seal, Req>
where
    Seal: ScopedError,
    Req: ScopedError,
{
    fn scope(&self) -> ErrorScope {
        match self {
            XactCommittedRoundCodecCreateError::Seal { err } => err.scope(),
            XactCommittedRoundCodecCreateError::Req { err } => err.scope(),
        }
    }
}

impl<Header, Seal, Req> ScopedError
    for XactCommittedRoundCodecEncodeError<Header, Seal, Req>
where
    Header: ScopedError,
    Seal: ScopedError,
    Req: ScopedError,
{
    fn scope(&self) -> ErrorScope {
        match self {
            XactCommittedRoundCodecEncodeError::Header { err } => err.scope(),
            XactCommittedRoundCodecEncodeError::Seal { err } => err.scope(),
            XactCommittedRoundCodecEncodeError::Req { err } => err.scope(),
            XactCommittedRoundCodecEncodeError::TooShort =>
                ErrorScope::Unrecoverable
        }
    }
}

impl<Header, Seal, Req> ScopedError
    for XactCommittedRoundCodecDecodeError<Header, Seal, Req>
where
    Header: ScopedError,
    Seal: ScopedError,
    Req: ScopedError,
{
    fn scope(&self) -> ErrorScope {
        match self {
            XactCommittedRoundCodecDecodeError::Header { err } => err.scope(),
            XactCommittedRoundCodecDecodeError::Seal { err } => err.scope(),
            XactCommittedRoundCodecDecodeError::Req { err } => err.scope(),
            XactCommittedRoundCodecDecodeError::Round { .. } |
            XactCommittedRoundCodecDecodeError::Hash { .. } |
            XactCommittedRoundCodecDecodeError::TooShort =>
                ErrorScope::Unrecoverable
        }
    }
}

impl<Res, Err> ScopedError for XactResultCodecCreateError<Res, Err>
where
    Res: ScopedError,
    Err: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            XactResultCodecCreateError::Res { err } => err.scope(),
            XactResultCodecCreateError::Err { err } => err.scope()
        }
    }
}

impl<Header, Res, Err> ScopedError
    for XactResultCodecEncodeError<Header, Res, Err>
where
    Header: ScopedError,
    Res: ScopedError,
    Err: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            XactResultCodecEncodeError::Header { err } => err.scope(),
            XactResultCodecEncodeError::Res { err } => err.scope(),
            XactResultCodecEncodeError::Err { err } => err.scope(),
            XactResultCodecEncodeError::TooShort => ErrorScope::Unrecoverable
        }
    }
}

impl<Header, Res, Err> ScopedError
    for XactResultCodecDecodeError<Header, Res, Err>
where
    Header: ScopedError,
    Res: ScopedError,
    Err: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            XactResultCodecDecodeError::Header { err } => err.scope(),
            XactResultCodecDecodeError::Res { err } => err.scope(),
            XactResultCodecDecodeError::Err { err } => err.scope(),
            XactResultCodecDecodeError::Hash { .. } |
            XactResultCodecDecodeError::TooShort => ErrorScope::Unrecoverable
        }
    }
}

impl<Req, Committed, Res> ScopedError
    for XactBatchCodecCreateError<Req, Committed, Res>
where
    Req: ScopedError,
    Committed: ScopedError,
    Res: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            XactBatchCodecCreateError::Req { err } => err.scope(),
            XactBatchCodecCreateError::Committed { err } => err.scope(),
            XactBatchCodecCreateError::Res { err } => err.scope(),
        }
    }
}

impl<Header, Req, Committed, Res, Notify> ScopedError
    for XactBatchCodecEncodeError<Header, Req, Committed, Res, Notify>
where
    Header: ScopedError,
    Req: ScopedError,
    Committed: ScopedError,
    Res: ScopedError,
    Notify: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            XactBatchCodecEncodeError::Header { err } => err.scope(),
            XactBatchCodecEncodeError::Req { err } => err.scope(),
            XactBatchCodecEncodeError::Committed { err } => err.scope(),
            XactBatchCodecEncodeError::Res { err } => err.scope(),
            XactBatchCodecEncodeError::Notify { err } => err.scope(),
        }
    }
}

impl<Header, Req, Committed, Res, Notify> ScopedError
    for XactBatchCodecDecodeError<Header, Req, Committed, Res, Notify>
where
    Header: ScopedError,
    Req: ScopedError,
    Committed: ScopedError,
    Res: ScopedError,
    Notify: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            XactBatchCodecDecodeError::Header { err } => err.scope(),
            XactBatchCodecDecodeError::Req { err } => err.scope(),
            XactBatchCodecDecodeError::Committed { err } => err.scope(),
            XactBatchCodecDecodeError::Res { err } => err.scope(),
            XactBatchCodecDecodeError::Notify { err } => err.scope(),
            XactBatchCodecDecodeError::State { .. } |
            XactBatchCodecDecodeError::Hash { .. } => ErrorScope::Unrecoverable
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
            XactReqCodecEncodeError::TooShort => {
                write!(f, "input buffer is too short")
            }
        }
    }
}

impl<Seal, Inner> Display for XactSealedCodecCreateError<Seal, Inner>
where
    Seal: Display,
    Inner: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            XactSealedCodecCreateError::Seal { err } => err.fmt(f),
            XactSealedCodecCreateError::Inner { err } => err.fmt(f)
        }
    }
}

impl<Header, Seal, Inner> Display for XactSealedCodecError<Header, Seal, Inner>
where
    Header: Display,
    Seal: Display,
    Inner: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            XactSealedCodecError::Header { err } => err.fmt(f),
            XactSealedCodecError::Seal { err } => err.fmt(f),
            XactSealedCodecError::Inner { err } => err.fmt(f),
            XactSealedCodecError::TooShort => {
                write!(f, "input buffer is too short")
            }
        }
    }
}

impl<Seal, Req> Display for XactCommittedRoundCodecCreateError<Seal, Req>
where
    Seal: Display,
    Req: Display,
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            XactCommittedRoundCodecCreateError::Seal { err } => err.fmt(f),
            XactCommittedRoundCodecCreateError::Req { err } => err.fmt(f),
        }
    }
}

impl<Header, Seal, Req> Display
    for XactCommittedRoundCodecEncodeError<Header, Seal, Req>
where
    Header: Display,
    Seal: Display,
    Req: Display,
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            XactCommittedRoundCodecEncodeError::Header { err } => err.fmt(f),
            XactCommittedRoundCodecEncodeError::Seal { err } => err.fmt(f),
            XactCommittedRoundCodecEncodeError::Req { err } => err.fmt(f),
            XactCommittedRoundCodecEncodeError::TooShort => {
                write!(f, "input buffer is too short")
            }
        }
    }
}

impl<Header, Seal, Req> Display
    for XactCommittedRoundCodecDecodeError<Header, Seal, Req>
where
    Header: Display,
    Seal: Display,
    Req: Display,
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            XactCommittedRoundCodecDecodeError::Header { err } => err.fmt(f),
            XactCommittedRoundCodecDecodeError::Seal { err } => err.fmt(f),
            XactCommittedRoundCodecDecodeError::Req { err } => err.fmt(f),
            XactCommittedRoundCodecDecodeError::Hash { err } => err.fmt(f),
            XactCommittedRoundCodecDecodeError::Round { .. } =>
                write!(f, "error converting round from bytes"),
            XactCommittedRoundCodecDecodeError::TooShort => {
                write!(f, "input buffer is too short")
            }
        }
    }
}

impl<Res, Err> Display for XactResultCodecCreateError<Res, Err>
where
    Res: Display,
    Err: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            XactResultCodecCreateError::Res { err } => err.fmt(f),
            XactResultCodecCreateError::Err { err } => err.fmt(f)
        }
    }
}

impl<Header, Res, Err> Display for XactResultCodecEncodeError<Header, Res, Err>
where
    Header: Display,
    Res: Display,
    Err: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            XactResultCodecEncodeError::Header { err } => err.fmt(f),
            XactResultCodecEncodeError::Res { err } => err.fmt(f),
            XactResultCodecEncodeError::Err { err } => err.fmt(f),
            XactResultCodecEncodeError::TooShort =>
                write!(f, "buffer is too short")
        }
    }
}

impl<Header, Res, Err> Display for XactResultCodecDecodeError<Header, Res, Err>
where
    Header: Display,
    Res: Display,
    Err: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            XactResultCodecDecodeError::Header { err } => err.fmt(f),
            XactResultCodecDecodeError::Hash { err } => err.fmt(f),
            XactResultCodecDecodeError::Res { err } => err.fmt(f),
            XactResultCodecDecodeError::Err { err } => err.fmt(f),
            XactResultCodecDecodeError::TooShort =>
                write!(f, "buffer is too short")
        }
    }
}

impl<Req, Committed, Res> Display
    for XactBatchCodecCreateError<Req, Committed, Res>
where
    Req: Display,
    Committed: Display,
    Res: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            XactBatchCodecCreateError::Req { err } => err.fmt(f),
            XactBatchCodecCreateError::Committed { err } => err.fmt(f),
            XactBatchCodecCreateError::Res { err } => err.fmt(f),
        }
    }
}

impl<Header, Req, Committed, Res, Notify> Display
    for XactBatchCodecEncodeError<Header, Req, Committed, Res, Notify>
where
    Header: Display,
    Req: Display,
    Committed: Display,
    Res: Display,
    Notify: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            XactBatchCodecEncodeError::Header { err } => err.fmt(f),
            XactBatchCodecEncodeError::Req { err } => err.fmt(f),
            XactBatchCodecEncodeError::Committed { err } => err.fmt(f),
            XactBatchCodecEncodeError::Res { err } => err.fmt(f),
            XactBatchCodecEncodeError::Notify { err } => err.fmt(f),
        }
    }
}

impl<Header, Req, Committed, Res, Notify> Display
    for XactBatchCodecDecodeError<Header, Req, Committed, Res, Notify>
where
    Header: Display,
    Req: Display,
    Committed: Display,
    Res: Display,
    Notify: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            XactBatchCodecDecodeError::Header { err } => err.fmt(f),
            XactBatchCodecDecodeError::Req { err } => err.fmt(f),
            XactBatchCodecDecodeError::Committed { err } => err.fmt(f),
            XactBatchCodecDecodeError::Res { err } => err.fmt(f),
            XactBatchCodecDecodeError::Notify { err } => err.fmt(f),
            XactBatchCodecDecodeError::Hash { err } => err.fmt(f),
            XactBatchCodecDecodeError::State { .. } =>
                write!(f, "round ID length")
        }
    }
}

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
            when: Some(crate::generated::xact::XactLinPoint {
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
            when: Some(crate::generated::xact::XactLinPoint {
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
    let mut codec: XactUncommittedReqBlobCodec<u128, SHA3Algo> =
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

#[test]
fn test_uncommitted_req_soft_effects_no_instance_blob() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::Effects {
        effects: vec![2, 1, 0],
        hard: false
    };
    let mut codec: XactUncommittedReqBlobCodec<u128, SHA3Algo> =
        XactUncommittedReqBlobCodec::create(())
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(
        &[0xfc, 0xc4, 0xb6, 0x25, 0xad, 0x52, 0x03, 0x6a,
          0xa0, 0xc7, 0x02, 0x25, 0xee, 0xa3, 0x56, 0x88,
          0x4c, 0x19, 0xf6, 0x2c, 0x3b, 0x86, 0x90, 0x1a,
          0x4d, 0x31, 0x77, 0x15, 0x10, 0x5a, 0x34, 0x78,
          0x1f, 0x72, 0xd0, 0x2d, 0x01, 0x4e, 0x76, 0x95,
          0xe0, 0x48, 0x3f, 0x7f, 0x7d, 0x52, 0xe3, 0x5c,
          0xf5, 0x76, 0x19, 0x98, 0x77, 0x78, 0xbc, 0xe1,
          0xbf, 0x75, 0x8e, 0xba, 0xa2, 0xb9, 0x63, 0x4f]
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

#[test]
fn test_uncommitted_req_hard_effects_instance_blob() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::Effects {
        effects: vec![2, 1, 0],
        hard: true
    };
    let mut codec: XactUncommittedReqBlobCodec<u128, SHA3Algo> =
        XactUncommittedReqBlobCodec::create(())
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(
        &[0x15, 0xed, 0x53, 0x61, 0x8b, 0xf6, 0x0d, 0xd3,
          0x12, 0xdb, 0x69, 0x3e, 0x5d, 0x48, 0xdb, 0x44,
          0x64, 0x29, 0x16, 0x7e, 0x1a, 0x37, 0x5a, 0x2e,
          0xc8, 0x2d, 0x6a, 0xca, 0x7b, 0x0d, 0xc9, 0xa0,
          0x87, 0x0f, 0x86, 0xaf, 0xa8, 0x88, 0x2e, 0x0d,
          0xbe, 0x9a, 0x2a, 0xf5, 0x82, 0x09, 0xa3, 0x2a,
          0x00, 0x35, 0x87, 0x86, 0x07, 0xa0, 0xc5, 0xec,
          0xb5, 0x72, 0x96, 0x73, 0xfc, 0xb8, 0x1d, 0x20]
    ).expect("Expected success");
    let req = XactUncommittedHashReq {
        hash: hash,
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: Some(0x1234567890abcdef),
        payload: vec![0, 1, 2, 3, 4, 5]
    };
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_soft_effects_instance_blob() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::Effects {
        effects: vec![2, 1, 0],
        hard: false
    };
    let mut codec: XactUncommittedReqBlobCodec<u128, SHA3Algo> =
        XactUncommittedReqBlobCodec::create(())
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(
        &[0xec, 0x17, 0x8c, 0x3c, 0xb6, 0x57, 0x79, 0x2f,
          0x34, 0xf5, 0x91, 0xd3, 0x49, 0x72, 0x48, 0xc3,
          0x83, 0x84, 0x71, 0x64, 0xbe, 0xef, 0xb5, 0xae,
          0xd7, 0xb6, 0xaf, 0x91, 0xcd, 0xd8, 0xc9, 0x4c,
          0xb8, 0x7c, 0x5c, 0x36, 0xe9, 0x0a, 0x2e, 0x62,
          0x71, 0x94, 0x8a, 0xc4, 0x3e, 0x90, 0xc8, 0x7d,
          0x3a, 0x1d, 0x48, 0x22, 0x51, 0xbb, 0x46, 0x57,
          0x0a, 0x8a, 0xa2, 0xbc, 0x1e, 0x25, 0x59, 0xa3]
    ).expect("Expected success");
    let req = XactUncommittedHashReq {
        hash: hash,
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: Some(0x1234567890abcdef),
        payload: vec![0, 1, 2, 3, 4, 5]
    };
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_hard_none_no_linpoint_no_instance_blob() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::HardNone {
        when: None
    };
    let mut codec: XactUncommittedReqBlobCodec<u128, SHA3Algo> =
        XactUncommittedReqBlobCodec::create(())
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(
        &[0xc7, 0xcc, 0xca, 0x97, 0x28, 0xef, 0xb3, 0xe4,
          0xec, 0xa4, 0x4f, 0x7b, 0xbc, 0x1d, 0xac, 0x5e,
          0x36, 0x26, 0x93, 0xc0, 0xd7, 0xeb, 0x90, 0xca,
          0x2e, 0x48, 0x5d, 0xa8, 0x48, 0xca, 0x35, 0x0f,
          0x3b, 0x62, 0x0e, 0x5c, 0x65, 0x1a, 0x30, 0xde,
          0x2e, 0x80, 0x4a, 0x6e, 0xac, 0xaa, 0x7d, 0x57,
          0x16, 0x74, 0xa4, 0x76, 0x5d, 0x17, 0xf4, 0xb1,
          0x3d, 0x6c, 0x23, 0xc7, 0x26, 0x3f, 0x8e, 0x33]
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

#[test]
fn test_uncommitted_req_hard_none_linpoint_no_instance_blob() {
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
    let mut codec: XactUncommittedReqBlobCodec<u128, SHA3Algo> =
        XactUncommittedReqBlobCodec::create(())
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(
        &[0x77, 0x85, 0x83, 0xdf, 0x1a, 0x06, 0xc5, 0xc6,
          0x26, 0x9f, 0x3b, 0x62, 0x01, 0x7b, 0x47, 0x7a,
          0x53, 0x01, 0x05, 0x67, 0xd9, 0xdc, 0xe8, 0x5f,
          0x62, 0x0f, 0xb5, 0x18, 0x2d, 0x54, 0x21, 0xae,
          0xdd, 0xa6, 0xa2, 0xc8, 0x86, 0x5e, 0xc2, 0x25,
          0xe1, 0xb5, 0x27, 0x6c, 0x83, 0x7f, 0x1f, 0x63,
          0x4f, 0x1e, 0x45, 0x7f, 0x2d, 0x3a, 0x90, 0x76,
          0x9d, 0x91, 0x1c, 0x64, 0x45, 0xd1, 0x6e, 0xda]
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

#[test]
fn test_uncommitted_req_hard_none_no_linpoint_instance_blob() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::HardNone {
        when: None
    };
    let mut codec: XactUncommittedReqBlobCodec<u128, SHA3Algo> =
        XactUncommittedReqBlobCodec::create(())
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(
        &[0x64, 0x07, 0xec, 0x83, 0xf5, 0x71, 0xec, 0x93,
          0xbc, 0xa9, 0x5d, 0x79, 0x9b, 0xb0, 0x39, 0x26,
          0xaa, 0xcc, 0x4f, 0x4f, 0x68, 0x91, 0x6a, 0x8e,
          0x8d, 0xc0, 0xfa, 0xb5, 0x96, 0x44, 0xa4, 0x2c,
          0x5f, 0x3f, 0x24, 0x1b, 0x6c, 0x58, 0x95, 0x80,
          0x76, 0xbb, 0xcb, 0xaf, 0x6d, 0x5a, 0x0a, 0xa4,
          0x3c, 0xe3, 0x19, 0x75, 0x45, 0x6f, 0x57, 0x2d,
          0x6e, 0x11, 0xeb, 0xe3, 0x53, 0x22, 0x59, 0x37]
    ).expect("Expected success");
    let req = XactUncommittedHashReq {
        hash: hash,
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: Some(0x1234567890abcdef),
        payload: vec![0, 1, 2, 3, 4, 5]
    };
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_hard_none_linpoint_instance_blob() {
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
    let mut codec: XactUncommittedReqBlobCodec<u128, SHA3Algo> =
        XactUncommittedReqBlobCodec::create(())
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(
        &[0x20, 0x76, 0xd1, 0x0e, 0x5b, 0x0f, 0x9c, 0xaf,
          0xae, 0xbc, 0x52, 0x1b, 0xe1, 0x29, 0x26, 0xae,
          0x58, 0x9f, 0x07, 0x8d, 0x75, 0xf5, 0xeb, 0x95,
          0xd2, 0x36, 0x45, 0xf6, 0x91, 0x0f, 0x44, 0x41,
          0x5d, 0x27, 0x2a, 0xaf, 0xf7, 0x7d, 0x75, 0x23,
          0x84, 0xc0, 0x1f, 0x7d, 0x32, 0x23, 0xc9, 0xe3,
          0xba, 0x6d, 0x20, 0xff, 0x41, 0x2f, 0x46, 0xfe,
          0x77, 0x5a, 0xa1, 0xa5, 0x23, 0x45, 0x1b, 0x68]
    ).expect("Expected success");
    let req = XactUncommittedHashReq {
        hash: hash,
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: Some(0x1234567890abcdef),
        payload: vec![0, 1, 2, 3, 4, 5]
    };
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_soft_none_no_instance_blob() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::SoftNone;
    let mut codec: XactUncommittedReqBlobCodec<u128, SHA3Algo> =
        XactUncommittedReqBlobCodec::create(())
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(
        &[0x53, 0x10, 0x18, 0x5f, 0xc1, 0xa9, 0x2f, 0xb3,
          0xf6, 0x8b, 0xcb, 0x8e, 0x5c, 0xe4, 0x47, 0xd3,
          0xf4, 0x7c, 0xa8, 0xfb, 0xb7, 0xfd, 0x63, 0x53,
          0x4e, 0x67, 0xd7, 0x58, 0x39, 0xf9, 0x6a, 0x2d,
          0xd7, 0x35, 0xcc, 0x83, 0x9a, 0x90, 0x09, 0x4e,
          0x25, 0xcf, 0x1f, 0xa4, 0x22, 0x54, 0x9b, 0xe1,
          0x7c, 0xad, 0x1a, 0x90, 0x70, 0x83, 0x98, 0x95,
          0x6c, 0xb3, 0x94, 0x64, 0x65, 0x13, 0xd9, 0x4b]
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

    for byte in decoded.hash.bytes().iter() {
        print!("0x{:02x}, ", byte);
    }
    println!();

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_soft_none_instance_blob() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::SoftNone;
    let mut codec: XactUncommittedReqBlobCodec<u128, SHA3Algo> =
        XactUncommittedReqBlobCodec::create(())
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(
        &[0x8b, 0x5d, 0x1d, 0x7d, 0x87, 0x1e, 0x12, 0xf9,
          0xa9, 0x2e, 0x7b, 0x0d, 0xcd, 0x24, 0x27, 0xc5,
          0x84, 0x5b, 0x64, 0xe9, 0x16, 0xc0, 0xde, 0x18,
          0xcd, 0x6d, 0x06, 0x4d, 0xbd, 0x8a, 0x47, 0x4d,
          0x9f, 0x05, 0x68, 0x9d, 0x7e, 0x10, 0x8d, 0x45,
          0xa2, 0x23, 0xc9, 0xf1, 0x80, 0xe5, 0xe7, 0x03,
          0xb9, 0x4b, 0xac, 0x15, 0xd5, 0xa1, 0x86, 0x8d,
          0x01, 0x43, 0x76, 0x3b, 0x2f, 0x5f, 0xba, 0x27]
    ).expect("Expected success");
    let req = XactUncommittedHashReq {
        hash: hash,
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: Some(0x1234567890abcdef),
        payload: vec![0, 1, 2, 3, 4, 5]
    };
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    for byte in decoded.hash.bytes().iter() {
        print!("0x{:02x}, ", byte);
    }
    println!();

    assert_eq!(req, decoded);
}

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
    let mut codec: XactUncommittedReqHashCodec<u128, SHA3Algo, _, _,
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
fn test_uncommitted_req_soft_effects_no_instance_hash() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::Effects {
        effects: TestEffects {
            effects: vec![2, 1, 0]
        },
        hard: false
    };
    let mut codec: XactUncommittedReqHashCodec<u128, SHA3Algo, _, _,
                                               TestPayloadCodec,
                                               TestEffectsCodec> =
        XactUncommittedReqHashCodec::create(((), ()))
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(
        &[0xfc, 0xc4, 0xb6, 0x25, 0xad, 0x52, 0x03, 0x6a,
          0xa0, 0xc7, 0x02, 0x25, 0xee, 0xa3, 0x56, 0x88,
          0x4c, 0x19, 0xf6, 0x2c, 0x3b, 0x86, 0x90, 0x1a,
          0x4d, 0x31, 0x77, 0x15, 0x10, 0x5a, 0x34, 0x78,
          0x1f, 0x72, 0xd0, 0x2d, 0x01, 0x4e, 0x76, 0x95,
          0xe0, 0x48, 0x3f, 0x7f, 0x7d, 0x52, 0xe3, 0x5c,
          0xf5, 0x76, 0x19, 0x98, 0x77, 0x78, 0xbc, 0xe1,
          0xbf, 0x75, 0x8e, 0xba, 0xa2, 0xb9, 0x63, 0x4f]
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
fn test_uncommitted_req_hard_effects_instance_hash() {
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
    let mut codec: XactUncommittedReqHashCodec<u128, SHA3Algo, _, _,
                                               TestPayloadCodec,
                                               TestEffectsCodec> =
        XactUncommittedReqHashCodec::create(((), ()))
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(
        &[0x15, 0xed, 0x53, 0x61, 0x8b, 0xf6, 0x0d, 0xd3,
          0x12, 0xdb, 0x69, 0x3e, 0x5d, 0x48, 0xdb, 0x44,
          0x64, 0x29, 0x16, 0x7e, 0x1a, 0x37, 0x5a, 0x2e,
          0xc8, 0x2d, 0x6a, 0xca, 0x7b, 0x0d, 0xc9, 0xa0,
          0x87, 0x0f, 0x86, 0xaf, 0xa8, 0x88, 0x2e, 0x0d,
          0xbe, 0x9a, 0x2a, 0xf5, 0x82, 0x09, 0xa3, 0x2a,
          0x00, 0x35, 0x87, 0x86, 0x07, 0xa0, 0xc5, 0xec,
          0xb5, 0x72, 0x96, 0x73, 0xfc, 0xb8, 0x1d, 0x20]
    ).expect("Expected success");
    let req = XactUncommittedHashReq {
        hash: hash,
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: Some(0x1234567890abcdef),
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
fn test_uncommitted_req_soft_effects_instance_hash() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::Effects {
        effects: TestEffects {
            effects: vec![2, 1, 0]
        },
        hard: false
    };
    let mut codec: XactUncommittedReqHashCodec<u128, SHA3Algo, _, _,
                                               TestPayloadCodec,
                                               TestEffectsCodec> =
        XactUncommittedReqHashCodec::create(((), ()))
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(
        &[0xec, 0x17, 0x8c, 0x3c, 0xb6, 0x57, 0x79, 0x2f,
          0x34, 0xf5, 0x91, 0xd3, 0x49, 0x72, 0x48, 0xc3,
          0x83, 0x84, 0x71, 0x64, 0xbe, 0xef, 0xb5, 0xae,
          0xd7, 0xb6, 0xaf, 0x91, 0xcd, 0xd8, 0xc9, 0x4c,
          0xb8, 0x7c, 0x5c, 0x36, 0xe9, 0x0a, 0x2e, 0x62,
          0x71, 0x94, 0x8a, 0xc4, 0x3e, 0x90, 0xc8, 0x7d,
          0x3a, 0x1d, 0x48, 0x22, 0x51, 0xbb, 0x46, 0x57,
          0x0a, 0x8a, 0xa2, 0xbc, 0x1e, 0x25, 0x59, 0xa3]
    ).expect("Expected success");
    let req = XactUncommittedHashReq {
        hash: hash,
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: Some(0x1234567890abcdef),
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
fn test_uncommitted_req_hard_none_no_linpoint_no_instance_hash() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::HardNone {
        when: None
    };
    let mut codec: XactUncommittedReqHashCodec<u128, SHA3Algo, _, _,
                                               TestPayloadCodec,
                                               TestEffectsCodec> =
        XactUncommittedReqHashCodec::create(((), ()))
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(
        &[0xc7, 0xcc, 0xca, 0x97, 0x28, 0xef, 0xb3, 0xe4,
          0xec, 0xa4, 0x4f, 0x7b, 0xbc, 0x1d, 0xac, 0x5e,
          0x36, 0x26, 0x93, 0xc0, 0xd7, 0xeb, 0x90, 0xca,
          0x2e, 0x48, 0x5d, 0xa8, 0x48, 0xca, 0x35, 0x0f,
          0x3b, 0x62, 0x0e, 0x5c, 0x65, 0x1a, 0x30, 0xde,
          0x2e, 0x80, 0x4a, 0x6e, 0xac, 0xaa, 0x7d, 0x57,
          0x16, 0x74, 0xa4, 0x76, 0x5d, 0x17, 0xf4, 0xb1,
          0x3d, 0x6c, 0x23, 0xc7, 0x26, 0x3f, 0x8e, 0x33]
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
fn test_uncommitted_req_hard_none_linpoint_no_instance_hash() {
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
    let mut codec: XactUncommittedReqHashCodec<u128, SHA3Algo, _, _,
                                               TestPayloadCodec,
                                               TestEffectsCodec> =
        XactUncommittedReqHashCodec::create(((), ()))
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(
        &[0x77, 0x85, 0x83, 0xdf, 0x1a, 0x06, 0xc5, 0xc6,
          0x26, 0x9f, 0x3b, 0x62, 0x01, 0x7b, 0x47, 0x7a,
          0x53, 0x01, 0x05, 0x67, 0xd9, 0xdc, 0xe8, 0x5f,
          0x62, 0x0f, 0xb5, 0x18, 0x2d, 0x54, 0x21, 0xae,
          0xdd, 0xa6, 0xa2, 0xc8, 0x86, 0x5e, 0xc2, 0x25,
          0xe1, 0xb5, 0x27, 0x6c, 0x83, 0x7f, 0x1f, 0x63,
          0x4f, 0x1e, 0x45, 0x7f, 0x2d, 0x3a, 0x90, 0x76,
          0x9d, 0x91, 0x1c, 0x64, 0x45, 0xd1, 0x6e, 0xda]
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
fn test_uncommitted_req_hard_none_no_linpoint_instance_hash() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::HardNone {
        when: None
    };
    let mut codec: XactUncommittedReqHashCodec<u128, SHA3Algo, _, _,
                                               TestPayloadCodec,
                                               TestEffectsCodec> =
        XactUncommittedReqHashCodec::create(((), ()))
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(
        &[0x64, 0x07, 0xec, 0x83, 0xf5, 0x71, 0xec, 0x93,
          0xbc, 0xa9, 0x5d, 0x79, 0x9b, 0xb0, 0x39, 0x26,
          0xaa, 0xcc, 0x4f, 0x4f, 0x68, 0x91, 0x6a, 0x8e,
          0x8d, 0xc0, 0xfa, 0xb5, 0x96, 0x44, 0xa4, 0x2c,
          0x5f, 0x3f, 0x24, 0x1b, 0x6c, 0x58, 0x95, 0x80,
          0x76, 0xbb, 0xcb, 0xaf, 0x6d, 0x5a, 0x0a, 0xa4,
          0x3c, 0xe3, 0x19, 0x75, 0x45, 0x6f, 0x57, 0x2d,
          0x6e, 0x11, 0xeb, 0xe3, 0x53, 0x22, 0x59, 0x37]
    ).expect("Expected success");
    let req = XactUncommittedHashReq {
        hash: hash,
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: Some(0x1234567890abcdef),
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
fn test_uncommitted_req_hard_none_linpoint_instance_hash() {
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
    let mut codec: XactUncommittedReqHashCodec<u128, SHA3Algo, _, _,
                                               TestPayloadCodec,
                                               TestEffectsCodec> =
        XactUncommittedReqHashCodec::create(((), ()))
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(
        &[0x20, 0x76, 0xd1, 0x0e, 0x5b, 0x0f, 0x9c, 0xaf,
          0xae, 0xbc, 0x52, 0x1b, 0xe1, 0x29, 0x26, 0xae,
          0x58, 0x9f, 0x07, 0x8d, 0x75, 0xf5, 0xeb, 0x95,
          0xd2, 0x36, 0x45, 0xf6, 0x91, 0x0f, 0x44, 0x41,
          0x5d, 0x27, 0x2a, 0xaf, 0xf7, 0x7d, 0x75, 0x23,
          0x84, 0xc0, 0x1f, 0x7d, 0x32, 0x23, 0xc9, 0xe3,
          0xba, 0x6d, 0x20, 0xff, 0x41, 0x2f, 0x46, 0xfe,
          0x77, 0x5a, 0xa1, 0xa5, 0x23, 0x45, 0x1b, 0x68]
    ).expect("Expected success");
    let req = XactUncommittedHashReq {
        hash: hash,
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: Some(0x1234567890abcdef),
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
fn test_uncommitted_req_soft_none_no_instance_hash() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::SoftNone;
    let mut codec: XactUncommittedReqHashCodec<u128, SHA3Algo, _, _,
                                               TestPayloadCodec,
                                               TestEffectsCodec> =
        XactUncommittedReqHashCodec::create(((), ()))
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(
        &[0x53, 0x10, 0x18, 0x5f, 0xc1, 0xa9, 0x2f, 0xb3,
          0xf6, 0x8b, 0xcb, 0x8e, 0x5c, 0xe4, 0x47, 0xd3,
          0xf4, 0x7c, 0xa8, 0xfb, 0xb7, 0xfd, 0x63, 0x53,
          0x4e, 0x67, 0xd7, 0x58, 0x39, 0xf9, 0x6a, 0x2d,
          0xd7, 0x35, 0xcc, 0x83, 0x9a, 0x90, 0x09, 0x4e,
          0x25, 0xcf, 0x1f, 0xa4, 0x22, 0x54, 0x9b, 0xe1,
          0x7c, 0xad, 0x1a, 0x90, 0x70, 0x83, 0x98, 0x95,
          0x6c, 0xb3, 0x94, 0x64, 0x65, 0x13, 0xd9, 0x4b]
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

    for byte in decoded.hash.bytes().iter() {
        print!("0x{:02x}, ", byte);
    }
    println!();

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_soft_none_instance_hash() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::SoftNone;
    let mut codec: XactUncommittedReqHashCodec<u128, SHA3Algo, _, _,
                                               TestPayloadCodec,
                                               TestEffectsCodec> =
        XactUncommittedReqHashCodec::create(((), ()))
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(
        &[0x8b, 0x5d, 0x1d, 0x7d, 0x87, 0x1e, 0x12, 0xf9,
          0xa9, 0x2e, 0x7b, 0x0d, 0xcd, 0x24, 0x27, 0xc5,
          0x84, 0x5b, 0x64, 0xe9, 0x16, 0xc0, 0xde, 0x18,
          0xcd, 0x6d, 0x06, 0x4d, 0xbd, 0x8a, 0x47, 0x4d,
          0x9f, 0x05, 0x68, 0x9d, 0x7e, 0x10, 0x8d, 0x45,
          0xa2, 0x23, 0xc9, 0xf1, 0x80, 0xe5, 0xe7, 0x03,
          0xb9, 0x4b, 0xac, 0x15, 0xd5, 0xa1, 0x86, 0x8d,
          0x01, 0x43, 0x76, 0x3b, 0x2f, 0x5f, 0xba, 0x27]
    ).expect("Expected success");
    let req = XactUncommittedHashReq {
        hash: hash,
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: Some(0x1234567890abcdef),
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    for byte in decoded.hash.bytes().iter() {
        print!("0x{:02x}, ", byte);
    }
    println!();

    assert_eq!(req, decoded);
}

#[test]
fn test_seal_header() {
    let header = XactSealHeader {
        len: 0xaaaa5555aaaa5555,
    };
    let mut codec = XactSealHeaderPERCodec::default();
    let mut buf = [0; XactSealHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_sealed_uncommitted_req() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::HardNone {
        when: None
    };
    let sealed = XactSealed {
        inner: XactUncommittedReq {
            version: Version::new(1, 2, 3),
            class: uuid,
            effects: effects_header,
            instance: Some(0x1234567890abcdef),
            payload: TestPayload {
                effects: vec![0, 1, 2, 3, 4, 5]
            }
        },
        seal: TestPayload {
            effects: vec![6, 7, 8, 9, 0]
        }
    };
    let mut codec: XactSealedCodec<
        _, _,
        TestPayloadCodec,
        XactUncommittedReqCodec<u128, _, _,
                                TestPayloadCodec,
                                TestEffectsCodec>,
    > = XactSealedCodec::create(((), ((), ())))
        .expect("Expected success");
    let len = codec.buf_size(&sealed);
    let mut buf = vec![0; len];
    let _ = codec.encode(&sealed, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(sealed, decoded);
}

#[test]
fn test_sealed_uncommitted_req_blob() {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let effects_header: XactEffects<u128, _> = XactEffects::HardNone {
        when: None
    };
    let sealed = XactSealed {
        inner: XactUncommittedReq {
            version: Version::new(1, 2, 3),
            class: uuid,
            effects: effects_header,
            instance: Some(0x1234567890abcdef),
            payload: TestPayload {
                effects: vec![0, 1, 2, 3, 4, 5]
            }
        },
        seal: vec![6, 7, 8, 9, 0]
    };
    let mut codec: XactSealedBlobCodec<
        _,
        XactUncommittedReqCodec<u128, _, _,
                                TestPayloadCodec,
                                TestEffectsCodec>,
    > = XactSealedBlobCodec::create(((), ()))
        .expect("Expected success");
    let len = codec.buf_size(&sealed);
    let mut buf = vec![0; len];
    let _ = codec.encode(&sealed, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(sealed, decoded);
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

#[test]
fn test_committed_round_header_no_seal() {
    let header = XactCommittedRoundHeader {
        round: vec![0x11; 16],
        seal: None,
        nreqs: 0xf
    };
    let mut codec = XactCommittedRoundHeaderPERCodec::default();
    let mut buf = [0; XactCommittedRoundHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_committed_round_header_seal() {
    let header = XactCommittedRoundHeader {
        round: vec![0x11; 16],
        seal: Some(XactConsensusSealHeader {
            hashes: vec![
                vec![0x00; 64], vec![0x11; 64],
                vec![0x22; 64], vec![0x33; 64],
                vec![0x44; 64], vec![0x55; 64],
                vec![0x66; 64], vec![0x77; 64],
                vec![0x88; 64], vec![0x99; 64],
                vec![0xaa; 64], vec![0xbb; 64],
                vec![0xcc; 64], vec![0xdd; 64],
                vec![0xee; 64], vec![0xff; 64]
            ],
            nseals: 0x1234567890abcdef
        }),
        nreqs: 0xf
    };
    let mut codec = XactCommittedRoundHeaderPERCodec::default();
    let mut buf = [0; XactCommittedRoundHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_committed_round_no_seal() {
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
    let header = XactCommittedRound {
        round: 0x1234567890abcdef,
        seal: None,
        reqs: vec![req]
    };
    let mut codec: XactCommittedRoundCodec<_, SHA3Algo, _, _, _,
                                           TestPayloadCodec,
                                           TestPayloadCodec,
                                           TestEffectsCodec> =
        XactCommittedRoundCodec::create(((), (), ()))
        .expect("Expected success");
    let len = codec.buf_size(&header);
    let mut buf = vec![0; len];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_committed_round_seal() {
    let hash = SHA3Algo::default();
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
    let header = XactCommittedRound {
        round: 0x1234567890abcdef,
        seal: Some(XactConsensusSeal {
            hashes: vec![
                hash.wrap_hashed_bytes(&[0x00; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0x11; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0x22; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0x33; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0x44; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0x55; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0x66; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0x77; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0x88; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0x99; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0xaa; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0xbb; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0xcc; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0xdd; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0xee; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0xff; 64])
                    .expect("Expected success")
            ],
            seals: vec![
                TestPayload {
                    effects: vec![0, 1, 2, 3, 4, 5]
                },
                TestPayload {
                    effects: vec![6, 7, 8, 9]
                }
            ]
        }),
        reqs: vec![req]
    };
    let mut codec: XactCommittedRoundCodec<_, SHA3Algo, _, _, _,
                                           TestPayloadCodec,
                                           TestPayloadCodec,
                                           TestEffectsCodec> =
        XactCommittedRoundCodec::create(((), (), ()))
        .expect("Expected success");
    let len = codec.buf_size(&header);
    let mut buf = vec![0; len];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_committed_round_no_seal_blob() {
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
    let header = XactCommittedRound {
        round: 0x1234567890abcdef,
        seal: None,
        reqs: vec![req]
    };
    let mut codec: XactCommittedRoundBlobCodec<_, SHA3Algo, _,
                                               TestPayloadCodec> =
        XactCommittedRoundBlobCodec::create(())
        .expect("Expected success");
    let len = codec.buf_size(&header);
    let mut buf = vec![0; len];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_committed_round_seal_blob() {
    let hash = SHA3Algo::default();
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
    let header = XactCommittedRound {
        round: 0x1234567890abcdef,
        seal: Some(XactConsensusSeal {
            hashes: vec![
                hash.wrap_hashed_bytes(&[0x00; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0x11; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0x22; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0x33; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0x44; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0x55; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0x66; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0x77; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0x88; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0x99; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0xaa; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0xbb; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0xcc; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0xdd; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0xee; 64])
                    .expect("Expected success"),
                hash.wrap_hashed_bytes(&[0xff; 64])
                    .expect("Expected success")
            ],
            seals: vec![
                TestPayload {
                    effects: vec![0, 1, 2, 3, 4, 5]
                },
                TestPayload {
                    effects: vec![6, 7, 8, 9]
                }
            ]
        }),
        reqs: vec![req]
    };
    let mut codec: XactCommittedRoundBlobCodec<_, SHA3Algo, _,
                                               TestPayloadCodec> =
        XactCommittedRoundBlobCodec::create(())
        .expect("Expected success");
    let len = codec.buf_size(&header);
    let mut buf = vec![0; len];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_result_header_ok() {
    let value = XactResultValueHeader::Ok(XactValueHeader {
        len: 0x1234567890abcdef
    });
    let header = XactResultHeader {
        hash: vec![0x11; 64],
        value: value
    };
    let mut codec = XactResultHeaderPERCodec::default();
    let mut buf = [0; XactResultHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_result_header_error() {
    let value = XactResultValueHeader::Error(XactErrorHeader {
        len: 0x1234567890abcdef
    });
    let header = XactResultHeader {
        hash: vec![0x11; 64],
        value: value
    };
    let mut codec = XactResultHeaderPERCodec::default();
    let mut buf = [0; XactResultHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_result_header_unknown_class() {
    let value = XactResultValueHeader::UnknownClass(Default::default());
    let header = XactResultHeader {
        hash: vec![0x11; 64],
        value: value
    };
    let mut codec = XactResultHeaderPERCodec::default();
    let mut buf = [0; XactResultHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_result_header_unknown_version() {
    let value = XactResultValueHeader::UnknownVersion(Default::default());
    let header = XactResultHeader {
        hash: vec![0x11; 64],
        value: value
    };
    let mut codec = XactResultHeaderPERCodec::default();
    let mut buf = [0; XactResultHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_result_header_unknown_instance() {
    let value = XactResultValueHeader::UnknownInstance(Default::default());
    let header = XactResultHeader {
        hash: vec![0x11; 64],
        value: value
    };
    let mut codec = XactResultHeaderPERCodec::default();
    let mut buf = [0; XactResultHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_result_header_invalid_payload() {
    let value = XactResultValueHeader::InvalidPayload(Default::default());
    let header = XactResultHeader {
        hash: vec![0x11; 64],
        value: value
    };
    let mut codec = XactResultHeaderPERCodec::default();
    let mut buf = [0; XactResultHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_result_header_invalid_effect() {
    let value = XactResultValueHeader::InvalidEffect(Default::default());
    let header = XactResultHeader {
        hash: vec![0x11; 64],
        value: value
    };
    let mut codec = XactResultHeaderPERCodec::default();
    let mut buf = [0; XactResultHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_result_header_effect_violation() {
    let value = XactResultValueHeader::EffectViolation(Default::default());
    let header = XactResultHeader {
        hash: vec![0x11; 64],
        value: value
    };
    let mut codec = XactResultHeaderPERCodec::default();
    let mut buf = [0; XactResultHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_result_header_unauthorized() {
    let value = XactResultValueHeader::Unauthorized(Default::default());
    let header = XactResultHeader {
        hash: vec![0x11; 64],
        value: value
    };
    let mut codec = XactResultHeaderPERCodec::default();
    let mut buf = [0; XactResultHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_result_header_internal() {
    let value = XactResultValueHeader::Internal(Default::default());
    let header = XactResultHeader {
        hash: vec![0x11; 64],
        value: value
    };
    let mut codec = XactResultHeaderPERCodec::default();
    let mut buf = [0; XactResultHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_result_ok() {
    let mut codec: XactResultCodec<SHA3Algo, _, _,
                                   TestPayloadCodec,
                                   TestPayloadCodec> =
        XactResultCodec::create(((), ()))
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactResult {
        res: Ok(TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }),
        hash: hash,
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_result_error() {
    let mut codec: XactResultCodec<SHA3Algo, _, _,
                                   TestPayloadCodec,
                                   TestPayloadCodec> =
        XactResultCodec::create(((), ()))
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactResult {
        res: Err(XactError::Error {
            err: TestPayload {
                effects: vec![0, 1, 2, 3, 4, 5]
            }
        }),
        hash: hash,
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_result_unknown_class() {
    let mut codec: XactResultCodec<SHA3Algo, _, _,
                                   TestPayloadCodec,
                                   TestPayloadCodec> =
        XactResultCodec::create(((), ()))
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactResult {
        res: Err(XactError::UnknownClass),
        hash: hash,
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_result_unknown_version() {
    let mut codec: XactResultCodec<SHA3Algo, _, _,
                                   TestPayloadCodec,
                                   TestPayloadCodec> =
        XactResultCodec::create(((), ()))
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactResult {
        res: Err(XactError::UnknownVersion),
        hash: hash,
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_result_unknown_instance() {
    let mut codec: XactResultCodec<SHA3Algo, _, _,
                                   TestPayloadCodec,
                                   TestPayloadCodec> =
        XactResultCodec::create(((), ()))
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactResult {
        res: Err(XactError::UnknownInstance),
        hash: hash,
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_result_invalid_payload() {
    let mut codec: XactResultCodec<SHA3Algo, _, _,
                                   TestPayloadCodec,
                                   TestPayloadCodec> =
        XactResultCodec::create(((), ()))
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactResult {
        res: Err(XactError::InvalidPayload),
        hash: hash,
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_result_invalid_effect() {
    let mut codec: XactResultCodec<SHA3Algo, _, _,
                                   TestPayloadCodec,
                                   TestPayloadCodec> =
        XactResultCodec::create(((), ()))
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactResult {
        res: Err(XactError::InvalidEffect),
        hash: hash,
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_result_effect_violation() {
    let mut codec: XactResultCodec<SHA3Algo, _, _,
                                   TestPayloadCodec,
                                   TestPayloadCodec> =
        XactResultCodec::create(((), ()))
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactResult {
        res: Err(XactError::EffectViolation),
        hash: hash,
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_result_unauthorized() {
    let mut codec: XactResultCodec<SHA3Algo, _, _,
                                   TestPayloadCodec,
                                   TestPayloadCodec> =
        XactResultCodec::create(((), ()))
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactResult {
        res: Err(XactError::Unauthorized),
        hash: hash,
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_result_internal() {
    let mut codec: XactResultCodec<SHA3Algo, _, _,
                                   TestPayloadCodec,
                                   TestPayloadCodec> =
        XactResultCodec::create(((), ()))
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactResult {
        res: Err(XactError::Internal),
        hash: hash,
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_result_ok_blob() {
    let mut codec: XactResultBlobCodec<SHA3Algo> =
        XactResultBlobCodec::create(())
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactResult {
        res: Ok(vec![0, 1, 2, 3, 4, 5]),
        hash: hash,
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_result_error_blob() {
    let mut codec: XactResultBlobCodec<SHA3Algo> =
        XactResultBlobCodec::create(())
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactResult {
        res: Err(XactError::Error {
            err: vec![0, 1, 2, 3, 4, 5]
        }),
        hash: hash,
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_result_unknown_class_blob() {
    let mut codec: XactResultBlobCodec<SHA3Algo> =
        XactResultBlobCodec::create(())
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactResult {
        res: Err(XactError::UnknownClass),
        hash: hash,
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_result_unknown_version_blob() {
    let mut codec: XactResultBlobCodec<SHA3Algo> =
        XactResultBlobCodec::create(())
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactResult {
        res: Err(XactError::UnknownVersion),
        hash: hash,
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_result_unknown_instance_blob() {
    let mut codec: XactResultBlobCodec<SHA3Algo> =
        XactResultBlobCodec::create(())
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactResult {
        res: Err(XactError::UnknownInstance),
        hash: hash,
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_result_invalid_payload_blob() {
    let mut codec: XactResultBlobCodec<SHA3Algo> =
        XactResultBlobCodec::create(())
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactResult {
        res: Err(XactError::InvalidPayload),
        hash: hash,
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_result_invalid_effect_blob() {
    let mut codec: XactResultBlobCodec<SHA3Algo> =
        XactResultBlobCodec::create(())
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactResult {
        res: Err(XactError::InvalidEffect),
        hash: hash,
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_result_effect_violation_blob() {
    let mut codec: XactResultBlobCodec<SHA3Algo> =
        XactResultBlobCodec::create(())
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactResult {
        res: Err(XactError::EffectViolation),
        hash: hash,
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_result_unauthorized_blob() {
    let mut codec: XactResultBlobCodec<SHA3Algo> =
        XactResultBlobCodec::create(())
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactResult {
        res: Err(XactError::Unauthorized),
        hash: hash,
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_result_internal_blob() {
    let mut codec: XactResultBlobCodec<SHA3Algo> =
        XactResultBlobCodec::create(())
        .expect("Expected success");
    let hash = codec.hash.wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactResult {
        res: Err(XactError::Internal),
        hash: hash,
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_header_accept() {
    let header = XactNotifyHeader {
        hash: vec![0x11; 64],
        state: XactNotifyStateHeader::Accept(Default::default())
    };
    let mut codec = XactNotifyHeaderPERCodec::default();
    let mut buf = [0; XactNotifyHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_notify_header_consensus() {
    let header = XactNotifyHeader {
        hash: vec![0x11; 64],
        state: XactNotifyStateHeader::Consensus(Default::default())
    };
    let mut codec = XactNotifyHeaderPERCodec::default();
    let mut buf = [0; XactNotifyHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_notify_header_commit() {
    let header = XactNotifyHeader {
        hash: vec![0x11; 64],
        state: XactNotifyStateHeader::Commit(
            crate::generated::xact::XactCommitState {
                when: crate::generated::xact::XactLinPoint {
                    round: vec![0x88; 16],
                    idx: 0x7
                }
            }
        )
    };
    let mut codec = XactNotifyHeaderPERCodec::default();
    let mut buf = [0; XactNotifyHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_notify_header_dispatch() {
    let header = XactNotifyHeader {
        hash: vec![0x11; 64],
        state: XactNotifyStateHeader::Dispatch(Default::default())
    };
    let mut codec = XactNotifyHeaderPERCodec::default();
    let mut buf = [0; XactNotifyHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_notify_header_complete() {
    let header = XactNotifyHeader {
        hash: vec![0x11; 64],
        state: XactNotifyStateHeader::Complete(
            crate::generated::xact::XactCommitState {
                when: crate::generated::xact::XactLinPoint {
                    round: vec![0x88; 16],
                    idx: 0x7
                }
            }
        )
    };
    let mut codec = XactNotifyHeaderPERCodec::default();
    let mut buf = [0; XactNotifyHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_notify_header() {
    let header = XactBatchHeader {
        ncommitted: 0xffffff,
        nreqs: 0xffffff,
        nresults: 0xffffff,
        nnotifies: 0xffffff,
    };
    let mut codec = XactBatchHeaderPERCodec::default();
    let mut buf = [0; XactBatchHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_batch() {
    let mut codec: XactBatchCodec<_, SHA3Algo, _, _, _, _, _,
                                  TestPayloadCodec,
                                  TestPayloadCodec,
                                  TestEffectsCodec,
                                  TestPayloadCodec,
                                  TestPayloadCodec>=
        XactBatchCodec::create(((), (), (), (), ()))
        .expect("Expected success");
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
    let sealed = XactSealed {
        seal: TestPayload {
            effects: vec![0xa, 0xb, 0xc, 0xd]
        },
        inner: req
    };
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        TEST_SERVICE_NAME.as_bytes()
    );
    let committed = XactCommittedReq {
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
    let round = XactCommittedRound {
        round: 0x1234567890abcdef,
        seal: Some(XactConsensusSeal {
            hashes: vec![
                codec.hash.wrap_hashed_bytes(&[0x00; 64])
                    .expect("Expected success"),
                codec.hash.wrap_hashed_bytes(&[0x11; 64])
                    .expect("Expected success"),
                codec.hash.wrap_hashed_bytes(&[0x22; 64])
                    .expect("Expected success"),
                codec.hash.wrap_hashed_bytes(&[0x33; 64])
                    .expect("Expected success"),
                codec.hash.wrap_hashed_bytes(&[0x44; 64])
                    .expect("Expected success"),
                codec.hash.wrap_hashed_bytes(&[0x55; 64])
                    .expect("Expected success"),
                codec.hash.wrap_hashed_bytes(&[0x66; 64])
                    .expect("Expected success"),
                codec.hash.wrap_hashed_bytes(&[0x77; 64])
                    .expect("Expected success"),
                codec.hash.wrap_hashed_bytes(&[0x88; 64])
                    .expect("Expected success"),
                codec.hash.wrap_hashed_bytes(&[0x99; 64])
                    .expect("Expected success"),
                codec.hash.wrap_hashed_bytes(&[0xaa; 64])
                    .expect("Expected success"),
                codec.hash.wrap_hashed_bytes(&[0xbb; 64])
                    .expect("Expected success"),
                codec.hash.wrap_hashed_bytes(&[0xcc; 64])
                    .expect("Expected success"),
                codec.hash.wrap_hashed_bytes(&[0xdd; 64])
                    .expect("Expected success"),
                codec.hash.wrap_hashed_bytes(&[0xee; 64])
                    .expect("Expected success"),
                codec.hash.wrap_hashed_bytes(&[0xff; 64])
                    .expect("Expected success")
            ],
            seals: vec![
                TestPayload {
                    effects: vec![0, 1, 2, 3, 4, 5]
                },
                TestPayload {
                    effects: vec![6, 7, 8, 9]
                }
            ]
        }),
        reqs: vec![committed]
    };
    let hash = codec.hash.wrap_hashed_bytes(&[0x11; 64])
        .expect("Expected success");
    let notify = XactNotify {
        hash: hash,
        state: XactNotifyState::Commit {
            when: XactLinPoint {
                round: 0x1234567890abcdef,
                idx: 0x7
            }
        }
    };
    let hash = codec.hash.wrap_hashed_bytes(&[0x88; 64])
        .expect("Expected success");
    let result = XactResult {
        res: Ok(TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }),
        hash: hash,
    };
    let batch = XactBatch {
        reqs: vec![sealed],
        committed: vec![round],
        results: vec![result],
        notifies: vec![notify]
    };
    let len = codec.buf_size(&batch);
    let mut buf = vec![0; len];
    let _ = codec.encode(&batch, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(batch, decoded);
}
