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
use crate::generated::xact::XactPrecommitState;
use crate::generated::xact::XactResultHeader;
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

const XACT_SEAL_HEADER_SIZE: usize = 9;
const XACT_SEAL_HEADER_BITS: usize = XACT_SEAL_HEADER_SIZE * 8;

const XACT_COMMITTED_ROUND_HEADER_SIZE: usize = 1051;
const XACT_COMMITTED_ROUND_HEADER_BITS: usize =
    XACT_COMMITTED_ROUND_HEADER_SIZE * 8;

const XACT_NOTIFY_HEADER_SIZE: usize = 90;
const XACT_NOTIFY_HEADER_BITS: usize = XACT_NOTIFY_HEADER_SIZE * 8;

const XACT_BATCH_HEADER_SIZE: usize = 12;
const XACT_BATCH_HEADER_BITS: usize = XACT_BATCH_HEADER_SIZE * 8;

type XactUncommittedReqHeaderPERCodec =
    PERCodec<XactUncommittedReqHeader, XACT_UNCOMMITTED_REQ_HEADER_BITS>;

type XactCommittedReqHeaderPERCodec =
    PERCodec<XactCommittedReqHeader, XACT_COMMITTED_REQ_HEADER_BITS>;

type XactCommittedRoundHeaderPERCodec =
    PERCodec<XactCommittedRoundHeader, XACT_COMMITTED_ROUND_HEADER_BITS>;

type XactSealHeaderPERCodec = PERCodec<XactSealHeader, XACT_SEAL_HEADER_BITS>;

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
where
    RoundID: Clone + From<u128> + Into<u128> {
    /// ID of the round in which this takes place.
    round: RoundID,
    /// Index within the round.
    idx: u8
}

/// Valid combinations of effects for an uncommitted request.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum XactEffects<RoundID, Effects>
where
    RoundID: Clone + From<u128> + Into<u128> {
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
    /// Instance of the transaction class.
    instance: u64,
    /// Effects for the transaction.
    effects: XactEffects<RoundID, Effects>,
    /// The request payload.
    payload: Payload
}

/// Uncommitted request with no hash.
///
/// This version is typically used by clients or other originators of
/// requests, who will compute the hash as part of encoding.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct XactUncommittedReq<RoundID, Payload, Effects>
where
    RoundID: Clone + From<u128> + Into<u128> {
    /// Class of transactions.
    class: Uuid,
    /// Version of the transaction class.
    version: Version,
    /// Instance of the transaction class.
    instance: u64,
    /// Effects for the transaction.
    effects: XactEffects<RoundID, Effects>,
    /// The request payload.
    payload: Payload
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
    /// Instance of the transaction class.
    instance: u64,
    /// Index within the transaction.
    idx: usize,
    /// Effects for the transaction.
    effects: Option<XactCommittedEffects<Effects>>,
    /// The request payload.
    payload: Payload
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
    /// Transaction was not committed, but produces effects.
    Uncommitted,
    /// Trasaction's hash does not match the hash in a seal.
    HashMismatch,
    /// Internal error occurred during execution.
    Internal
}

/// Notifications that can occur for a transaction request.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum XactNotifyState<RoundID, Res, Err>
where
    RoundID: Clone + From<u128> + Into<u128> {
    /// The transaction has been accepted by a peer.
    Accept,
    /// The transaction has been dispatched to a processor without
    /// being committed by consensus.
    PrecommitDispatch {
        /// The requested linearization point, if there is one.
        when: Option<XactLinPoint<RoundID>>
    },
    /// The transaction has been submitted to a consensus pool.
    Consensus,
    /// A batch containing the transaction has been committed by the
    /// consensus pool.
    Commit {
        /// The linearization point assigned by consensus.
        when: XactLinPoint<RoundID>
    },
    /// The transaction has been dispatched to a processor.
    Dispatch {
        /// The linearization point assigned by consensus.
        when: XactLinPoint<RoundID>
    },
    Success {
        /// The linearization point at which the transaction was executed.
        when: XactLinPoint<RoundID>,
        /// The result of execution, if present.
        result: Option<Res>
    },
    /// The transaction failed with an error.
    Error {
        /// The error information, if present.
        error: Option<XactError<Err>>
    }
}

/// Notifications about the state of a transaction request.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct XactNotify<RoundID, H, Res, Err>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: HashID {
    /// Hash of the request.
    hash: H,
    /// Notification state.
    state: XactNotifyState<RoundID, Res, Err>
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct XactBatch<RoundID, H, Seal, Payload, Effects, Res, Err>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: HashID {
    committed: Vec<XactCommittedRound<RoundID, H, Seal, Payload, Effects>>,
    reqs: Vec<XactSealed<Seal, XactUncommittedReq<RoundID, Payload, Effects>>>,
    notifies: Vec<XactNotify<RoundID, H, Res, Err>>
}

pub type XactBlobBatch<RoundID, H, Seal> =
    XactHashBatch<RoundID, H, Seal, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>>;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct XactHashBatch<RoundID, H, Seal, Payload, Effects, Res, Err>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: HashID {
    committed: Vec<XactCommittedRound<RoundID, H, Seal, Payload, Effects>>,
    reqs: Vec<
        XactSealed<Seal, XactUncommittedHashReq<RoundID, H, Payload, Effects>>
    >,
    notifies: Vec<XactNotify<RoundID, H, Res, Err>>
}

/// A codec for [XactUncommittedReq]s that does not produce hashes upon
/// decoding.
///
/// This will only encode or decode [XactUncommittedReq]s, which do not
/// have a hash. This is typically used by clients.
#[derive(Clone)]
pub struct XactUncommittedReqCodec<
    RoundID,
    Payload,
    Effect,
    PayloadCodec,
    EffectCodec
> where
    RoundID: Clone + From<u128> + Into<u128>,
    PayloadCodec: Codec<Payload>,
    EffectCodec: Codec<Effect> {
    payload: PhantomData<Payload>,
    effect: PhantomData<Effect>,
    round: PhantomData<RoundID>,
    req_codec: XactUncommittedReqHeaderPERCodec,
    payload_codec: PayloadCodec,
    effect_codec: EffectCodec
}

/// A codec for [XactUncommittedHashReq]s that produces hashes upon
/// decoding.
///
/// This will only encode or decode [XactUncommittedHashReq]s, which
/// have a hash. This is typically used by processors.
#[derive(Clone)]
pub struct XactUncommittedReqHashCodec<
    RoundID,
    H,
    Payload,
    Effect,
    PayloadCodec,
    EffectCodec
> where
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
    RoundID: Clone + From<u128> + Into<u128> {
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
    effect_codec: EffectCodec
}

#[derive(Clone)]
pub struct XactCommittedRoundCodec<
    RoundID,
    H,
    Seal,
    Payload,
    Effect,
    SealCodec,
    PayloadCodec,
    EffectCodec
> where
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
    req_codec:
        XactCommittedReqCodec<Payload, Effect, PayloadCodec, EffectCodec>,
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
    seal_codec: SealCodec
}

#[derive(Clone)]
pub struct XactSealedBlobCodec<Inner, InnerCodec>
where
    InnerCodec: Codec<Inner> {
    inner: PhantomData<Inner>,
    header_codec: XactSealHeaderPERCodec,
    inner_codec: InnerCodec
}

#[derive(Clone)]
pub struct XactNotifyCodec<RoundID, H, Res, Err, ResCodec, ErrCodec>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: HashAlgo,
    H::HashID: Clone,
    ResCodec: Codec<Res>,
    ErrCodec: Codec<Err> {
    round: PhantomData<RoundID>,
    res: PhantomData<Res>,
    err: PhantomData<Err>,
    res_codec: ResCodec,
    err_codec: ErrCodec,
    header_codec: XactNotifyHeaderPERCodec,
    hash: H
}

#[derive(Clone)]
pub struct XactNotifyBlobCodec<RoundID, H>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: Clone + HashAlgo,
    H::HashID: Clone {
    round: PhantomData<RoundID>,
    header_codec: XactNotifyHeaderPERCodec,
    hash: H
}

#[derive(Clone)]
pub struct XactBatchCodec<
    RoundID,
    H,
    Seal,
    Payload,
    Effect,
    Res,
    Err,
    SealCodec,
    PayloadCodec,
    EffectCodec,
    ResCodec,
    ErrCodec
> where
    RoundID: Clone + From<u128> + Into<u128>,
    H: HashAlgo,
    H::HashID: Clone,
    PayloadCodec: Codec<Payload>,
    EffectCodec: Codec<Effect>,
    SealCodec: Codec<Seal>,
    ResCodec: Codec<Res>,
    ErrCodec: Codec<Err> {
    header_codec: XactBatchHeaderPERCodec,
    committed_codec: XactCommittedRoundCodec<
        RoundID,
        H,
        Seal,
        Payload,
        Effect,
        SealCodec,
        PayloadCodec,
        EffectCodec
    >,
    req_codec: XactSealedCodec<
        Seal,
        XactUncommittedReq<RoundID, Payload, Effect>,
        SealCodec,
        XactUncommittedReqCodec<
            RoundID,
            Payload,
            Effect,
            PayloadCodec,
            EffectCodec
        >
    >,
    notify_codec: XactNotifyCodec<RoundID, H, Res, Err, ResCodec, ErrCodec>
}

#[derive(Clone)]
pub struct XactBatchHashCodec<
    RoundID,
    H,
    Seal,
    Payload,
    Effect,
    Res,
    Err,
    SealCodec,
    PayloadCodec,
    EffectCodec,
    ResCodec,
    ErrCodec
> where
    RoundID: Clone + From<u128> + Into<u128>,
    H: Default + HashAlgo,
    H::HashID: Clone,
    PayloadCodec: Codec<Payload>,
    EffectCodec: Codec<Effect>,
    SealCodec: Codec<Seal>,
    ResCodec: Codec<Res>,
    ErrCodec: Codec<Err> {
    header_codec: XactBatchHeaderPERCodec,
    committed_codec: XactCommittedRoundCodec<
        RoundID,
        H,
        Seal,
        Payload,
        Effect,
        SealCodec,
        PayloadCodec,
        EffectCodec
    >,
    req_codec: XactSealedCodec<
        Seal,
        XactUncommittedHashReq<RoundID, H::HashID, Payload, Effect>,
        SealCodec,
        XactUncommittedReqHashCodec<
            RoundID,
            H,
            Payload,
            Effect,
            PayloadCodec,
            EffectCodec
        >
    >,
    notify_codec: XactNotifyCodec<RoundID, H, Res, Err, ResCodec, ErrCodec>
}

#[derive(Clone)]
pub struct XactBatchBlobCodec<RoundID, H, Seal, SealCodec>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: Clone + Default + HashAlgo,
    H::HashID: Clone,
    SealCodec: Codec<Seal> {
    header_codec: XactBatchHeaderPERCodec,
    committed_codec: XactCommittedRoundBlobCodec<RoundID, H, Seal, SealCodec>,
    req_codec: XactSealedCodec<
        Seal,
        XactUncommittedHashReq<RoundID, H::HashID, Vec<u8>, Vec<u8>>,
        SealCodec,
        XactUncommittedReqBlobCodec<RoundID, H>
    >,
    notify_codec: XactNotifyBlobCodec<RoundID, H>
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
    }
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

/// Errors that can occur creating an [XactNotifyCodec].
#[derive(Debug)]
pub enum XactNotifyCodecCreateError<Res, Err> {
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

/// Errors that can occur in an [XactNotifyCodec].
#[derive(Debug)]
pub enum XactNotifyCodecEncodeError<Header, Res, Err> {
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

/// Errors that can occur in an [XactNotifyCodec].
#[derive(Debug)]
pub enum XactNotifyCodecDecodeError<Header, Res, Err> {
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
pub enum XactBatchCodecCreateError<Req, Committed, Notify> {
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
    /// Error occurred creating the notify codec.
    Notify {
        /// The error that occurred creating the notify codec.
        err: Notify
    }
}

/// Errors that can occur encoding in an [XactBatchCodec].
#[derive(Debug)]
pub enum XactBatchCodecEncodeError<Header, Req, Committed, Notify> {
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
    /// Error occurred writing the notification.
    Notify {
        /// The error that occurred writing the notification.
        err: Notify
    }
}

/// Errors that can occur decoding in an [XactBatchCodec].
#[derive(Debug)]
pub enum XactBatchCodecDecodeError<Header, Req, Committed, Notify> {
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

impl<H, Seal> XactConsensusSeal<H, Seal> {
    #[inline]
    pub fn new(
        hashes: Vec<H>,
        seals: Vec<Seal>
    ) -> Self {
        XactConsensusSeal {
            hashes: hashes,
            seals: seals
        }
    }

    #[inline]
    pub fn nhashes(&self) -> usize {
        self.hashes.len()
    }

    #[inline]
    pub fn hashes(&self) -> &[H] {
        &self.hashes
    }

    #[inline]
    pub fn seal(&self) -> &[Seal] {
        &self.seals
    }

    #[inline]
    pub fn take(self) -> (Vec<H>, Vec<Seal>) {
        (self.hashes, self.seals)
    }
}

impl<RoundID, H, Seal, Payload, Effects>
    XactCommittedRound<RoundID, H, Seal, Payload, Effects>
{
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
    ) -> (
        RoundID,
        Option<XactConsensusSeal<H, Seal>>,
        Vec<XactCommittedReq<Payload, Effects>>
    ) {
        (self.round, self.seal, self.reqs)
    }
}

impl<Payload, Effects> XactCommittedReq<Payload, Effects> {
    #[inline]
    pub fn new(
        class: Uuid,
        version: Version,
        instance: u64,
        idx: usize,
        payload: Payload,
        effects: Option<XactCommittedEffects<Effects>>
    ) -> Self {
        XactCommittedReq {
            class: class,
            version: version,
            instance: instance,
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
    pub fn instance(&self) -> u64 {
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
    pub fn take(
        self
    ) -> (
        Uuid,
        Version,
        u64,
        usize,
        Option<XactCommittedEffects<Effects>>,
        Payload
    ) {
        (
            self.class,
            self.version,
            self.instance,
            self.idx,
            self.effects,
            self.payload
        )
    }
}

impl<RoundID, Payload, Effects> XactUncommittedReq<RoundID, Payload, Effects>
where
    RoundID: Clone + From<u128> + Into<u128>
{
    #[inline]
    pub fn new(
        class: Uuid,
        version: Version,
        instance: u64,
        payload: Payload,
        effects: XactEffects<RoundID, Effects>
    ) -> Self {
        XactUncommittedReq {
            class: class,
            version: version,
            instance: instance,
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
    pub fn instance(&self) -> u64 {
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
    pub fn take(
        self
    ) -> (Uuid, Version, u64, XactEffects<RoundID, Effects>, Payload) {
        (
            self.class,
            self.version,
            self.instance,
            self.effects,
            self.payload
        )
    }
}

impl<RoundID, H, Payload, Effects>
    XactUncommittedHashReq<RoundID, H, Payload, Effects>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: HashID
{
    #[inline]
    pub fn new(
        hash: H,
        class: Uuid,
        version: Version,
        instance: u64,
        payload: Payload,
        effects: XactEffects<RoundID, Effects>
    ) -> Self {
        XactUncommittedHashReq {
            hash: hash,
            class: class,
            version: version,
            instance: instance,
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
    pub fn instance(&self) -> u64 {
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
    pub fn take(
        self
    ) -> (
        Uuid,
        Version,
        u64,
        H,
        XactEffects<RoundID, Effects>,
        Payload
    ) {
        (
            self.class,
            self.version,
            self.instance,
            self.hash,
            self.effects,
            self.payload
        )
    }
}

impl<Seal, Inner> XactSealed<Seal, Inner> {
    #[inline]
    pub fn new(
        seal: Seal,
        inner: Inner
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

impl<RoundID, H, Res, Err> XactNotify<RoundID, H, Res, Err>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: HashID
{
    #[inline]
    pub fn new(
        hash: H,
        state: XactNotifyState<RoundID, Res, Err>
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
    pub fn state(&self) -> &XactNotifyState<RoundID, Res, Err> {
        &self.state
    }

    #[inline]
    pub fn take(self) -> (H, XactNotifyState<RoundID, Res, Err>) {
        (self.hash, self.state)
    }
}

impl<RoundID, H, Seal, Payload, Effects, Res, Err>
    XactBatch<RoundID, H, Seal, Payload, Effects, Res, Err>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: HashID
{
    #[inline]
    pub fn new(
        committed: Vec<XactCommittedRound<RoundID, H, Seal, Payload, Effects>>,
        reqs: Vec<
            XactSealed<Seal, XactUncommittedReq<RoundID, Payload, Effects>>
        >,
        notifies: Vec<XactNotify<RoundID, H, Res, Err>>
    ) -> Self {
        XactBatch {
            committed: committed,
            reqs: reqs,
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
    ) -> &[XactSealed<Seal, XactUncommittedReq<RoundID, Payload, Effects>>]
    {
        &self.reqs
    }

    #[inline]
    pub fn notifies(&self) -> &[XactNotify<RoundID, H, Res, Err>] {
        &self.notifies
    }

    #[inline]
    pub fn take(
        self
    ) -> (
        Vec<XactCommittedRound<RoundID, H, Seal, Payload, Effects>>,
        Vec<XactSealed<Seal, XactUncommittedReq<RoundID, Payload, Effects>>>,
        Vec<XactNotify<RoundID, H, Res, Err>>
    ) {
        (self.committed, self.reqs, self.notifies)
    }
}

impl<RoundID, H, Seal, Payload, Effects, Res, Err>
    XactHashBatch<RoundID, H, Seal, Payload, Effects, Res, Err>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: HashID
{
    #[inline]
    pub fn new(
        committed: Vec<XactCommittedRound<RoundID, H, Seal, Payload, Effects>>,
        reqs: Vec<
            XactSealed<
                Seal,
                XactUncommittedHashReq<RoundID, H, Payload, Effects>
            >
        >,
        notifies: Vec<XactNotify<RoundID, H, Res, Err>>
    ) -> Self {
        XactHashBatch {
            committed: committed,
            reqs: reqs,
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
    ) -> &[XactSealed<
        Seal,
        XactUncommittedHashReq<RoundID, H, Payload, Effects>
    >] {
        &self.reqs
    }

    #[inline]
    pub fn notifies(&self) -> &[XactNotify<RoundID, H, Res, Err>] {
        &self.notifies
    }

    #[inline]
    pub fn take(
        self
    ) -> (
        Vec<XactCommittedRound<RoundID, H, Seal, Payload, Effects>>,
        Vec<
            XactSealed<
                Seal,
                XactUncommittedHashReq<RoundID, H, Payload, Effects>
            >
        >,
        Vec<XactNotify<RoundID, H, Res, Err>>
    ) {
        (self.committed, self.reqs, self.notifies)
    }
}

impl<RoundID> TryFrom<&'_ crate::generated::xact::XactLinPoint>
    for XactLinPoint<RoundID>
where
    RoundID: Clone + From<u128> + Into<u128>
{
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
where
    RoundID: Clone + From<u128> + Into<u128>
{
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
where
    RoundID: Clone + From<u128> + Into<u128>
{
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
where
    RoundID: Clone + From<u128> + Into<u128>
{
    #[inline]
    fn from(val: XactLinPoint<RoundID>) -> Self {
        Self::from(&val)
    }
}

impl<RoundID> XactLinPoint<RoundID>
where
    RoundID: Clone + From<u128> + Into<u128>
{
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
    for XactUncommittedReqCodec<
        RoundID,
        Payload,
        Effect,
        PayloadCodec,
        EffectCodec
    >
where
    RoundID: Clone + From<u128> + Into<u128>,
    PayloadCodec: Codec<Payload>,
    EffectCodec: Codec<Effect>
{
    type CreateError = XactReqCodecCreateError<
        PayloadCodec::CreateError,
        EffectCodec::CreateError
    >;
    type DecodeError =
        XactReqCodecDecodeError<
            PayloadCodec::DecodeError,
            EffectCodec::DecodeError,
            <XactUncommittedReqHeaderPERCodec as Codec<
                XactUncommittedReqHeader
            >>::DecodeError
        >;
    type EncodeError =
        XactReqCodecEncodeError<
            PayloadCodec::EncodeError,
            EffectCodec::EncodeError,
            <XactUncommittedReqHeaderPERCodec as Codec<
                XactUncommittedReqHeader
            >>::EncodeError
        >;
    type Param = (PayloadCodec::Param, EffectCodec::Param);

    fn create(param: Self::Param) -> Result<Self, Self::CreateError> {
        let (payload, effect) = param;
        let payload_codec = PayloadCodec::create(payload)
            .map_err(|err| XactReqCodecCreateError::Payload { err: err })?;
        let effect_codec = EffectCodec::create(effect)
            .map_err(|err| XactReqCodecCreateError::Effect { err: err })?;

        Ok(XactUncommittedReqCodec {
            payload: PhantomData,
            effect: PhantomData,
            round: PhantomData,
            req_codec: XactUncommittedReqHeaderPERCodec::default(),
            payload_codec: payload_codec,
            effect_codec: effect_codec
        })
    }

    fn buf_size(
        &self,
        val: &XactUncommittedReq<RoundID, Payload, Effect>
    ) -> usize {
        let payload = self.payload_codec.buf_size(&val.payload) + 9;
        let effects = match &val.effects {
            XactEffects::Effects { effects, .. } => {
                self.effect_codec.buf_size(effects) + 11
            }
            XactEffects::HardNone { when: Some(_) } => 18,
            XactEffects::HardNone { when: None } => 2,
            XactEffects::SoftNone => 1
        };
        let class = 16;
        let instance = 9;
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
            .map_err(|err| XactReqCodecEncodeError::Payload { err: err })?;
        let payload_len = payload.len();
        let mut curr = 0;

        // Write the header and any effects, then store the header.
        match &req.effects {
            XactEffects::Effects { hard, effects } => {
                let effects =
                    self.effect_codec.encode_to_vec(effects).map_err(
                        |err| XactReqCodecEncodeError::Effects { err: err }
                    )?;
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
                    .map_err(|err| XactReqCodecEncodeError::Req { err: err })?;

                if curr + effects_len < buf.len() {
                    buf[curr..curr + effects_len].copy_from_slice(&effects[..]);

                    curr += effects_len;
                } else {
                    return Err(XactReqCodecEncodeError::TooShort);
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
                    .map_err(|err| XactReqCodecEncodeError::Req { err: err })?;
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
                    .map_err(|err| XactReqCodecEncodeError::Req { err: err })?;
            }
        };

        if curr + payload_len < buf.len() {
            buf[curr..curr + payload_len].copy_from_slice(&payload[..]);

            curr += payload_len;
        } else {
            return Err(XactReqCodecEncodeError::TooShort);
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<
        (XactUncommittedReq<RoundID, Payload, Effect>, usize),
        Self::DecodeError
    > {
        let mut curr = 0;
        let (req, nbytes) = self
            .req_codec
            .decode(&buf[curr..])
            .map_err(|err| XactReqCodecDecodeError::Req { err: err })?;

        curr += nbytes;

        let class = Uuid::from_slice(&req.class)
            .map_err(|err| XactReqCodecDecodeError::UUID { err: err })?;
        let effects = match req.effects {
            XactUncommittedEffectsHeader::Effects(XactEffectsHeader {
                hard,
                len
            }) => {
                let (effects, _) = self
                    .effect_codec
                    .decode(&buf[curr..curr + len as usize])
                    .map_err(|err| XactReqCodecDecodeError::Effects {
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
                    let round = when.round.try_into().expect("Impossible case");
                    let round = u128::from_le_bytes(round);

                    XactLinPoint {
                        round: round.into(),
                        idx: when.idx
                    }
                });

                Ok(XactEffects::HardNone { when: when })
            }
            XactUncommittedEffectsHeader::SoftNone(_) => {
                Ok(XactEffects::SoftNone)
            }
        }?;

        let (payload, _) = self
            .payload_codec
            .decode(&buf[curr..curr + req.len as usize])
            .map_err(|err| XactReqCodecDecodeError::Payload { err: err })?;

        curr += req.len as usize;

        Ok((
            XactUncommittedReq {
                instance: req.instance,
                version: req.version,
                effects: effects,
                payload: payload,
                class: class
            },
            curr
        ))
    }
}

impl<RoundID, H>
    Codec<XactUncommittedHashReq<RoundID, H::HashID, Vec<u8>, Vec<u8>>>
    for XactUncommittedReqBlobCodec<RoundID, H>
where
    H: HashAlgo + Default,
    H::HashID: Clone,
    RoundID: Clone + From<u128> + Into<u128>
{
    type CreateError = XactReqCodecCreateError<Infallible, Infallible>;
    type DecodeError =
        XactReqCodecDecodeError<
            Infallible,
            Infallible,
            <XactUncommittedReqHeaderPERCodec as Codec<
                XactUncommittedReqHeader
            >>::DecodeError
        >;
    type EncodeError =
        XactReqCodecEncodeError<
            Infallible,
            Infallible,
            <XactUncommittedReqHeaderPERCodec as Codec<
                XactUncommittedReqHeader
            >>::EncodeError
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
        val: &XactUncommittedHashReq<RoundID, H::HashID, Vec<u8>, Vec<u8>>
    ) -> usize {
        let payload = val.payload.len() + 9;
        let effects = match &val.effects {
            XactEffects::Effects { effects, .. } => effects.len() + 11,
            XactEffects::HardNone { when: Some(_) } => 18,
            XactEffects::HardNone { when: None } => 2,
            XactEffects::SoftNone => 1
        };
        let class = 16;
        let instance = 9;
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
                        hard: *hard
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
                    .map_err(|err| XactReqCodecEncodeError::Req { err: err })?;

                if curr + effects_len < buf.len() {
                    buf[curr..curr + effects_len].copy_from_slice(&effects[..]);

                    curr += effects_len;
                } else {
                    return Err(XactReqCodecEncodeError::TooShort);
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
                    .map_err(|err| XactReqCodecEncodeError::Req { err: err })?;
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
                    .map_err(|err| XactReqCodecEncodeError::Req { err: err })?;
            }
        };

        // Encode the actual payload.
        let payload_len = req.payload.len();

        if curr + payload_len < buf.len() {
            buf[curr..curr + payload_len].copy_from_slice(&req.payload[..]);

            curr += payload_len
        } else {
            return Err(XactReqCodecEncodeError::TooShort);
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<
        (
            XactUncommittedHashReq<RoundID, H::HashID, Vec<u8>, Vec<u8>>,
            usize
        ),
        Self::DecodeError
    > {
        let mut curr = 0;
        let (req, nbytes) = self
            .req_codec
            .decode(&buf[curr..])
            .map_err(|err| XactReqCodecDecodeError::Req { err: err })?;

        curr += nbytes;

        let class = Uuid::from_slice(&req.class)
            .map_err(|err| XactReqCodecDecodeError::UUID { err: err })?;
        let effects = match req.effects {
            XactUncommittedEffectsHeader::Effects(XactEffectsHeader {
                hard,
                len
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
                    let round = when.round.try_into().expect("Impossible case");
                    let round = u128::from_le_bytes(round);

                    XactLinPoint {
                        round: round.into(),
                        idx: when.idx
                    }
                });

                Ok(XactEffects::HardNone { when: when })
            }
            XactUncommittedEffectsHeader::SoftNone(_) => {
                Ok(XactEffects::SoftNone)
            }
        }?;
        let payload = if curr + req.len as usize <= buf.len() {
            let data = buf[curr..curr + req.len as usize].to_vec();

            curr += req.len as usize;

            Ok(data)
        } else {
            Err(XactReqCodecDecodeError::TooShort)
        }?;
        let hashid = self.hash.hash_bytes(once(&buf[..curr]));

        Ok((
            XactUncommittedHashReq {
                instance: req.instance,
                version: req.version,
                effects: effects,
                payload: payload,
                class: class,
                hash: hashid
            },
            curr
        ))
    }
}

impl<H, RoundID, Payload, Effect, PayloadCodec, EffectCodec>
    XactUncommittedReqHashCodec<
        RoundID,
        H,
        Payload,
        Effect,
        PayloadCodec,
        EffectCodec
    >
where
    H: HashAlgo + Default,
    H::HashID: Clone,
    PayloadCodec: Codec<Payload>,
    EffectCodec: Codec<Effect>,
    RoundID: Clone + From<u128> + Into<u128>
{
    // Generate a hash for an [XactUncommittedHashReq].
    pub fn hash(
        &mut self,
        req: &XactUncommittedHashReq<RoundID, H::HashID, Payload, Effect>
    ) -> Result<
        H::HashID,
        <Self as Codec<
            XactUncommittedHashReq<RoundID, H::HashID, Payload, Effect>
        >>::EncodeError
    > {
        match &req.effects {
            XactEffects::Effects { hard, effects } => self
                .hash_components_effects(
                    &req.class,
                    &req.version,
                    req.instance,
                    *hard,
                    effects,
                    &req.payload
                ),
            XactEffects::HardNone { when } => self
                .hash_components_hard_no_effects(
                    &req.class,
                    &req.version,
                    req.instance,
                    when,
                    &req.payload
                ),
            XactEffects::SoftNone => self.hash_components_soft_no_effects(
                &req.class,
                &req.version,
                req.instance,
                &req.payload
            )
        }
    }

    // Generate a hash for an [XactCommittedReq].
    pub fn hash_committed(
        &mut self,
        req: &XactCommittedReq<Payload, Effect>
    ) -> Result<
        H::HashID,
        <Self as Codec<
            XactUncommittedHashReq<RoundID, H::HashID, Payload, Effect>
        >>::EncodeError
    > {
        match &req.effects {
            Some(XactCommittedEffects { hard, effects }) => self
                .hash_components_effects(
                    &req.class,
                    &req.version,
                    req.instance,
                    *hard,
                    effects,
                    &req.payload
                ),
            None => self.hash_components_soft_no_effects(
                &req.class,
                &req.version,
                req.instance,
                &req.payload
            )
        }
    }

    fn hash_components_hard_no_effects(
        &mut self,
        class: &Uuid,
        version: &Version,
        instance: u64,
        when: &Option<XactLinPoint<RoundID>>,
        payload: &Payload
    ) -> Result<
        H::HashID,
        <Self as Codec<
            XactUncommittedHashReq<RoundID, H::HashID, Payload, Effect>
        >>::EncodeError
    > {
        let payload = self
            .payload_codec
            .encode_to_vec(payload)
            .map_err(|err| XactReqCodecEncodeError::Payload { err: err })?;
        let payload_len = payload.len();
        let effects_header =
            XactUncommittedEffectsHeader::HardNone(XactHardNone {
                when: when.as_ref().map(|when| when.into())
            });
        let header = XactUncommittedReqHeader {
            version: version.clone(),
            class: (*class).into(),
            effects: effects_header,
            instance: instance,
            len: payload_len as u64
        };
        let header = self
            .req_codec
            .encode_to_vec(&header)
            .map_err(|err| XactReqCodecEncodeError::Req { err: err })?;
        let hashid = self
            .hash
            .hash_bytes(vec![&header[..], &payload[..]].into_iter());

        Ok(hashid)
    }

    fn hash_components_soft_no_effects(
        &mut self,
        class: &Uuid,
        version: &Version,
        instance: u64,
        payload: &Payload
    ) -> Result<
        H::HashID,
        <Self as Codec<
            XactUncommittedHashReq<RoundID, H::HashID, Payload, Effect>
        >>::EncodeError
    > {
        let payload = self
            .payload_codec
            .encode_to_vec(payload)
            .map_err(|err| XactReqCodecEncodeError::Payload { err: err })?;
        let payload_len = payload.len();
        let effects =
            XactUncommittedEffectsHeader::SoftNone(Default::default());
        let header = XactUncommittedReqHeader {
            version: version.clone(),
            class: (*class).into(),
            effects: effects,
            instance: instance,
            len: payload_len as u64
        };
        let header = self
            .req_codec
            .encode_to_vec(&header)
            .map_err(|err| XactReqCodecEncodeError::Req { err: err })?;
        let hashid = self
            .hash
            .hash_bytes(vec![&header[..], &payload[..]].into_iter());

        Ok(hashid)
    }

    fn hash_components_effects(
        &mut self,
        class: &Uuid,
        version: &Version,
        instance: u64,
        hard: bool,
        effects: &Effect,
        payload: &Payload
    ) -> Result<
        H::HashID,
        <Self as Codec<
            XactUncommittedHashReq<RoundID, H::HashID, Payload, Effect>
        >>::EncodeError
    > {
        let payload = self
            .payload_codec
            .encode_to_vec(payload)
            .map_err(|err| XactReqCodecEncodeError::Payload { err: err })?;
        let payload_len = payload.len();
        let effects = self
            .effect_codec
            .encode_to_vec(effects)
            .map_err(|err| XactReqCodecEncodeError::Effects { err: err })?;
        let effects_len = effects.len();
        let effects_header =
            XactUncommittedEffectsHeader::Effects(XactEffectsHeader {
                len: effects_len as u64,
                hard: hard
            });
        let header = XactUncommittedReqHeader {
            version: version.clone(),
            class: (*class).into(),
            effects: effects_header,
            instance: instance,
            len: payload_len as u64
        };
        let header = self
            .req_codec
            .encode_to_vec(&header)
            .map_err(|err| XactReqCodecEncodeError::Req { err: err })?;
        let hashid = self.hash.hash_bytes(
            vec![&header[..], &effects[..], &payload[..]].into_iter()
        );

        Ok(hashid)
    }
}

impl<H, RoundID, Payload, Effect, PayloadCodec, EffectCodec>
    Codec<XactUncommittedHashReq<RoundID, H::HashID, Payload, Effect>>
    for XactUncommittedReqHashCodec<
        RoundID,
        H,
        Payload,
        Effect,
        PayloadCodec,
        EffectCodec
    >
where
    H: HashAlgo + Default,
    H::HashID: Clone,
    PayloadCodec: Codec<Payload>,
    EffectCodec: Codec<Effect>,
    RoundID: Clone + From<u128> + Into<u128>
{
    type CreateError = XactReqCodecCreateError<
        PayloadCodec::CreateError,
        EffectCodec::CreateError
    >;
    type DecodeError =
        XactReqCodecDecodeError<
            PayloadCodec::DecodeError,
            EffectCodec::DecodeError,
            <XactUncommittedReqHeaderPERCodec as Codec<
                XactUncommittedReqHeader
            >>::DecodeError
        >;
    type EncodeError =
        XactReqCodecEncodeError<
            PayloadCodec::EncodeError,
            EffectCodec::EncodeError,
            <XactUncommittedReqHeaderPERCodec as Codec<
                XactUncommittedReqHeader
            >>::EncodeError
        >;
    type Param = (PayloadCodec::Param, EffectCodec::Param);

    fn create(param: Self::Param) -> Result<Self, Self::CreateError> {
        let (payload, effect) = param;
        let payload_codec = PayloadCodec::create(payload)
            .map_err(|err| XactReqCodecCreateError::Payload { err: err })?;
        let effect_codec = EffectCodec::create(effect)
            .map_err(|err| XactReqCodecCreateError::Effect { err: err })?;
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
        val: &XactUncommittedHashReq<RoundID, H::HashID, Payload, Effect>
    ) -> usize {
        let payload = self.payload_codec.buf_size(&val.payload) + 9;
        let effects = match &val.effects {
            XactEffects::Effects { effects, .. } => {
                self.effect_codec.buf_size(effects) + 11
            }
            XactEffects::HardNone { when: Some(_) } => 18,
            XactEffects::HardNone { when: None } => 2,
            XactEffects::SoftNone => 1
        };
        let class = 16;
        let instance = 9;
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
            .map_err(|err| XactReqCodecEncodeError::Payload { err: err })?;
        let payload_len = payload.len();
        let mut curr = 0;

        // Write the header and any effects, then store the header.
        match &req.effects {
            XactEffects::Effects { hard, effects } => {
                let effects =
                    self.effect_codec.encode_to_vec(effects).map_err(
                        |err| XactReqCodecEncodeError::Effects { err: err }
                    )?;
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
                    .map_err(|err| XactReqCodecEncodeError::Req { err: err })?;

                let effects_len = effects.len();

                if curr + effects_len < buf.len() {
                    buf[curr..curr + effects_len].copy_from_slice(&effects[..]);

                    curr += effects_len;
                } else {
                    return Err(XactReqCodecEncodeError::TooShort);
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
                    .map_err(|err| XactReqCodecEncodeError::Req { err: err })?;
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
                    .map_err(|err| XactReqCodecEncodeError::Req { err: err })?;
            }
        };

        if curr + payload_len < buf.len() {
            buf[curr..curr + payload_len].copy_from_slice(&payload[..]);

            curr += payload_len;
        } else {
            return Err(XactReqCodecEncodeError::TooShort);
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<
        (
            XactUncommittedHashReq<RoundID, H::HashID, Payload, Effect>,
            usize
        ),
        Self::DecodeError
    > {
        let mut curr = 0;
        let (req, nbytes) = self
            .req_codec
            .decode(&buf[curr..])
            .map_err(|err| XactReqCodecDecodeError::Req { err: err })?;

        curr += nbytes;

        let class = Uuid::from_slice(&req.class)
            .map_err(|err| XactReqCodecDecodeError::UUID { err: err })?;
        let effects = match req.effects {
            XactUncommittedEffectsHeader::Effects(XactEffectsHeader {
                hard,
                len
            }) => {
                let (effects, _) = self
                    .effect_codec
                    .decode(&buf[curr..curr + len as usize])
                    .map_err(|err| XactReqCodecDecodeError::Effects {
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
                    let round = when.round.try_into().expect("Impossible case");
                    let round = u128::from_le_bytes(round);

                    XactLinPoint {
                        round: round.into(),
                        idx: when.idx
                    }
                });

                Ok(XactEffects::HardNone { when: when })
            }
            XactUncommittedEffectsHeader::SoftNone(_) => {
                Ok(XactEffects::SoftNone)
            }
        }?;

        let (payload, _) = if (curr + req.len as usize) < buf.len() {
            self.payload_codec
                .decode(&buf[curr..curr + req.len as usize])
                .map_err(|err| XactReqCodecDecodeError::Payload { err: err })
        } else {
            Err(XactReqCodecDecodeError::TooShort)
        }?;

        curr += req.len as usize;

        let hashid = self.hash.hash_bytes(once(&buf[..curr]));

        Ok((
            XactUncommittedHashReq {
                instance: req.instance,
                version: req.version,
                effects: effects,
                payload: payload,
                class: class,
                hash: hashid
            },
            curr
        ))
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
        EffectCodec::CreateError
    >;
    type DecodeError =
        XactReqCodecDecodeError<
            PayloadCodec::DecodeError,
            EffectCodec::DecodeError,
            <XactUncommittedReqHeaderPERCodec as Codec<
                XactUncommittedReqHeader
            >>::DecodeError
        >;
    type EncodeError =
        XactReqCodecEncodeError<
            PayloadCodec::EncodeError,
            EffectCodec::EncodeError,
            <XactUncommittedReqHeaderPERCodec as Codec<
                XactUncommittedReqHeader
            >>::EncodeError
        >;
    type Param = (PayloadCodec::Param, EffectCodec::Param);

    fn create(param: Self::Param) -> Result<Self, Self::CreateError> {
        let (payload, effect) = param;
        let payload_codec = PayloadCodec::create(payload)
            .map_err(|err| XactReqCodecCreateError::Payload { err: err })?;
        let effect_codec = EffectCodec::create(effect)
            .map_err(|err| XactReqCodecCreateError::Effect { err: err })?;

        Ok(XactCommittedReqCodec {
            payload: PhantomData,
            effect: PhantomData,
            req_codec: XactCommittedReqHeaderPERCodec::default(),
            payload_codec: payload_codec,
            effect_codec: effect_codec
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
        let instance = 9;
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
            .map_err(|err| XactReqCodecEncodeError::Payload { err: err })?;
        let payload_len = payload.len();
        let mut curr = 0;

        // Write the header and any effects, then store the header.
        match &req.effects {
            Some(XactCommittedEffects { hard, effects }) => {
                let effects =
                    self.effect_codec.encode_to_vec(effects).map_err(
                        |err| XactReqCodecEncodeError::Effects { err: err }
                    )?;
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
                    .map_err(|err| XactReqCodecEncodeError::Req { err: err })?;

                if curr + effects_len < buf.len() {
                    buf[curr..curr + effects_len].copy_from_slice(&effects[..]);

                    curr += effects_len;
                } else {
                    return Err(XactReqCodecEncodeError::TooShort);
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
                    .map_err(|err| XactReqCodecEncodeError::Req { err: err })?;
            }
        };

        if curr + payload_len < buf.len() {
            buf[curr..curr + payload_len].copy_from_slice(&payload[..]);

            curr += payload_len;
        } else {
            return Err(XactReqCodecEncodeError::TooShort);
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
            .map_err(|err| XactReqCodecDecodeError::Req { err: err })?;

        curr += nbytes;

        let class = Uuid::from_slice(&req.class)
            .map_err(|err| XactReqCodecDecodeError::UUID { err: err })?;
        let effects = match req.effects {
            Some(XactEffectsHeader { hard, len }) => {
                let (effects, _) = self
                    .effect_codec
                    .decode(&buf[curr..curr + len as usize])
                    .map_err(|err| XactReqCodecDecodeError::Effects {
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
            .map_err(|err| XactReqCodecDecodeError::Payload { err: err })?;

        curr += req.len as usize;

        Ok((
            XactCommittedReq {
                instance: req.instance,
                version: req.version,
                effects: effects,
                payload: payload,
                idx: req.idx as usize,
                class: class
            },
            curr
        ))
    }
}

impl Codec<XactCommittedReq<Vec<u8>, Vec<u8>>> for XactCommittedReqBlobCodec {
    type CreateError = XactReqCodecCreateError<Infallible, Infallible>;
    type DecodeError =
        XactReqCodecDecodeError<
            Infallible,
            Infallible,
            <XactUncommittedReqHeaderPERCodec as Codec<
                XactUncommittedReqHeader
            >>::DecodeError
        >;
    type EncodeError =
        XactReqCodecEncodeError<
            Infallible,
            Infallible,
            <XactUncommittedReqHeaderPERCodec as Codec<
                XactUncommittedReqHeader
            >>::EncodeError
        >;
    type Param = ();

    fn create(_param: Self::Param) -> Result<Self, Self::CreateError> {
        Ok(XactCommittedReqBlobCodec {
            req_codec: XactCommittedReqHeaderPERCodec::default()
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
        let instance = 9;
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
                    .map_err(|err| XactReqCodecEncodeError::Req { err: err })?;

                if curr + effects_len < buf.len() {
                    buf[curr..curr + effects_len].copy_from_slice(&effects[..]);

                    curr += effects_len;
                } else {
                    return Err(XactReqCodecEncodeError::TooShort);
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
                    .map_err(|err| XactReqCodecEncodeError::Req { err: err })?;
            }
        };

        if curr + payload_len < buf.len() {
            buf[curr..curr + payload_len].copy_from_slice(&req.payload[..]);
        } else {
            return Err(XactReqCodecEncodeError::TooShort);
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
            .map_err(|err| XactReqCodecDecodeError::Req { err: err })?;

        curr += nbytes;

        let class = Uuid::from_slice(&req.class)
            .map_err(|err| XactReqCodecDecodeError::UUID { err: err })?;
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

        Ok((
            XactCommittedReq {
                instance: req.instance,
                version: req.version,
                effects: effects,
                payload: payload,
                idx: req.idx as usize,
                class: class
            },
            curr
        ))
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
        InnerCodec::CreateError
    >;
    type DecodeError = XactSealedCodecError<
        <XactSealHeaderPERCodec as Codec<XactSealHeader>>::DecodeError,
        SealCodec::DecodeError,
        InnerCodec::DecodeError
    >;
    type EncodeError = XactSealedCodecError<
        <XactSealHeaderPERCodec as Codec<XactSealHeader>>::EncodeError,
        SealCodec::EncodeError,
        InnerCodec::EncodeError
    >;
    type Param = (SealCodec::Param, InnerCodec::Param);

    fn create(param: Self::Param) -> Result<Self, Self::CreateError> {
        let (seal, inner) = param;
        let seal_codec = SealCodec::create(seal)
            .map_err(|err| XactSealedCodecCreateError::Seal { err: err })?;
        let inner_codec = InnerCodec::create(inner)
            .map_err(|err| XactSealedCodecCreateError::Inner { err: err })?;

        Ok(XactSealedCodec {
            seal: PhantomData,
            inner: PhantomData,
            header_codec: XactSealHeaderPERCodec::default(),
            seal_codec: seal_codec,
            inner_codec: inner_codec
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
            .map_err(|err| XactSealedCodecError::Inner { err: err })?;

        let seal = self
            .seal_codec
            .encode_to_vec(&val.seal)
            .map_err(|err| XactSealedCodecError::Seal { err: err })?;
        let seal_len = seal.len();
        let header = XactSealHeader {
            len: seal_len as u64
        };

        curr += self
            .header_codec
            .encode(&header, &mut buf[curr..])
            .map_err(|err| XactSealedCodecError::Header { err: err })?;

        if curr + seal_len < buf.len() {
            buf[curr..curr + seal_len].copy_from_slice(&seal[..]);

            curr += seal_len;
        } else {
            return Err(XactSealedCodecError::TooShort);
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(XactSealed<Seal, Inner>, usize), Self::DecodeError> {
        let mut curr = 0;
        let (inner, nbytes) = self
            .inner_codec
            .decode(&buf[curr..])
            .map_err(|err| XactSealedCodecError::Inner { err: err })?;

        curr += nbytes;

        let (header, nbytes) = self
            .header_codec
            .decode(&buf[curr..])
            .map_err(|err| XactSealedCodecError::Header { err: err })?;

        curr += nbytes;

        let (seal, nbytes) = self
            .seal_codec
            .decode(&buf[curr..curr + header.len as usize])
            .map_err(|err| XactSealedCodecError::Seal { err: err })?;

        curr += nbytes;

        Ok((
            XactSealed {
                inner: inner,
                seal: seal
            },
            curr
        ))
    }
}

impl<Inner, InnerCodec> Codec<XactSealed<Vec<u8>, Inner>>
    for XactSealedBlobCodec<Inner, InnerCodec>
where
    InnerCodec: Codec<Inner>
{
    type CreateError =
        XactSealedCodecCreateError<Infallible, InnerCodec::CreateError>;
    type DecodeError = XactSealedCodecError<
        <XactSealHeaderPERCodec as Codec<XactSealHeader>>::DecodeError,
        Infallible,
        InnerCodec::DecodeError
    >;
    type EncodeError = XactSealedCodecError<
        <XactSealHeaderPERCodec as Codec<XactSealHeader>>::EncodeError,
        Infallible,
        InnerCodec::EncodeError
    >;
    type Param = InnerCodec::Param;

    fn create(param: Self::Param) -> Result<Self, Self::CreateError> {
        let inner_codec = InnerCodec::create(param)
            .map_err(|err| XactSealedCodecCreateError::Inner { err: err })?;

        Ok(XactSealedBlobCodec {
            inner: PhantomData,
            header_codec: XactSealHeaderPERCodec::default(),
            inner_codec: inner_codec
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
            .map_err(|err| XactSealedCodecError::Inner { err: err })?;

        let seal_len = val.seal.len();
        let header = XactSealHeader {
            len: seal_len as u64
        };

        curr += self
            .header_codec
            .encode(&header, &mut buf[curr..])
            .map_err(|err| XactSealedCodecError::Header { err: err })?;

        if curr + seal_len < buf.len() {
            buf[curr..curr + seal_len].copy_from_slice(&val.seal[..]);

            curr += seal_len;
        } else {
            return Err(XactSealedCodecError::TooShort);
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(XactSealed<Vec<u8>, Inner>, usize), Self::DecodeError> {
        let mut curr = 0;
        let (inner, nbytes) = self
            .inner_codec
            .decode(&buf[curr..])
            .map_err(|err| XactSealedCodecError::Inner { err: err })?;

        curr += nbytes;

        let (header, nbytes) = self
            .header_codec
            .decode(&buf[curr..])
            .map_err(|err| XactSealedCodecError::Header { err: err })?;

        curr += nbytes;

        let seal = if curr + header.len as usize <= buf.len() {
            let data = buf[curr..curr + header.len as usize].to_vec();

            curr += header.len as usize;

            Ok(data)
        } else {
            Err(XactSealedCodecError::TooShort)
        }?;

        Ok((
            XactSealed {
                inner: inner,
                seal: seal
            },
            curr
        ))
    }
}

impl<
        RoundID,
        H,
        Seal,
        Payload,
        Effect,
        SealCodec,
        PayloadCodec,
        EffectCodec
    > Codec<XactCommittedRound<RoundID, H::HashID, Seal, Payload, Effect>>
    for XactCommittedRoundCodec<
        RoundID,
        H,
        Seal,
        Payload,
        Effect,
        SealCodec,
        PayloadCodec,
        EffectCodec
    >
where
    H: Default + HashAlgo,
    H::HashID: Clone,
    RoundID: Clone + From<u128> + Into<u128>,
    PayloadCodec: Codec<Payload>,
    EffectCodec: Codec<Effect>,
    SealCodec: Codec<Seal>
{
    type CreateError = XactCommittedRoundCodecCreateError<
        SealCodec::CreateError,
        XactReqCodecCreateError<
            PayloadCodec::CreateError,
            EffectCodec::CreateError
        >
    >;
    type DecodeError =
        XactCommittedRoundCodecDecodeError<
            <XactCommittedRoundHeaderPERCodec as Codec<
                XactCommittedRoundHeader
            >>::DecodeError,
            SealCodec::DecodeError,
            XactReqCodecDecodeError<
                PayloadCodec::DecodeError,
                EffectCodec::DecodeError,
                <XactCommittedReqHeaderPERCodec as Codec<
                    XactCommittedReqHeader
                >>::DecodeError
            >
        >;
    type EncodeError =
        XactCommittedRoundCodecEncodeError<
            <XactCommittedRoundHeaderPERCodec as Codec<
                XactCommittedRoundHeader
            >>::EncodeError,
            SealCodec::EncodeError,
            XactReqCodecEncodeError<
                PayloadCodec::EncodeError,
                EffectCodec::EncodeError,
                <XactCommittedReqHeaderPERCodec as Codec<
                    XactCommittedReqHeader
                >>::EncodeError
            >
        >;
    type Param = (SealCodec::Param, PayloadCodec::Param, EffectCodec::Param);

    fn create(param: Self::Param) -> Result<Self, Self::CreateError> {
        let (seal, payload, effect) = param;
        let seal_codec = SealCodec::create(seal).map_err(|err| {
            XactCommittedRoundCodecCreateError::Seal { err: err }
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
            let hashes = seal
                .hashes
                .iter()
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
                let seal =
                    self.seal_codec.encode_to_vec(seal).map_err(|err| {
                        XactCommittedRoundCodecEncodeError::Seal { err: err }
                    })?;
                let seal_len = seal.len();
                let header = XactSealHeader {
                    len: seal_len as u64
                };

                curr += self
                    .seal_header_codec
                    .encode(&header, &mut buf[curr..])
                    .map_err(|err| {
                        XactCommittedRoundCodecEncodeError::Header { err: err }
                    })?;

                if curr + seal_len < buf.len() {
                    buf[curr..curr + seal_len].copy_from_slice(&seal[..]);

                    curr += seal_len;
                } else {
                    return Err(XactCommittedRoundCodecEncodeError::TooShort);
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
            curr += self.req_codec.encode(req, &mut buf[curr..]).map_err(
                |err| XactCommittedRoundCodecEncodeError::Req { err: err }
            )?;
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<
        (
            XactCommittedRound<RoundID, H::HashID, Seal, Payload, Effect>,
            usize
        ),
        Self::DecodeError
    > {
        let mut curr = 0;
        let (header, nbytes) =
            self.header_codec.decode(&buf[curr..]).map_err(|err| {
                XactCommittedRoundCodecDecodeError::Header { err: err }
            })?;
        let round = header.round.clone().try_into().map_err(|err| {
            XactCommittedRoundCodecDecodeError::Round { err: err }
        })?;
        let round = u128::from_le_bytes(round);
        let round = round.into();

        curr += nbytes;

        let seal = match &header.seal {
            Some(seal) => {
                let mut hashes = Vec::with_capacity(seal.hashes.len());

                for hash in seal.hashes.iter() {
                    let hash =
                        self.hash.wrap_hashed_bytes(hash).map_err(|err| {
                            XactCommittedRoundCodecDecodeError::Hash {
                                err: err
                            }
                        })?;

                    hashes.push(hash);
                }

                let mut seals = Vec::with_capacity(seal.nseals as usize);

                for _ in 0..seal.nseals {
                    let (header, nbytes) =
                        self.seal_header_codec.decode(&buf[curr..]).map_err(
                            |err| XactCommittedRoundCodecDecodeError::Header {
                                err: err
                            }
                        )?;

                    curr += nbytes;

                    let (seal, nbytes) = self
                        .seal_codec
                        .decode(&buf[curr..curr + header.len as usize])
                        .map_err(|err| {
                            XactCommittedRoundCodecDecodeError::Seal {
                                err: err
                            }
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
            let (req, nbytes) =
                self.req_codec.decode(&buf[curr..]).map_err(|err| {
                    XactCommittedRoundCodecDecodeError::Req { err: err }
                })?;

            curr += nbytes;
            reqs.push(req);
        }

        Ok((
            XactCommittedRound {
                round: round,
                seal: seal,
                reqs: reqs
            },
            curr
        ))
    }
}

impl<RoundID, H, Seal, SealCodec>
    Codec<XactCommittedRound<RoundID, H::HashID, Seal, Vec<u8>, Vec<u8>>>
    for XactCommittedRoundBlobCodec<RoundID, H, Seal, SealCodec>
where
    H: Default + HashAlgo,
    H::HashID: Clone,
    RoundID: Clone + From<u128> + Into<u128>,
    SealCodec: Codec<Seal>
{
    type CreateError = XactCommittedRoundCodecCreateError<
        SealCodec::CreateError,
        XactReqCodecCreateError<Infallible, Infallible>
    >;
    type DecodeError =
        XactCommittedRoundCodecDecodeError<
            <XactCommittedRoundHeaderPERCodec as Codec<
                XactCommittedRoundHeader
            >>::DecodeError,
            SealCodec::DecodeError,
            XactReqCodecDecodeError<
                Infallible,
                Infallible,
                <XactCommittedReqHeaderPERCodec as Codec<
                    XactCommittedReqHeader
                >>::DecodeError
            >
        >;
    type EncodeError =
        XactCommittedRoundCodecEncodeError<
            <XactCommittedRoundHeaderPERCodec as Codec<
                XactCommittedRoundHeader
            >>::EncodeError,
            SealCodec::EncodeError,
            XactReqCodecEncodeError<
                Infallible,
                Infallible,
                <XactCommittedReqHeaderPERCodec as Codec<
                    XactCommittedReqHeader
                >>::EncodeError
            >
        >;
    type Param = SealCodec::Param;

    fn create(param: Self::Param) -> Result<Self, Self::CreateError> {
        let seal_codec = SealCodec::create(param).map_err(|err| {
            XactCommittedRoundCodecCreateError::Seal { err: err }
        })?;
        let req_codec =
            XactCommittedReqBlobCodec::create(()).map_err(|err| {
                XactCommittedRoundCodecCreateError::Req { err: err }
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
            let hashes = seal
                .hashes
                .iter()
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
                let seal =
                    self.seal_codec.encode_to_vec(seal).map_err(|err| {
                        XactCommittedRoundCodecEncodeError::Seal { err: err }
                    })?;
                let seal_len = seal.len();
                let header = XactSealHeader {
                    len: seal_len as u64
                };

                curr += self
                    .seal_header_codec
                    .encode(&header, &mut buf[curr..])
                    .map_err(|err| {
                        XactCommittedRoundCodecEncodeError::Header { err: err }
                    })?;

                if curr + seal_len < buf.len() {
                    buf[curr..curr + seal_len].copy_from_slice(&seal[..]);

                    curr += seal_len;
                } else {
                    return Err(XactCommittedRoundCodecEncodeError::TooShort);
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
            curr += self.req_codec.encode(req, &mut buf[curr..]).map_err(
                |err| XactCommittedRoundCodecEncodeError::Req { err: err }
            )?;
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<
        (
            XactCommittedRound<RoundID, H::HashID, Seal, Vec<u8>, Vec<u8>>,
            usize
        ),
        Self::DecodeError
    > {
        let mut curr = 0;
        let (header, nbytes) =
            self.header_codec.decode(&buf[curr..]).map_err(|err| {
                XactCommittedRoundCodecDecodeError::Header { err: err }
            })?;
        let round = header.round.clone().try_into().map_err(|err| {
            XactCommittedRoundCodecDecodeError::Round { err: err }
        })?;
        let round = u128::from_le_bytes(round);
        let round = round.into();

        curr += nbytes;

        let seal = match &header.seal {
            Some(seal) => {
                let mut hashes = Vec::with_capacity(seal.hashes.len());

                for hash in seal.hashes.iter() {
                    let hash =
                        self.hash.wrap_hashed_bytes(hash).map_err(|err| {
                            XactCommittedRoundCodecDecodeError::Hash {
                                err: err
                            }
                        })?;

                    hashes.push(hash);
                }

                let mut seals = Vec::with_capacity(seal.nseals as usize);

                for _ in 0..seal.nseals {
                    let (header, nbytes) =
                        self.seal_header_codec.decode(&buf[curr..]).map_err(
                            |err| XactCommittedRoundCodecDecodeError::Header {
                                err: err
                            }
                        )?;

                    curr += nbytes;

                    let (seal, nbytes) = self
                        .seal_codec
                        .decode(&buf[curr..curr + header.len as usize])
                        .map_err(|err| {
                            XactCommittedRoundCodecDecodeError::Seal {
                                err: err
                            }
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
            let (req, nbytes) =
                self.req_codec.decode(&buf[curr..]).map_err(|err| {
                    XactCommittedRoundCodecDecodeError::Req { err: err }
                })?;

            curr += nbytes;
            reqs.push(req);
        }

        Ok((
            XactCommittedRound {
                round: round,
                seal: seal,
                reqs: reqs
            },
            curr
        ))
    }
}

impl<RoundID, H, Res, Err, ResCodec, ErrCodec>
    Codec<XactNotify<RoundID, H::HashID, Res, Err>>
    for XactNotifyCodec<RoundID, H, Res, Err, ResCodec, ErrCodec>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: Default + HashAlgo,
    H::HashID: Clone,
    ResCodec: Codec<Res>,
    ErrCodec: Codec<Err>
{
    type CreateError = XactNotifyCodecCreateError<
        ResCodec::CreateError,
        ErrCodec::CreateError
    >;
    type DecodeError = XactNotifyCodecDecodeError<
        <XactNotifyHeaderPERCodec as Codec<XactNotifyHeader>>::DecodeError,
        ResCodec::DecodeError,
        ErrCodec::DecodeError
    >;
    type EncodeError = XactNotifyCodecEncodeError<
        <XactNotifyHeaderPERCodec as Codec<XactNotifyHeader>>::EncodeError,
        ResCodec::EncodeError,
        ErrCodec::EncodeError
    >;
    type Param = (ResCodec::Param, ErrCodec::Param);

    fn create(param: Self::Param) -> Result<Self, Self::CreateError> {
        let (res, err) = param;
        let res_codec = ResCodec::create(res)
            .map_err(|err| XactNotifyCodecCreateError::Res { err: err })?;
        let err_codec = ErrCodec::create(err)
            .map_err(|err| XactNotifyCodecCreateError::Err { err: err })?;
        let hash = H::default();

        Ok(XactNotifyCodec {
            round: PhantomData,
            res: PhantomData,
            err: PhantomData,
            header_codec: XactNotifyHeaderPERCodec::default(),
            res_codec: res_codec,
            err_codec: err_codec,
            hash: hash
        })
    }

    #[inline]
    fn buf_size(
        &self,
        val: &XactNotify<RoundID, H::HashID, Res, Err>
    ) -> usize {
        let hash = 64;
        let state = match &val.state {
            XactNotifyState::Accept => 1,
            XactNotifyState::PrecommitDispatch { when: Some(_) } => {
                let header = 2;
                let linpoint = 17;

                header + linpoint
            }
            XactNotifyState::PrecommitDispatch { when: None } => 2,
            XactNotifyState::Consensus => 1,
            XactNotifyState::Commit { .. } => {
                let header = 1;
                let linpoint = 17;

                header + linpoint
            }
            XactNotifyState::Dispatch { .. } => {
                let header = 1;
                let linpoint = 17;

                header + linpoint
            }
            XactNotifyState::Success {
                result: Some(res), ..
            } => {
                let header = 2;
                let len = 9;
                let linpoint = 17;

                self.res_codec.buf_size(res) + header + len + linpoint
            }
            XactNotifyState::Success { result: None, .. } => {
                let header = 2;
                let linpoint = 17;

                header + linpoint
            }
            XactNotifyState::Error {
                error: Some(XactError::Error { err })
            } => {
                let header = 2;
                let len = 9;

                self.err_codec.buf_size(err) + header + len
            }
            XactNotifyState::Error {
                error: Some(XactError::UnknownClass)
            } |
            XactNotifyState::Error {
                error: Some(XactError::UnknownVersion)
            } |
            XactNotifyState::Error {
                error: Some(XactError::UnknownInstance)
            } |
            XactNotifyState::Error {
                error: Some(XactError::InvalidPayload)
            } |
            XactNotifyState::Error {
                error: Some(XactError::InvalidEffect)
            } |
            XactNotifyState::Error {
                error: Some(XactError::EffectViolation)
            } |
            XactNotifyState::Error {
                error: Some(XactError::Unauthorized)
            } |
            XactNotifyState::Error {
                error: Some(XactError::Uncommitted)
            } |
            XactNotifyState::Error {
                error: Some(XactError::HashMismatch)
            } |
            XactNotifyState::Error {
                error: Some(XactError::Internal)
            } => 3,
            XactNotifyState::Error { error: None } => 2
        };

        hash + state
    }

    fn encode(
        &mut self,
        val: &XactNotify<RoundID, H::HashID, Res, Err>,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let (state, data) =
            match &val.state {
                XactNotifyState::Accept => {
                    (XactNotifyStateHeader::Accept(Default::default()), None)
                }
                XactNotifyState::PrecommitDispatch { when } => {
                    let state = XactPrecommitState {
                        when: when.as_ref().map(|when| when.into())
                    };

                    (XactNotifyStateHeader::PrecommitDispatch(state), None)
                }
                XactNotifyState::Consensus => {
                    (XactNotifyStateHeader::Consensus(Default::default()), None)
                }
                XactNotifyState::Commit { when } => {
                    let state = crate::generated::xact::XactCommitState {
                        when: when.into()
                    };

                    (XactNotifyStateHeader::Commit(state), None)
                }
                XactNotifyState::Dispatch { when } => {
                    let state = crate::generated::xact::XactCommitState {
                        when: when.into()
                    };

                    (XactNotifyStateHeader::Dispatch(state), None)
                }
                XactNotifyState::Success {
                    result: Some(result),
                    when
                } => {
                    let res = self.res_codec.encode_to_vec(result).map_err(
                        |err| XactNotifyCodecEncodeError::Res { err: err }
                    )?;
                    let state = XactResultHeader {
                        when: when.into(),
                        len: res.len() as u64
                    };

                    (XactNotifyStateHeader::Success(state), Some(res))
                }
                XactNotifyState::Success { result: None, when } => {
                    let state = crate::generated::xact::XactCommitState {
                        when: when.into()
                    };

                    (XactNotifyStateHeader::Finished(state), None)
                }
                XactNotifyState::Error { error: Some(error) } => match error {
                    XactError::Error { err } => {
                        let err = self.err_codec.encode_to_vec(err).map_err(
                            |err| XactNotifyCodecEncodeError::Err { err: err }
                        )?;

                        (
                            XactNotifyStateHeader::Error(
                                XactErrorHeader::Error(XactValueHeader {
                                    len: err.len() as u64
                                })
                            ),
                            Some(err)
                        )
                    }
                    XactError::UnknownClass => (
                        XactNotifyStateHeader::Error(
                            XactErrorHeader::UnknownClass(Default::default())
                        ),
                        None
                    ),
                    XactError::UnknownVersion => (
                        XactNotifyStateHeader::Error(
                            XactErrorHeader::UnknownVersion(Default::default())
                        ),
                        None
                    ),
                    XactError::UnknownInstance => (
                        XactNotifyStateHeader::Error(
                            XactErrorHeader::UnknownInstance(Default::default())
                        ),
                        None
                    ),
                    XactError::InvalidPayload => (
                        XactNotifyStateHeader::Error(
                            XactErrorHeader::InvalidPayload(Default::default())
                        ),
                        None
                    ),
                    XactError::InvalidEffect => (
                        XactNotifyStateHeader::Error(
                            XactErrorHeader::InvalidEffect(Default::default())
                        ),
                        None
                    ),
                    XactError::EffectViolation => (
                        XactNotifyStateHeader::Error(
                            XactErrorHeader::EffectViolation(Default::default())
                        ),
                        None
                    ),
                    XactError::Unauthorized => (
                        XactNotifyStateHeader::Error(
                            XactErrorHeader::Unauthorized(Default::default())
                        ),
                        None
                    ),
                    XactError::Uncommitted => (
                        XactNotifyStateHeader::Error(
                            XactErrorHeader::Uncommitted(Default::default())
                        ),
                        None
                    ),
                    XactError::HashMismatch => (
                        XactNotifyStateHeader::Error(
                            XactErrorHeader::HashMismatch(Default::default())
                        ),
                        None
                    ),
                    XactError::Internal => (
                        XactNotifyStateHeader::Error(
                            XactErrorHeader::Internal(Default::default())
                        ),
                        None
                    )
                },
                XactNotifyState::Error { error: None } => {
                    (XactNotifyStateHeader::Fail(Default::default()), None)
                }
            };
        let header = XactNotifyHeader {
            hash: val.hash.bytes().to_vec(),
            state: state
        };
        let mut curr = 0;

        curr += self
            .header_codec
            .encode(&header, &mut buf[curr..])
            .map_err(|err| XactNotifyCodecEncodeError::Header { err: err })?;

        if let Some(data) = data {
            let err_len = data.len();

            if curr + err_len < buf.len() {
                buf[curr..curr + err_len].copy_from_slice(&data[..]);

                curr += err_len;
            } else {
                return Err(XactNotifyCodecEncodeError::TooShort);
            }
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<
        (XactNotify<RoundID, H::HashID, Res, Err>, usize),
        Self::DecodeError
    > {
        let mut curr = 0;
        let (header, nbytes) = self
            .header_codec
            .decode(&buf[curr..])
            .map_err(|err| XactNotifyCodecDecodeError::Header { err: err })?;
        let hash = self
            .hash
            .wrap_hashed_bytes(&header.hash)
            .map_err(|err| XactNotifyCodecDecodeError::Hash { err: err })?;

        curr += nbytes;

        let state = match &header.state {
            XactNotifyStateHeader::Accept(_) => XactNotifyState::Accept,
            XactNotifyStateHeader::PrecommitDispatch(state) => {
                match &state.when {
                    Some(when) => {
                        let when = when.try_into().map_err(|err| {
                            XactNotifyCodecDecodeError::Round { err: err }
                        })?;

                        XactNotifyState::PrecommitDispatch { when: Some(when) }
                    }
                    None => XactNotifyState::PrecommitDispatch { when: None }
                }
            }
            XactNotifyStateHeader::Consensus(_) => XactNotifyState::Consensus,
            XactNotifyStateHeader::Commit(state) => {
                let when = (&state.when).try_into().map_err(|err| {
                    XactNotifyCodecDecodeError::Round { err: err }
                })?;

                XactNotifyState::Commit { when: when }
            }
            XactNotifyStateHeader::Dispatch(state) => {
                let when = (&state.when).try_into().map_err(|err| {
                    XactNotifyCodecDecodeError::Round { err: err }
                })?;

                XactNotifyState::Dispatch { when: when }
            }
            XactNotifyStateHeader::Success(state) => {
                let len = state.len as usize;
                let (res, _) =
                    self.res_codec.decode(&buf[curr..curr + len]).map_err(
                        |err| XactNotifyCodecDecodeError::Res { err: err }
                    )?;

                curr += len;
                let when = (&state.when).try_into().map_err(|err| {
                    XactNotifyCodecDecodeError::Round { err: err }
                })?;

                XactNotifyState::Success {
                    when: when,
                    result: Some(res)
                }
            }
            XactNotifyStateHeader::Finished(state) => {
                let when = (&state.when).try_into().map_err(|err| {
                    XactNotifyCodecDecodeError::Round { err: err }
                })?;

                XactNotifyState::Success {
                    when: when,
                    result: None
                }
            }
            XactNotifyStateHeader::Error(err) => match err {
                XactErrorHeader::Error(val) => {
                    let len = val.len as usize;
                    let (err, _) =
                        self.err_codec.decode(&buf[curr..curr + len]).map_err(
                            |err| XactNotifyCodecDecodeError::Err { err: err }
                        )?;

                    curr += len;

                    XactNotifyState::Error {
                        error: Some(XactError::Error { err: err })
                    }
                }
                XactErrorHeader::UnknownClass(_) => XactNotifyState::Error {
                    error: Some(XactError::UnknownClass)
                },
                XactErrorHeader::UnknownVersion(_) => XactNotifyState::Error {
                    error: Some(XactError::UnknownVersion)
                },
                XactErrorHeader::UnknownInstance(_) => XactNotifyState::Error {
                    error: Some(XactError::UnknownInstance)
                },
                XactErrorHeader::InvalidPayload(_) => XactNotifyState::Error {
                    error: Some(XactError::InvalidPayload)
                },
                XactErrorHeader::InvalidEffect(_) => XactNotifyState::Error {
                    error: Some(XactError::InvalidEffect)
                },
                XactErrorHeader::EffectViolation(_) => XactNotifyState::Error {
                    error: Some(XactError::EffectViolation)
                },
                XactErrorHeader::Unauthorized(_) => XactNotifyState::Error {
                    error: Some(XactError::Unauthorized)
                },
                XactErrorHeader::Uncommitted(_) => XactNotifyState::Error {
                    error: Some(XactError::Uncommitted)
                },
                XactErrorHeader::HashMismatch(_) => XactNotifyState::Error {
                    error: Some(XactError::HashMismatch)
                },
                XactErrorHeader::Internal(_) => XactNotifyState::Error {
                    error: Some(XactError::Internal)
                }
            },
            XactNotifyStateHeader::Fail(_) => {
                XactNotifyState::Error { error: None }
            }
        };
        let notify = XactNotify {
            state: state,
            hash: hash
        };

        Ok((notify, curr))
    }
}

impl<RoundID, H> Codec<XactNotify<RoundID, H::HashID, Vec<u8>, Vec<u8>>>
    for XactNotifyBlobCodec<RoundID, H>
where
    RoundID: Clone + From<u128> + Into<u128>,
    H: Clone + Default + HashAlgo,
    H::HashID: Clone
{
    type CreateError = XactNotifyCodecCreateError<Infallible, Infallible>;
    type DecodeError = XactNotifyCodecDecodeError<
        <XactNotifyHeaderPERCodec as Codec<XactNotifyHeader>>::DecodeError,
        Infallible,
        Infallible
    >;
    type EncodeError = XactNotifyCodecEncodeError<
        <XactNotifyHeaderPERCodec as Codec<XactNotifyHeader>>::EncodeError,
        Infallible,
        Infallible
    >;
    type Param = ();

    fn create(_param: Self::Param) -> Result<Self, Self::CreateError> {
        let hash = H::default();

        Ok(XactNotifyBlobCodec {
            round: PhantomData,
            header_codec: XactNotifyHeaderPERCodec::default(),
            hash: hash
        })
    }

    #[inline]
    fn buf_size(
        &self,
        val: &XactNotify<RoundID, H::HashID, Vec<u8>, Vec<u8>>
    ) -> usize {
        let hash = 64;
        let state = match &val.state {
            XactNotifyState::Accept => 1,
            XactNotifyState::PrecommitDispatch { when: Some(_) } => {
                let header = 2;
                let linpoint = 17;

                header + linpoint
            }
            XactNotifyState::PrecommitDispatch { when: None } => 2,
            XactNotifyState::Consensus => 1,
            XactNotifyState::Commit { .. } => {
                let header = 1;
                let linpoint = 17;

                header + linpoint
            }
            XactNotifyState::Dispatch { .. } => {
                let header = 1;
                let linpoint = 17;

                header + linpoint
            }
            XactNotifyState::Success {
                result: Some(res), ..
            } => {
                let header = 2;
                let len = 9;
                let linpoint = 17;

                res.len() + header + len + linpoint
            }
            XactNotifyState::Success { result: None, .. } => {
                let header = 2;
                let linpoint = 17;

                header + linpoint
            }
            XactNotifyState::Error {
                error: Some(XactError::Error { err })
            } => {
                let header = 2;
                let len = 9;

                err.len() + header + len
            }
            XactNotifyState::Error {
                error: Some(XactError::UnknownClass)
            } |
            XactNotifyState::Error {
                error: Some(XactError::UnknownVersion)
            } |
            XactNotifyState::Error {
                error: Some(XactError::UnknownInstance)
            } |
            XactNotifyState::Error {
                error: Some(XactError::InvalidPayload)
            } |
            XactNotifyState::Error {
                error: Some(XactError::InvalidEffect)
            } |
            XactNotifyState::Error {
                error: Some(XactError::EffectViolation)
            } |
            XactNotifyState::Error {
                error: Some(XactError::Unauthorized)
            } |
            XactNotifyState::Error {
                error: Some(XactError::Uncommitted)
            } |
            XactNotifyState::Error {
                error: Some(XactError::HashMismatch)
            } |
            XactNotifyState::Error {
                error: Some(XactError::Internal)
            } => 3,
            XactNotifyState::Error { error: None } => 2
        };

        hash + state
    }

    fn encode(
        &mut self,
        val: &XactNotify<RoundID, H::HashID, Vec<u8>, Vec<u8>>,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let (state, data) = match &val.state {
            XactNotifyState::Accept => {
                (XactNotifyStateHeader::Accept(Default::default()), None)
            }
            XactNotifyState::PrecommitDispatch { when } => {
                let state = XactPrecommitState {
                    when: when.as_ref().map(|when| when.into())
                };

                (XactNotifyStateHeader::PrecommitDispatch(state), None)
            }
            XactNotifyState::Consensus => {
                (XactNotifyStateHeader::Consensus(Default::default()), None)
            }
            XactNotifyState::Commit { when } => {
                let state = crate::generated::xact::XactCommitState {
                    when: when.into()
                };

                (XactNotifyStateHeader::Commit(state), None)
            }
            XactNotifyState::Dispatch { when } => {
                let state = crate::generated::xact::XactCommitState {
                    when: when.into()
                };

                (XactNotifyStateHeader::Dispatch(state), None)
            }
            XactNotifyState::Success {
                result: Some(result),
                when
            } => {
                let state = XactResultHeader {
                    when: when.into(),
                    len: result.len() as u64
                };

                (XactNotifyStateHeader::Success(state), Some(result))
            }
            XactNotifyState::Success { result: None, when } => {
                let state = crate::generated::xact::XactCommitState {
                    when: when.into()
                };

                (XactNotifyStateHeader::Finished(state), None)
            }
            XactNotifyState::Error { error: Some(error) } => match error {
                XactError::Error { err } => (
                    XactNotifyStateHeader::Error(XactErrorHeader::Error(
                        XactValueHeader {
                            len: err.len() as u64
                        }
                    )),
                    Some(err)
                ),
                XactError::UnknownClass => (
                    XactNotifyStateHeader::Error(
                        XactErrorHeader::UnknownClass(Default::default())
                    ),
                    None
                ),
                XactError::UnknownVersion => (
                    XactNotifyStateHeader::Error(
                        XactErrorHeader::UnknownVersion(Default::default())
                    ),
                    None
                ),
                XactError::UnknownInstance => (
                    XactNotifyStateHeader::Error(
                        XactErrorHeader::UnknownInstance(Default::default())
                    ),
                    None
                ),
                XactError::InvalidPayload => (
                    XactNotifyStateHeader::Error(
                        XactErrorHeader::InvalidPayload(Default::default())
                    ),
                    None
                ),
                XactError::InvalidEffect => (
                    XactNotifyStateHeader::Error(
                        XactErrorHeader::InvalidEffect(Default::default())
                    ),
                    None
                ),
                XactError::EffectViolation => (
                    XactNotifyStateHeader::Error(
                        XactErrorHeader::EffectViolation(Default::default())
                    ),
                    None
                ),
                XactError::Unauthorized => (
                    XactNotifyStateHeader::Error(
                        XactErrorHeader::Unauthorized(Default::default())
                    ),
                    None
                ),
                XactError::Uncommitted => (
                    XactNotifyStateHeader::Error(XactErrorHeader::Uncommitted(
                        Default::default()
                    )),
                    None
                ),
                XactError::HashMismatch => (
                    XactNotifyStateHeader::Error(
                        XactErrorHeader::HashMismatch(Default::default())
                    ),
                    None
                ),
                XactError::Internal => (
                    XactNotifyStateHeader::Error(XactErrorHeader::Internal(
                        Default::default()
                    )),
                    None
                )
            },
            XactNotifyState::Error { error: None } => {
                (XactNotifyStateHeader::Fail(Default::default()), None)
            }
        };
        let header = XactNotifyHeader {
            hash: val.hash.bytes().to_vec(),
            state: state
        };
        let mut curr = 0;

        curr += self
            .header_codec
            .encode(&header, &mut buf[curr..])
            .map_err(|err| XactNotifyCodecEncodeError::Header { err: err })?;

        if let Some(data) = data {
            let err_len = data.len();

            if curr + err_len < buf.len() {
                buf[curr..curr + err_len].copy_from_slice(&data[..]);

                curr += err_len;
            } else {
                return Err(XactNotifyCodecEncodeError::TooShort);
            }
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<
        (XactNotify<RoundID, H::HashID, Vec<u8>, Vec<u8>>, usize),
        Self::DecodeError
    > {
        let mut curr = 0;
        let (header, nbytes) = self
            .header_codec
            .decode(&buf[curr..])
            .map_err(|err| XactNotifyCodecDecodeError::Header { err: err })?;
        let hash = self
            .hash
            .wrap_hashed_bytes(&header.hash)
            .map_err(|err| XactNotifyCodecDecodeError::Hash { err: err })?;

        curr += nbytes;

        let state = match &header.state {
            XactNotifyStateHeader::Accept(_) => XactNotifyState::Accept,
            XactNotifyStateHeader::PrecommitDispatch(state) => {
                match &state.when {
                    Some(when) => {
                        let when = when.try_into().map_err(|err| {
                            XactNotifyCodecDecodeError::Round { err: err }
                        })?;

                        XactNotifyState::PrecommitDispatch { when: Some(when) }
                    }
                    None => XactNotifyState::PrecommitDispatch { when: None }
                }
            }
            XactNotifyStateHeader::Consensus(_) => XactNotifyState::Consensus,
            XactNotifyStateHeader::Commit(state) => {
                let when = (&state.when).try_into().map_err(|err| {
                    XactNotifyCodecDecodeError::Round { err: err }
                })?;

                XactNotifyState::Commit { when: when }
            }
            XactNotifyStateHeader::Dispatch(state) => {
                let when = (&state.when).try_into().map_err(|err| {
                    XactNotifyCodecDecodeError::Round { err: err }
                })?;

                XactNotifyState::Dispatch { when: when }
            }
            XactNotifyStateHeader::Success(state) => {
                let len = state.len as usize;
                let res = if curr + len < buf.len() {
                    buf[curr..curr + len].to_vec()
                } else {
                    return Err(XactNotifyCodecDecodeError::TooShort);
                };

                curr += len;
                let when = (&state.when).try_into().map_err(|err| {
                    XactNotifyCodecDecodeError::Round { err: err }
                })?;

                XactNotifyState::Success {
                    when: when,
                    result: Some(res)
                }
            }
            XactNotifyStateHeader::Finished(state) => {
                let when = (&state.when).try_into().map_err(|err| {
                    XactNotifyCodecDecodeError::Round { err: err }
                })?;

                XactNotifyState::Success {
                    when: when,
                    result: None
                }
            }
            XactNotifyStateHeader::Error(err) => match err {
                XactErrorHeader::Error(val) => {
                    let len = val.len as usize;
                    let err = if curr + len < buf.len() {
                        buf[curr..curr + len].to_vec()
                    } else {
                        return Err(XactNotifyCodecDecodeError::TooShort);
                    };

                    curr += len;

                    XactNotifyState::Error {
                        error: Some(XactError::Error { err: err })
                    }
                }
                XactErrorHeader::UnknownClass(_) => XactNotifyState::Error {
                    error: Some(XactError::UnknownClass)
                },
                XactErrorHeader::UnknownVersion(_) => XactNotifyState::Error {
                    error: Some(XactError::UnknownVersion)
                },
                XactErrorHeader::UnknownInstance(_) => XactNotifyState::Error {
                    error: Some(XactError::UnknownInstance)
                },
                XactErrorHeader::InvalidPayload(_) => XactNotifyState::Error {
                    error: Some(XactError::InvalidPayload)
                },
                XactErrorHeader::InvalidEffect(_) => XactNotifyState::Error {
                    error: Some(XactError::InvalidEffect)
                },
                XactErrorHeader::EffectViolation(_) => XactNotifyState::Error {
                    error: Some(XactError::EffectViolation)
                },
                XactErrorHeader::Unauthorized(_) => XactNotifyState::Error {
                    error: Some(XactError::Unauthorized)
                },
                XactErrorHeader::Uncommitted(_) => XactNotifyState::Error {
                    error: Some(XactError::Uncommitted)
                },
                XactErrorHeader::HashMismatch(_) => XactNotifyState::Error {
                    error: Some(XactError::HashMismatch)
                },
                XactErrorHeader::Internal(_) => XactNotifyState::Error {
                    error: Some(XactError::Internal)
                }
            },
            XactNotifyStateHeader::Fail(_) => {
                XactNotifyState::Error { error: None }
            }
        };
        let notify = XactNotify {
            state: state,
            hash: hash
        };

        Ok((notify, curr))
    }
}

impl<
        RoundID,
        H,
        Seal,
        Payload,
        Effect,
        Res,
        Err,
        SealCodec,
        PayloadCodec,
        EffectCodec,
        ResCodec,
        ErrCodec
    > Codec<XactBatch<RoundID, H::HashID, Seal, Payload, Effect, Res, Err>>
    for XactBatchCodec<
        RoundID,
        H,
        Seal,
        Payload,
        Effect,
        Res,
        Err,
        SealCodec,
        PayloadCodec,
        EffectCodec,
        ResCodec,
        ErrCodec
    >
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
    ErrCodec::Param: Clone
{
    type CreateError = XactBatchCodecCreateError<
        XactSealedCodecCreateError<
            SealCodec::CreateError,
            XactReqCodecCreateError<
                PayloadCodec::CreateError,
                EffectCodec::CreateError
            >
        >,
        XactCommittedRoundCodecCreateError<
            SealCodec::CreateError,
            XactReqCodecCreateError<
                PayloadCodec::CreateError,
                EffectCodec::CreateError
            >
        >,
        XactNotifyCodecCreateError<
            ResCodec::CreateError,
            ErrCodec::CreateError
        >
    >;
    type DecodeError = XactBatchCodecDecodeError<
        <XactBatchHeaderPERCodec as Codec<XactBatchHeader>>::DecodeError,
        XactSealedCodecError<
            <XactSealHeaderPERCodec as Codec<XactSealHeader>>::DecodeError,
            SealCodec::DecodeError,
            XactReqCodecDecodeError<
                PayloadCodec::DecodeError,
                EffectCodec::DecodeError,
                <XactUncommittedReqHeaderPERCodec as Codec<
                    XactUncommittedReqHeader
                >>::DecodeError
            >
        >,
        XactCommittedRoundCodecDecodeError<
            <XactCommittedRoundHeaderPERCodec as Codec<
                XactCommittedRoundHeader
            >>::DecodeError,
            SealCodec::DecodeError,
            XactReqCodecDecodeError<
                PayloadCodec::DecodeError,
                EffectCodec::DecodeError,
                <XactCommittedReqHeaderPERCodec as Codec<
                    XactCommittedReqHeader
                >>::DecodeError
            >
        >,
        XactNotifyCodecDecodeError<
            <XactNotifyHeaderPERCodec as Codec<XactNotifyHeader>>::DecodeError,
            ResCodec::DecodeError,
            ErrCodec::DecodeError
        >
    >;
    type EncodeError = XactBatchCodecEncodeError<
        <XactBatchHeaderPERCodec as Codec<XactBatchHeader>>::EncodeError,
        XactSealedCodecError<
            <XactSealHeaderPERCodec as Codec<XactSealHeader>>::EncodeError,
            SealCodec::EncodeError,
            XactReqCodecEncodeError<
                PayloadCodec::EncodeError,
                EffectCodec::EncodeError,
                <XactUncommittedReqHeaderPERCodec as Codec<
                    XactUncommittedReqHeader
                >>::EncodeError
            >
        >,
        XactCommittedRoundCodecEncodeError<
            <XactCommittedRoundHeaderPERCodec as Codec<
                XactCommittedRoundHeader
            >>::EncodeError,
            SealCodec::EncodeError,
            XactReqCodecEncodeError<
                PayloadCodec::EncodeError,
                EffectCodec::EncodeError,
                <XactCommittedReqHeaderPERCodec as Codec<
                    XactCommittedReqHeader
                >>::EncodeError
            >
        >,
        XactNotifyCodecEncodeError<
            <XactNotifyHeaderPERCodec as Codec<XactNotifyHeader>>::EncodeError,
            ResCodec::EncodeError,
            ErrCodec::EncodeError
        >
    >;
    type Param = (
        SealCodec::Param,
        PayloadCodec::Param,
        EffectCodec::Param,
        ResCodec::Param,
        ErrCodec::Param
    );

    fn create(param: Self::Param) -> Result<Self, Self::CreateError> {
        let (seal, payload, effect, res, err) = param;
        let req_codec = XactSealedCodec::create((
            seal.clone(),
            (payload.clone(), effect.clone())
        ))
        .map_err(|err| XactBatchCodecCreateError::Req { err: err })?;
        let committed_codec = XactCommittedRoundCodec::create((
            seal.clone(),
            payload.clone(),
            effect.clone()
        ))
        .map_err(|err| XactBatchCodecCreateError::Committed { err: err })?;
        let notify_codec = XactNotifyCodec::create((res.clone(), err.clone()))
            .map_err(|err| XactBatchCodecCreateError::Notify { err: err })?;

        Ok(XactBatchCodec {
            header_codec: XactBatchHeaderPERCodec::default(),
            committed_codec: committed_codec,
            req_codec: req_codec,
            notify_codec: notify_codec
        })
    }

    #[inline]
    fn buf_size(
        &self,
        val: &XactBatch<RoundID, H::HashID, Seal, Payload, Effect, Res, Err>
    ) -> usize {
        let req: usize = val
            .reqs
            .iter()
            .map(|req| self.req_codec.buf_size(req))
            .sum();
        let committed: usize = val
            .committed
            .iter()
            .map(|committed| self.committed_codec.buf_size(committed))
            .sum();
        let notifies: usize = val
            .notifies
            .iter()
            .map(|res| self.notify_codec.buf_size(res))
            .sum();

        req + committed + notifies + 9
    }

    fn encode(
        &mut self,
        val: &XactBatch<RoundID, H::HashID, Seal, Payload, Effect, Res, Err>,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let header = XactBatchHeader {
            ncommitted: val.committed.len() as u32,
            nreqs: val.reqs.len() as u32,
            nnotifies: val.notifies.len() as u32
        };
        let mut curr = 0;

        curr += self
            .header_codec
            .encode(&header, &mut buf[curr..])
            .map_err(|err| XactBatchCodecEncodeError::Header { err: err })?;

        for committed in val.committed.iter() {
            curr += self
                .committed_codec
                .encode(committed, &mut buf[curr..])
                .map_err(|err| XactBatchCodecEncodeError::Committed {
                    err: err
                })?;
        }

        for req in val.reqs.iter() {
            curr += self
                .req_codec
                .encode(req, &mut buf[curr..])
                .map_err(|err| XactBatchCodecEncodeError::Req { err: err })?;
        }

        for result in val.notifies.iter() {
            curr +=
                self.notify_codec.encode(result, &mut buf[curr..]).map_err(
                    |err| XactBatchCodecEncodeError::Notify { err: err }
                )?;
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<
        (
            XactBatch<RoundID, H::HashID, Seal, Payload, Effect, Res, Err>,
            usize
        ),
        Self::DecodeError
    > {
        let mut curr = 0;
        let (header, nbytes) = self
            .header_codec
            .decode(&buf[curr..])
            .map_err(|err| XactBatchCodecDecodeError::Header { err: err })?;

        curr += nbytes;

        let mut committed = Vec::with_capacity(header.ncommitted as usize);

        for _ in 0..header.ncommitted {
            let (round, nbytes) =
                self.committed_codec.decode(&buf[curr..]).map_err(|err| {
                    XactBatchCodecDecodeError::Committed { err: err }
                })?;

            committed.push(round);
            curr += nbytes;
        }

        let mut reqs = Vec::with_capacity(header.nreqs as usize);

        for _ in 0..header.nreqs {
            let (req, nbytes) = self
                .req_codec
                .decode(&buf[curr..])
                .map_err(|err| XactBatchCodecDecodeError::Req { err: err })?;

            reqs.push(req);
            curr += nbytes;
        }

        let mut notifies = Vec::with_capacity(header.nnotifies as usize);

        for _ in 0..header.nnotifies {
            let (res, nbytes) =
                self.notify_codec.decode(&buf[curr..]).map_err(|err| {
                    XactBatchCodecDecodeError::Notify { err: err }
                })?;

            notifies.push(res);
            curr += nbytes;
        }

        Ok((
            XactBatch {
                committed: committed,
                reqs: reqs,
                notifies: notifies
            },
            curr
        ))
    }
}

impl<
        RoundID,
        H,
        Seal,
        Payload,
        Effect,
        Res,
        Err,
        SealCodec,
        PayloadCodec,
        EffectCodec,
        ResCodec,
        ErrCodec
    >
    XactBatchHashCodec<
        RoundID,
        H,
        Seal,
        Payload,
        Effect,
        Res,
        Err,
        SealCodec,
        PayloadCodec,
        EffectCodec,
        ResCodec,
        ErrCodec
    >
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
    ErrCodec::Param: Clone
{
    // Generate a hash for an [XactUncommittedHashReq].
    pub fn hash(
        &mut self,
        req: &XactUncommittedHashReq<RoundID, H::HashID, Payload, Effect>
    ) -> Result<
        H::HashID,
        <XactUncommittedReqHashCodec<
            RoundID,
            H,
            Payload,
            Effect,
            PayloadCodec,
            EffectCodec
        > as Codec<
            XactUncommittedHashReq<RoundID, H::HashID, Payload, Effect>
        >>::EncodeError
    > {
        self.req_codec.inner_codec.hash(req)
    }

    // Generate a hash for an [XactCommittedReq].
    pub fn hash_committed(
        &mut self,
        req: &XactCommittedReq<Payload, Effect>
    ) -> Result<
        H::HashID,
        <XactUncommittedReqHashCodec<
            RoundID,
            H,
            Payload,
            Effect,
            PayloadCodec,
            EffectCodec
        > as Codec<
            XactUncommittedHashReq<RoundID, H::HashID, Payload, Effect>
        >>::EncodeError
    > {
        self.req_codec.inner_codec.hash_committed(req)
    }
}

impl<
        RoundID,
        H,
        Seal,
        Payload,
        Effect,
        Res,
        Err,
        SealCodec,
        PayloadCodec,
        EffectCodec,
        ResCodec,
        ErrCodec
    > Codec<XactHashBatch<RoundID, H::HashID, Seal, Payload, Effect, Res, Err>>
    for XactBatchHashCodec<
        RoundID,
        H,
        Seal,
        Payload,
        Effect,
        Res,
        Err,
        SealCodec,
        PayloadCodec,
        EffectCodec,
        ResCodec,
        ErrCodec
    >
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
    ErrCodec::Param: Clone
{
    type CreateError = XactBatchCodecCreateError<
        XactSealedCodecCreateError<
            SealCodec::CreateError,
            XactReqCodecCreateError<
                PayloadCodec::CreateError,
                EffectCodec::CreateError
            >
        >,
        XactCommittedRoundCodecCreateError<
            SealCodec::CreateError,
            XactReqCodecCreateError<
                PayloadCodec::CreateError,
                EffectCodec::CreateError
            >
        >,
        XactNotifyCodecCreateError<
            ResCodec::CreateError,
            ErrCodec::CreateError
        >
    >;
    type DecodeError = XactBatchCodecDecodeError<
        <XactBatchHeaderPERCodec as Codec<XactBatchHeader>>::DecodeError,
        XactSealedCodecError<
            <XactSealHeaderPERCodec as Codec<XactSealHeader>>::DecodeError,
            SealCodec::DecodeError,
            XactReqCodecDecodeError<
                PayloadCodec::DecodeError,
                EffectCodec::DecodeError,
                <XactUncommittedReqHeaderPERCodec as Codec<
                    XactUncommittedReqHeader
                >>::DecodeError
            >
        >,
        XactCommittedRoundCodecDecodeError<
            <XactCommittedRoundHeaderPERCodec as Codec<
                XactCommittedRoundHeader
            >>::DecodeError,
            SealCodec::DecodeError,
            XactReqCodecDecodeError<
                PayloadCodec::DecodeError,
                EffectCodec::DecodeError,
                <XactCommittedReqHeaderPERCodec as Codec<
                    XactCommittedReqHeader
                >>::DecodeError
            >
        >,
        XactNotifyCodecDecodeError<
            <XactNotifyHeaderPERCodec as Codec<XactNotifyHeader>>::DecodeError,
            ResCodec::DecodeError,
            ErrCodec::DecodeError
        >
    >;
    type EncodeError = XactBatchCodecEncodeError<
        <XactBatchHeaderPERCodec as Codec<XactBatchHeader>>::EncodeError,
        XactSealedCodecError<
            <XactSealHeaderPERCodec as Codec<XactSealHeader>>::EncodeError,
            SealCodec::EncodeError,
            XactReqCodecEncodeError<
                PayloadCodec::EncodeError,
                EffectCodec::EncodeError,
                <XactUncommittedReqHeaderPERCodec as Codec<
                    XactUncommittedReqHeader
                >>::EncodeError
            >
        >,
        XactCommittedRoundCodecEncodeError<
            <XactCommittedRoundHeaderPERCodec as Codec<
                XactCommittedRoundHeader
            >>::EncodeError,
            SealCodec::EncodeError,
            XactReqCodecEncodeError<
                PayloadCodec::EncodeError,
                EffectCodec::EncodeError,
                <XactCommittedReqHeaderPERCodec as Codec<
                    XactCommittedReqHeader
                >>::EncodeError
            >
        >,
        XactNotifyCodecEncodeError<
            <XactNotifyHeaderPERCodec as Codec<XactNotifyHeader>>::EncodeError,
            ResCodec::EncodeError,
            ErrCodec::EncodeError
        >
    >;
    type Param = (
        SealCodec::Param,
        PayloadCodec::Param,
        EffectCodec::Param,
        ResCodec::Param,
        ErrCodec::Param
    );

    fn create(param: Self::Param) -> Result<Self, Self::CreateError> {
        let (seal, payload, effect, res, err) = param;
        let req_codec = XactSealedCodec::create((
            seal.clone(),
            (payload.clone(), effect.clone())
        ))
        .map_err(|err| XactBatchCodecCreateError::Req { err: err })?;
        let committed_codec = XactCommittedRoundCodec::create((
            seal.clone(),
            payload.clone(),
            effect.clone()
        ))
        .map_err(|err| XactBatchCodecCreateError::Committed { err: err })?;
        let res_codec = XactNotifyCodec::create((res.clone(), err.clone()))
            .map_err(|err| XactBatchCodecCreateError::Notify { err: err })?;

        Ok(XactBatchHashCodec {
            header_codec: XactBatchHeaderPERCodec::default(),
            committed_codec: committed_codec,
            req_codec: req_codec,
            notify_codec: res_codec
        })
    }

    #[inline]
    fn buf_size(
        &self,
        val: &XactHashBatch<
            RoundID,
            H::HashID,
            Seal,
            Payload,
            Effect,
            Res,
            Err
        >
    ) -> usize {
        let req: usize = val
            .reqs
            .iter()
            .map(|req| self.req_codec.buf_size(req))
            .sum();
        let committed: usize = val
            .committed
            .iter()
            .map(|committed| self.committed_codec.buf_size(committed))
            .sum();
        let notifies: usize = val
            .notifies
            .iter()
            .map(|res| self.notify_codec.buf_size(res))
            .sum();

        req + committed + notifies + 9
    }

    fn encode(
        &mut self,
        val: &XactHashBatch<
            RoundID,
            H::HashID,
            Seal,
            Payload,
            Effect,
            Res,
            Err
        >,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let header = XactBatchHeader {
            ncommitted: val.committed.len() as u32,
            nreqs: val.reqs.len() as u32,
            nnotifies: val.notifies.len() as u32
        };
        let mut curr = 0;

        curr += self
            .header_codec
            .encode(&header, &mut buf[curr..])
            .map_err(|err| XactBatchCodecEncodeError::Header { err: err })?;

        for committed in val.committed.iter() {
            curr += self
                .committed_codec
                .encode(committed, &mut buf[curr..])
                .map_err(|err| XactBatchCodecEncodeError::Committed {
                    err: err
                })?;
        }

        for req in val.reqs.iter() {
            curr += self
                .req_codec
                .encode(req, &mut buf[curr..])
                .map_err(|err| XactBatchCodecEncodeError::Req { err: err })?;
        }

        for notify in val.notifies.iter() {
            curr +=
                self.notify_codec.encode(notify, &mut buf[curr..]).map_err(
                    |err| XactBatchCodecEncodeError::Notify { err: err }
                )?;
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<
        (
            XactHashBatch<RoundID, H::HashID, Seal, Payload, Effect, Res, Err>,
            usize
        ),
        Self::DecodeError
    > {
        let mut curr = 0;
        let (header, nbytes) = self
            .header_codec
            .decode(&buf[curr..])
            .map_err(|err| XactBatchCodecDecodeError::Header { err: err })?;

        curr += nbytes;

        let mut committed = Vec::with_capacity(header.ncommitted as usize);

        for _ in 0..header.ncommitted {
            let (round, nbytes) =
                self.committed_codec.decode(&buf[curr..]).map_err(|err| {
                    XactBatchCodecDecodeError::Committed { err: err }
                })?;

            committed.push(round);
            curr += nbytes;
        }

        let mut reqs = Vec::with_capacity(header.nreqs as usize);

        for _ in 0..header.nreqs {
            let (req, nbytes) = self
                .req_codec
                .decode(&buf[curr..])
                .map_err(|err| XactBatchCodecDecodeError::Req { err: err })?;

            reqs.push(req);
            curr += nbytes;
        }

        let mut notifies = Vec::with_capacity(header.nnotifies as usize);

        for _ in 0..header.nnotifies {
            let (notify, nbytes) =
                self.notify_codec.decode(&buf[curr..]).map_err(|err| {
                    XactBatchCodecDecodeError::Notify { err: err }
                })?;

            notifies.push(notify);
            curr += nbytes;
        }

        Ok((
            XactHashBatch {
                committed: committed,
                reqs: reqs,
                notifies: notifies
            },
            curr
        ))
    }
}

impl<RoundID, H, Seal, SealCodec>
    Codec<
        XactHashBatch<
            RoundID,
            H::HashID,
            Seal,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>
        >
    > for XactBatchBlobCodec<RoundID, H, Seal, SealCodec>
where
    H: Clone + Default + HashAlgo,
    H::HashID: Clone,
    RoundID: Clone + From<u128> + Into<u128>,
    SealCodec: Codec<Seal>,
    SealCodec::Param: Clone
{
    type CreateError = XactBatchCodecCreateError<
        XactSealedCodecCreateError<
            SealCodec::CreateError,
            XactReqCodecCreateError<Infallible, Infallible>
        >,
        XactCommittedRoundCodecCreateError<
            SealCodec::CreateError,
            XactReqCodecCreateError<Infallible, Infallible>
        >,
        XactNotifyCodecCreateError<Infallible, Infallible>
    >;
    type DecodeError = XactBatchCodecDecodeError<
        <XactBatchHeaderPERCodec as Codec<XactBatchHeader>>::DecodeError,
        XactSealedCodecError<
            <XactSealHeaderPERCodec as Codec<XactSealHeader>>::DecodeError,
            SealCodec::DecodeError,
            XactReqCodecDecodeError<
                Infallible,
                Infallible,
                <XactUncommittedReqHeaderPERCodec as Codec<
                    XactUncommittedReqHeader
                >>::DecodeError
            >
        >,
        XactCommittedRoundCodecDecodeError<
            <XactCommittedRoundHeaderPERCodec as Codec<
                XactCommittedRoundHeader
            >>::DecodeError,
            SealCodec::DecodeError,
            XactReqCodecDecodeError<
                Infallible,
                Infallible,
                <XactCommittedReqHeaderPERCodec as Codec<
                    XactCommittedReqHeader
                >>::DecodeError
            >
        >,
        XactNotifyCodecDecodeError<
            <XactNotifyHeaderPERCodec as Codec<XactNotifyHeader>>::DecodeError,
            Infallible,
            Infallible
        >
    >;
    type EncodeError = XactBatchCodecEncodeError<
        <XactBatchHeaderPERCodec as Codec<XactBatchHeader>>::EncodeError,
        XactSealedCodecError<
            <XactSealHeaderPERCodec as Codec<XactSealHeader>>::EncodeError,
            SealCodec::EncodeError,
            XactReqCodecEncodeError<
                Infallible,
                Infallible,
                <XactUncommittedReqHeaderPERCodec as Codec<
                    XactUncommittedReqHeader
                >>::EncodeError
            >
        >,
        XactCommittedRoundCodecEncodeError<
            <XactCommittedRoundHeaderPERCodec as Codec<
                XactCommittedRoundHeader
            >>::EncodeError,
            SealCodec::EncodeError,
            XactReqCodecEncodeError<
                Infallible,
                Infallible,
                <XactCommittedReqHeaderPERCodec as Codec<
                    XactCommittedReqHeader
                >>::EncodeError
            >
        >,
        XactNotifyCodecEncodeError<
            <XactNotifyHeaderPERCodec as Codec<XactNotifyHeader>>::EncodeError,
            Infallible,
            Infallible
        >
    >;
    type Param = SealCodec::Param;

    fn create(param: Self::Param) -> Result<Self, Self::CreateError> {
        let req_codec = XactSealedCodec::create((param.clone(), ()))
            .map_err(|err| XactBatchCodecCreateError::Req { err: err })?;
        let committed_codec = XactCommittedRoundBlobCodec::create(
            param.clone()
        )
        .map_err(|err| XactBatchCodecCreateError::Committed { err: err })?;
        let notify_codec = XactNotifyBlobCodec::create(())
            .map_err(|err| XactBatchCodecCreateError::Notify { err: err })?;

        Ok(XactBatchBlobCodec {
            header_codec: XactBatchHeaderPERCodec::default(),
            committed_codec: committed_codec,
            req_codec: req_codec,
            notify_codec: notify_codec
        })
    }

    #[inline]
    fn buf_size(
        &self,
        val: &XactHashBatch<
            RoundID,
            H::HashID,
            Seal,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>
        >
    ) -> usize {
        let req: usize = val
            .reqs
            .iter()
            .map(|req| self.req_codec.buf_size(req))
            .sum();
        let committed: usize = val
            .committed
            .iter()
            .map(|committed| self.committed_codec.buf_size(committed))
            .sum();
        let notifies: usize = val
            .notifies
            .iter()
            .map(|res| self.notify_codec.buf_size(res))
            .sum();

        req + committed + notifies + 9
    }

    fn encode(
        &mut self,
        val: &XactHashBatch<
            RoundID,
            H::HashID,
            Seal,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>
        >,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let header = XactBatchHeader {
            ncommitted: val.committed.len() as u32,
            nreqs: val.reqs.len() as u32,
            nnotifies: val.notifies.len() as u32
        };
        let mut curr = 0;

        curr += self
            .header_codec
            .encode(&header, &mut buf[curr..])
            .map_err(|err| XactBatchCodecEncodeError::Header { err: err })?;

        for committed in val.committed.iter() {
            curr += self
                .committed_codec
                .encode(committed, &mut buf[curr..])
                .map_err(|err| XactBatchCodecEncodeError::Committed {
                    err: err
                })?;
        }

        for req in val.reqs.iter() {
            curr += self
                .req_codec
                .encode(req, &mut buf[curr..])
                .map_err(|err| XactBatchCodecEncodeError::Req { err: err })?;
        }

        for notify in val.notifies.iter() {
            curr +=
                self.notify_codec.encode(notify, &mut buf[curr..]).map_err(
                    |err| XactBatchCodecEncodeError::Notify { err: err }
                )?;
        }

        Ok(curr)
    }

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<
        (
            XactHashBatch<
                RoundID,
                H::HashID,
                Seal,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>
            >,
            usize
        ),
        Self::DecodeError
    > {
        let mut curr = 0;
        let (header, nbytes) = self
            .header_codec
            .decode(&buf[curr..])
            .map_err(|err| XactBatchCodecDecodeError::Header { err: err })?;

        curr += nbytes;

        let mut committed = Vec::with_capacity(header.ncommitted as usize);

        for _ in 0..header.ncommitted {
            let (round, nbytes) =
                self.committed_codec.decode(&buf[curr..]).map_err(|err| {
                    XactBatchCodecDecodeError::Committed { err: err }
                })?;

            committed.push(round);
            curr += nbytes;
        }

        let mut reqs = Vec::with_capacity(header.nreqs as usize);

        for _ in 0..header.nreqs {
            let (req, nbytes) = self
                .req_codec
                .decode(&buf[curr..])
                .map_err(|err| XactBatchCodecDecodeError::Req { err: err })?;

            reqs.push(req);
            curr += nbytes;
        }

        let mut notifies = Vec::with_capacity(header.nnotifies as usize);

        for _ in 0..header.nnotifies {
            let (res, nbytes) =
                self.notify_codec.decode(&buf[curr..]).map_err(|err| {
                    XactBatchCodecDecodeError::Notify { err: err }
                })?;

            notifies.push(res);
            curr += nbytes;
        }

        Ok((
            XactHashBatch {
                committed: committed,
                reqs: reqs,
                notifies: notifies
            },
            curr
        ))
    }
}

impl<RoundID, H, Res, Err> Display for XactNotify<RoundID, H, Res, Err>
where
    RoundID: Clone + Display + From<u128> + Into<u128>,
    H: Display + HashID,
    Res: Display,
    Err: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        write!(f, "{} {}", self.hash, self.state)
    }
}
impl<RoundID, Res, Err> Display for XactNotifyState<RoundID, Res, Err>
where
    RoundID: Clone + Display + From<u128> + Into<u128>,
    Res: Display,
    Err: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            XactNotifyState::Accept => write!(f, "accepted"),
            XactNotifyState::PrecommitDispatch { when: Some(when) } => {
                write!(f, "dispatched without commit ({})", when)
            }
            XactNotifyState::PrecommitDispatch { when: None } => {
                write!(f, "dispatched without commit")
            }
            XactNotifyState::Consensus => write!(f, "submitted to consensus"),
            XactNotifyState::Commit { when } => {
                write!(f, "committed ({})", when)
            }
            XactNotifyState::Dispatch { when } => {
                write!(f, "dispatched ({})", when)
            }
            XactNotifyState::Success {
                result: Some(result),
                when
            } => write!(f, "succeeded ({}), result: {}", when, result),
            XactNotifyState::Success { result: None, when } => {
                write!(f, "succeeded ({})", when)
            }
            XactNotifyState::Error { error: Some(error) } => {
                write!(f, "error: {}", error)
            }
            XactNotifyState::Error { error: None } => write!(f, "failed")
        }
    }
}

impl<Err> Display for XactError<Err>
where
    Err: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            XactError::Error { err } => err.fmt(f),
            XactError::UnknownClass => write!(f, "unknown transaction class"),
            XactError::UnknownVersion => {
                write!(f, "unsupported version of transaction class")
            }
            XactError::UnknownInstance => {
                write!(f, "unknown instance of transaction class")
            }
            XactError::InvalidPayload => {
                write!(f, "error parsing transaction request")
            }
            XactError::InvalidEffect => {
                write!(f, "error parsing effects constraint")
            }
            XactError::EffectViolation => {
                write!(f, "violated effects constraint")
            }
            XactError::Unauthorized => {
                write!(f, "transaction request was unauthorization")
            }
            XactError::Uncommitted => {
                write!(f, "transaction produced effects but was not committed")
            }
            XactError::HashMismatch => {
                write!(f, "transaction's hash does not match seal")
            }
            XactError::Internal => {
                write!(f, "internal error processing transaction request")
            }
        }
    }
}

impl<RoundID> Display for XactLinPoint<RoundID>
where
    RoundID: Clone + Display + From<u128> + Into<u128>
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        write!(f, "{}, idx {}", self.round, self.idx)
    }
}

impl<RoundID, Effects> Display for XactEffects<RoundID, Effects>
where
    RoundID: Clone + Display + From<u128> + Into<u128>,
    Effects: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            XactEffects::Effects {
                hard: true,
                effects
            } => write!(f, "hard {}", effects),
            XactEffects::Effects {
                hard: false,
                effects
            } => write!(f, "soft {}", effects),
            XactEffects::HardNone { when: Some(when) } => {
                write!(f, "hard none, when: {{ {} }}", when)
            }
            XactEffects::HardNone { when: None } => write!(f, "hard none"),
            XactEffects::SoftNone => write!(f, "soft none")
        }
    }
}

impl<Payload, Effect> ScopedError for XactReqCodecCreateError<Payload, Effect>
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
            XactReqCodecDecodeError::TooShort => ErrorScope::Unrecoverable
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
            XactReqCodecEncodeError::TooShort => ErrorScope::Unrecoverable
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

impl<Seal, Req> ScopedError for XactCommittedRoundCodecCreateError<Seal, Req>
where
    Seal: ScopedError,
    Req: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            XactCommittedRoundCodecCreateError::Seal { err } => err.scope(),
            XactCommittedRoundCodecCreateError::Req { err } => err.scope()
        }
    }
}

impl<Header, Seal, Req> ScopedError
    for XactCommittedRoundCodecEncodeError<Header, Seal, Req>
where
    Header: ScopedError,
    Seal: ScopedError,
    Req: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            XactCommittedRoundCodecEncodeError::Header { err } => err.scope(),
            XactCommittedRoundCodecEncodeError::Seal { err } => err.scope(),
            XactCommittedRoundCodecEncodeError::Req { err } => err.scope(),
            XactCommittedRoundCodecEncodeError::TooShort => {
                ErrorScope::Unrecoverable
            }
        }
    }
}

impl<Header, Seal, Req> ScopedError
    for XactCommittedRoundCodecDecodeError<Header, Seal, Req>
where
    Header: ScopedError,
    Seal: ScopedError,
    Req: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            XactCommittedRoundCodecDecodeError::Header { err } => err.scope(),
            XactCommittedRoundCodecDecodeError::Seal { err } => err.scope(),
            XactCommittedRoundCodecDecodeError::Req { err } => err.scope(),
            XactCommittedRoundCodecDecodeError::Round { .. } |
            XactCommittedRoundCodecDecodeError::Hash { .. } |
            XactCommittedRoundCodecDecodeError::TooShort => {
                ErrorScope::Unrecoverable
            }
        }
    }
}

impl<Res, Err> ScopedError for XactNotifyCodecCreateError<Res, Err>
where
    Res: ScopedError,
    Err: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            XactNotifyCodecCreateError::Res { err } => err.scope(),
            XactNotifyCodecCreateError::Err { err } => err.scope()
        }
    }
}

impl<Header, Res, Err> ScopedError
    for XactNotifyCodecEncodeError<Header, Res, Err>
where
    Header: ScopedError,
    Res: ScopedError,
    Err: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            XactNotifyCodecEncodeError::Header { err } => err.scope(),
            XactNotifyCodecEncodeError::Res { err } => err.scope(),
            XactNotifyCodecEncodeError::Err { err } => err.scope(),
            XactNotifyCodecEncodeError::TooShort => ErrorScope::Unrecoverable
        }
    }
}

impl<Header, Res, Err> ScopedError
    for XactNotifyCodecDecodeError<Header, Res, Err>
where
    Header: ScopedError,
    Res: ScopedError,
    Err: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            XactNotifyCodecDecodeError::Header { err } => err.scope(),
            XactNotifyCodecDecodeError::Res { err } => err.scope(),
            XactNotifyCodecDecodeError::Err { err } => err.scope(),
            XactNotifyCodecDecodeError::Round { .. } |
            XactNotifyCodecDecodeError::Hash { .. } |
            XactNotifyCodecDecodeError::TooShort => ErrorScope::Unrecoverable
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
            XactBatchCodecCreateError::Notify { err } => err.scope()
        }
    }
}

impl<Header, Req, Committed, Notify> ScopedError
    for XactBatchCodecEncodeError<Header, Req, Committed, Notify>
where
    Header: ScopedError,
    Req: ScopedError,
    Committed: ScopedError,
    Notify: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            XactBatchCodecEncodeError::Header { err } => err.scope(),
            XactBatchCodecEncodeError::Req { err } => err.scope(),
            XactBatchCodecEncodeError::Committed { err } => err.scope(),
            XactBatchCodecEncodeError::Notify { err } => err.scope()
        }
    }
}

impl<Header, Req, Committed, Notify> ScopedError
    for XactBatchCodecDecodeError<Header, Req, Committed, Notify>
where
    Header: ScopedError,
    Req: ScopedError,
    Committed: ScopedError,
    Notify: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            XactBatchCodecDecodeError::Header { err } => err.scope(),
            XactBatchCodecDecodeError::Req { err } => err.scope(),
            XactBatchCodecDecodeError::Committed { err } => err.scope(),
            XactBatchCodecDecodeError::Notify { err } => err.scope(),
            XactBatchCodecDecodeError::State { .. } |
            XactBatchCodecDecodeError::Hash { .. } => ErrorScope::Unrecoverable
        }
    }
}

impl<Payload, Effect> Display for XactReqCodecCreateError<Payload, Effect>
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
    Req: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            XactCommittedRoundCodecCreateError::Seal { err } => err.fmt(f),
            XactCommittedRoundCodecCreateError::Req { err } => err.fmt(f)
        }
    }
}

impl<Header, Seal, Req> Display
    for XactCommittedRoundCodecEncodeError<Header, Seal, Req>
where
    Header: Display,
    Seal: Display,
    Req: Display
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
    Req: Display
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
            XactCommittedRoundCodecDecodeError::Round { .. } => {
                write!(f, "error converting round from bytes")
            }
            XactCommittedRoundCodecDecodeError::TooShort => {
                write!(f, "input buffer is too short")
            }
        }
    }
}

impl<Res, Err> Display for XactNotifyCodecCreateError<Res, Err>
where
    Res: Display,
    Err: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            XactNotifyCodecCreateError::Res { err } => err.fmt(f),
            XactNotifyCodecCreateError::Err { err } => err.fmt(f)
        }
    }
}

impl<Header, Res, Err> Display for XactNotifyCodecEncodeError<Header, Res, Err>
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
            XactNotifyCodecEncodeError::Header { err } => err.fmt(f),
            XactNotifyCodecEncodeError::Res { err } => err.fmt(f),
            XactNotifyCodecEncodeError::Err { err } => err.fmt(f),
            XactNotifyCodecEncodeError::TooShort => {
                write!(f, "buffer is too short")
            }
        }
    }
}

impl<Header, Res, Err> Display for XactNotifyCodecDecodeError<Header, Res, Err>
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
            XactNotifyCodecDecodeError::Header { err } => err.fmt(f),
            XactNotifyCodecDecodeError::Hash { err } => err.fmt(f),
            XactNotifyCodecDecodeError::Res { err } => err.fmt(f),
            XactNotifyCodecDecodeError::Err { err } => err.fmt(f),
            XactNotifyCodecDecodeError::Round { .. } => {
                write!(f, "wrong number of bytes for round")
            }
            XactNotifyCodecDecodeError::TooShort => {
                write!(f, "buffer is too short")
            }
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
            XactBatchCodecCreateError::Notify { err } => err.fmt(f)
        }
    }
}

impl<Header, Req, Committed, Notify> Display
    for XactBatchCodecEncodeError<Header, Req, Committed, Notify>
where
    Header: Display,
    Req: Display,
    Committed: Display,
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
            XactBatchCodecEncodeError::Notify { err } => err.fmt(f)
        }
    }
}

impl<Header, Req, Committed, Notify> Display
    for XactBatchCodecDecodeError<Header, Req, Committed, Notify>
where
    Header: Display,
    Req: Display,
    Committed: Display,
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
            XactBatchCodecDecodeError::Notify { err } => err.fmt(f),
            XactBatchCodecDecodeError::Hash { err } => err.fmt(f),
            XactBatchCodecDecodeError::State { .. } => {
                write!(f, "round ID length")
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
    type DecodeError = Infallible;
    type EncodeError = Infallible;
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

        Ok((TestEffects { effects: effects }, len))
    }
}

#[cfg(test)]
impl Codec<TestPayload> for TestPayloadCodec {
    type CreateError = Infallible;
    type DecodeError = Infallible;
    type EncodeError = Infallible;
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

        Ok((TestPayload { effects: effects }, len))
    }
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
        instance: 0x1234567890abcdef
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
        instance: 0x1234567890abcdef
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
        instance: 0x1234567890abcdef
    };
    let mut codec = XactUncommittedReqHeaderPERCodec::default();
    let mut buf = [0; XactUncommittedReqHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_uncommitted_req_header_hard_none_linpoint_instance() {
    let effects_header = XactUncommittedEffectsHeader::HardNone(XactHardNone {
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
        instance: 0x1234567890abcdef
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
        instance: 0x1234567890abcdef
    };
    let mut codec = XactUncommittedReqHeaderPERCodec::default();
    let mut buf = [0; XactUncommittedReqHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_uncommitted_req_hard_effects_instance() {
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, TEST_SERVICE_NAME.as_bytes());
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
        instance: 0x1234567890abcdef,
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let mut codec: XactUncommittedReqCodec<
        u128,
        _,
        _,
        TestPayloadCodec,
        TestEffectsCodec
    > = XactUncommittedReqCodec::create(((), ())).expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_soft_effects_instance() {
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, TEST_SERVICE_NAME.as_bytes());
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
        instance: 0x1234567890abcdef,
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let mut codec: XactUncommittedReqCodec<
        u128,
        _,
        _,
        TestPayloadCodec,
        TestEffectsCodec
    > = XactUncommittedReqCodec::create(((), ())).expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_hard_none_no_linpoint_instance() {
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, TEST_SERVICE_NAME.as_bytes());
    let effects_header: XactEffects<u128, _> =
        XactEffects::HardNone { when: None };
    let req = XactUncommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: 0x1234567890abcdef,
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let mut codec: XactUncommittedReqCodec<
        u128,
        _,
        _,
        TestPayloadCodec,
        TestEffectsCodec
    > = XactUncommittedReqCodec::create(((), ())).expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_hard_none_linpoint_instance() {
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, TEST_SERVICE_NAME.as_bytes());
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
        instance: 0x1234567890abcdef,
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let mut codec: XactUncommittedReqCodec<
        u128,
        _,
        _,
        TestPayloadCodec,
        TestEffectsCodec
    > = XactUncommittedReqCodec::create(((), ())).expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_soft_none_no_linpoint_instance() {
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, TEST_SERVICE_NAME.as_bytes());
    let effects_header: XactEffects<u128, _> = XactEffects::SoftNone;
    let req = XactUncommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: 0x1234567890abcdef,
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let mut codec: XactUncommittedReqCodec<
        u128,
        _,
        _,
        TestPayloadCodec,
        TestEffectsCodec
    > = XactUncommittedReqCodec::create(((), ())).expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_hard_effects_instance_blob() {
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, TEST_SERVICE_NAME.as_bytes());
    let effects_header: XactEffects<u128, _> = XactEffects::Effects {
        effects: vec![2, 1, 0],
        hard: true
    };
    let mut codec: XactUncommittedReqBlobCodec<u128, SHA3Algo> =
        XactUncommittedReqBlobCodec::create(()).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[
            0xf9, 0xe2, 0xa2, 0x3f, 0xe3, 0x7d, 0x7e, 0xa5, 0x40, 0xfe, 0x31,
            0x55, 0x7a, 0x61, 0xbb, 0xa2, 0xfc, 0x6b, 0x6a, 0x97, 0xeb, 0x34,
            0xd1, 0x27, 0x6d, 0x60, 0x28, 0x44, 0xa1, 0x8d, 0x34, 0x33, 0x3e,
            0xdf, 0x5a, 0x15, 0xfb, 0x6e, 0x2a, 0x0b, 0x06, 0x6d, 0xce, 0x64,
            0x86, 0xb6, 0xa1, 0x18, 0x20, 0x87, 0x67, 0x23, 0xf1, 0x4c, 0xa6,
            0xe7, 0xf1, 0x58, 0x3f, 0x25, 0x4f, 0x8e, 0xfb, 0xa0
        ])
        .expect("Expected success");
    let req = XactUncommittedHashReq {
        hash: hash,
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: 0x1234567890abcdef,
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
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, TEST_SERVICE_NAME.as_bytes());
    let effects_header: XactEffects<u128, _> = XactEffects::Effects {
        effects: vec![2, 1, 0],
        hard: false
    };
    let mut codec: XactUncommittedReqBlobCodec<u128, SHA3Algo> =
        XactUncommittedReqBlobCodec::create(()).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[
            0x9a, 0x98, 0x33, 0x5a, 0x8b, 0x67, 0x9f, 0xe6, 0x41, 0x1b, 0x89,
            0x26, 0x0e, 0x0b, 0xb5, 0x10, 0x82, 0x70, 0xb8, 0x4b, 0x07, 0x24,
            0xda, 0xc0, 0x65, 0x72, 0x3d, 0x29, 0xd6, 0xa8, 0x18, 0x75, 0x30,
            0xd8, 0x1e, 0x1c, 0x9a, 0xed, 0xb7, 0x99, 0x97, 0x76, 0xcd, 0x34,
            0x6b, 0x94, 0x2a, 0x65, 0x15, 0x1c, 0x41, 0x53, 0xa5, 0xff, 0x26,
            0xc0, 0x79, 0xca, 0x86, 0x98, 0x9d, 0xbd, 0xe3, 0xdf
        ])
        .expect("Expected success");
    let req = XactUncommittedHashReq {
        hash: hash,
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: 0x1234567890abcdef,
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
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, TEST_SERVICE_NAME.as_bytes());
    let effects_header: XactEffects<u128, _> =
        XactEffects::HardNone { when: None };
    let mut codec: XactUncommittedReqBlobCodec<u128, SHA3Algo> =
        XactUncommittedReqBlobCodec::create(()).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[
            0xd0, 0x39, 0xdf, 0x49, 0x82, 0x38, 0x39, 0xf0, 0x8e, 0xf8, 0x06,
            0x9e, 0x9d, 0xe2, 0x71, 0xef, 0xd7, 0x5c, 0xa4, 0xed, 0x1f, 0xd8,
            0xa9, 0x63, 0x9b, 0x1a, 0xb7, 0x47, 0xc3, 0x11, 0x09, 0x33, 0xa5,
            0x4c, 0x2f, 0xc5, 0xaf, 0x05, 0x9f, 0x4d, 0x78, 0x1c, 0x01, 0x02,
            0x4c, 0x1d, 0xcf, 0xd7, 0xa6, 0xad, 0xda, 0x59, 0xe9, 0x78, 0xa7,
            0x63, 0xda, 0xe7, 0x2c, 0x7d, 0xeb, 0xa7, 0x60, 0xd3
        ])
        .expect("Expected success");
    let req = XactUncommittedHashReq {
        hash: hash,
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: 0x1234567890abcdef,
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
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, TEST_SERVICE_NAME.as_bytes());
    let effects_header: XactEffects<u128, _> = XactEffects::HardNone {
        when: Some(XactLinPoint {
            round: 0x1234567890abcdef,
            idx: 0x0f
        })
    };
    let mut codec: XactUncommittedReqBlobCodec<u128, SHA3Algo> =
        XactUncommittedReqBlobCodec::create(()).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[
            0x3c, 0xb6, 0x44, 0x34, 0x8b, 0xfb, 0xdb, 0xdf, 0x87, 0x5a, 0xbc,
            0x31, 0x4f, 0x26, 0xc8, 0xcb, 0x97, 0x21, 0x57, 0x42, 0x54, 0x1b,
            0x32, 0xba, 0x34, 0xb7, 0xc6, 0x0b, 0x5d, 0xf7, 0xba, 0x6a, 0x8b,
            0xf9, 0x72, 0xf6, 0x53, 0xc8, 0x2c, 0x24, 0x87, 0x34, 0x14, 0x19,
            0xde, 0x82, 0xa1, 0x26, 0x62, 0xa1, 0xfe, 0x8e, 0x09, 0x3b, 0xc9,
            0x64, 0x56, 0xcb, 0x00, 0x72, 0x80, 0xa6, 0xf7, 0x46
        ])
        .expect("Expected success");
    let req = XactUncommittedHashReq {
        hash: hash,
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: 0x1234567890abcdef,
        payload: vec![0, 1, 2, 3, 4, 5]
    };
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_soft_none_instance_blob() {
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, TEST_SERVICE_NAME.as_bytes());
    let effects_header: XactEffects<u128, _> = XactEffects::SoftNone;
    let mut codec: XactUncommittedReqBlobCodec<u128, SHA3Algo> =
        XactUncommittedReqBlobCodec::create(()).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[
            0x31, 0x38, 0x16, 0xe3, 0x14, 0x8a, 0x9d, 0x6d, 0x2c, 0x99, 0x8a,
            0x74, 0xc7, 0xde, 0x41, 0xdb, 0x98, 0xa5, 0xd9, 0xa7, 0x89, 0x14,
            0x56, 0x2c, 0x6e, 0x5b, 0xe4, 0x23, 0x07, 0x8d, 0x6b, 0x5f, 0x66,
            0x71, 0x31, 0x1d, 0xc9, 0x53, 0xee, 0xdf, 0xae, 0x36, 0x17, 0xd9,
            0xf6, 0xc7, 0x54, 0x41, 0x46, 0x86, 0x53, 0x5e, 0x97, 0x31, 0x10,
            0xae, 0x4d, 0x37, 0xb6, 0x29, 0x3b, 0x91, 0x2c, 0x88
        ])
        .expect("Expected success");
    let req = XactUncommittedHashReq {
        hash: hash,
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: 0x1234567890abcdef,
        payload: vec![0, 1, 2, 3, 4, 5]
    };
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_hard_effects_instance_hash() {
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, TEST_SERVICE_NAME.as_bytes());
    let effects_header: XactEffects<u128, _> = XactEffects::Effects {
        effects: TestEffects {
            effects: vec![2, 1, 0]
        },
        hard: true
    };
    let mut codec: XactUncommittedReqHashCodec<
        u128,
        SHA3Algo,
        _,
        _,
        TestPayloadCodec,
        TestEffectsCodec
    > = XactUncommittedReqHashCodec::create(((), ()))
        .expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[
            0xf9, 0xe2, 0xa2, 0x3f, 0xe3, 0x7d, 0x7e, 0xa5, 0x40, 0xfe, 0x31,
            0x55, 0x7a, 0x61, 0xbb, 0xa2, 0xfc, 0x6b, 0x6a, 0x97, 0xeb, 0x34,
            0xd1, 0x27, 0x6d, 0x60, 0x28, 0x44, 0xa1, 0x8d, 0x34, 0x33, 0x3e,
            0xdf, 0x5a, 0x15, 0xfb, 0x6e, 0x2a, 0x0b, 0x06, 0x6d, 0xce, 0x64,
            0x86, 0xb6, 0xa1, 0x18, 0x20, 0x87, 0x67, 0x23, 0xf1, 0x4c, 0xa6,
            0xe7, 0xf1, 0x58, 0x3f, 0x25, 0x4f, 0x8e, 0xfb, 0xa0
        ])
        .expect("Expected success");
    let req = XactUncommittedHashReq {
        hash: hash.clone(),
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: 0x1234567890abcdef,
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let actual_hash = codec.hash(&req).expect("Expected success");

    assert_eq!(hash, actual_hash);

    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_soft_effects_instance_hash() {
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, TEST_SERVICE_NAME.as_bytes());
    let effects_header: XactEffects<u128, _> = XactEffects::Effects {
        effects: TestEffects {
            effects: vec![2, 1, 0]
        },
        hard: false
    };
    let mut codec: XactUncommittedReqHashCodec<
        u128,
        SHA3Algo,
        _,
        _,
        TestPayloadCodec,
        TestEffectsCodec
    > = XactUncommittedReqHashCodec::create(((), ()))
        .expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[
            0x9a, 0x98, 0x33, 0x5a, 0x8b, 0x67, 0x9f, 0xe6, 0x41, 0x1b, 0x89,
            0x26, 0x0e, 0x0b, 0xb5, 0x10, 0x82, 0x70, 0xb8, 0x4b, 0x07, 0x24,
            0xda, 0xc0, 0x65, 0x72, 0x3d, 0x29, 0xd6, 0xa8, 0x18, 0x75, 0x30,
            0xd8, 0x1e, 0x1c, 0x9a, 0xed, 0xb7, 0x99, 0x97, 0x76, 0xcd, 0x34,
            0x6b, 0x94, 0x2a, 0x65, 0x15, 0x1c, 0x41, 0x53, 0xa5, 0xff, 0x26,
            0xc0, 0x79, 0xca, 0x86, 0x98, 0x9d, 0xbd, 0xe3, 0xdf
        ])
        .expect("Expected success");
    let req = XactUncommittedHashReq {
        hash: hash.clone(),
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: 0x1234567890abcdef,
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let actual_hash = codec.hash(&req).expect("Expected success");

    assert_eq!(hash, actual_hash);

    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_hard_none_no_linpoint_instance_hash() {
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, TEST_SERVICE_NAME.as_bytes());
    let effects_header: XactEffects<u128, _> =
        XactEffects::HardNone { when: None };
    let mut codec: XactUncommittedReqHashCodec<
        u128,
        SHA3Algo,
        _,
        _,
        TestPayloadCodec,
        TestEffectsCodec
    > = XactUncommittedReqHashCodec::create(((), ()))
        .expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[
            0xd0, 0x39, 0xdf, 0x49, 0x82, 0x38, 0x39, 0xf0, 0x8e, 0xf8, 0x06,
            0x9e, 0x9d, 0xe2, 0x71, 0xef, 0xd7, 0x5c, 0xa4, 0xed, 0x1f, 0xd8,
            0xa9, 0x63, 0x9b, 0x1a, 0xb7, 0x47, 0xc3, 0x11, 0x09, 0x33, 0xa5,
            0x4c, 0x2f, 0xc5, 0xaf, 0x05, 0x9f, 0x4d, 0x78, 0x1c, 0x01, 0x02,
            0x4c, 0x1d, 0xcf, 0xd7, 0xa6, 0xad, 0xda, 0x59, 0xe9, 0x78, 0xa7,
            0x63, 0xda, 0xe7, 0x2c, 0x7d, 0xeb, 0xa7, 0x60, 0xd3
        ])
        .expect("Expected success");
    let req = XactUncommittedHashReq {
        hash: hash.clone(),
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: 0x1234567890abcdef,
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let actual_hash = codec.hash(&req).expect("Expected success");

    assert_eq!(hash, actual_hash);

    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_hard_none_linpoint_instance_hash() {
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, TEST_SERVICE_NAME.as_bytes());
    let effects_header: XactEffects<u128, _> = XactEffects::HardNone {
        when: Some(XactLinPoint {
            round: 0x1234567890abcdef,
            idx: 0x0f
        })
    };
    let mut codec: XactUncommittedReqHashCodec<
        u128,
        SHA3Algo,
        _,
        _,
        TestPayloadCodec,
        TestEffectsCodec
    > = XactUncommittedReqHashCodec::create(((), ()))
        .expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[
            0x3c, 0xb6, 0x44, 0x34, 0x8b, 0xfb, 0xdb, 0xdf, 0x87, 0x5a, 0xbc,
            0x31, 0x4f, 0x26, 0xc8, 0xcb, 0x97, 0x21, 0x57, 0x42, 0x54, 0x1b,
            0x32, 0xba, 0x34, 0xb7, 0xc6, 0x0b, 0x5d, 0xf7, 0xba, 0x6a, 0x8b,
            0xf9, 0x72, 0xf6, 0x53, 0xc8, 0x2c, 0x24, 0x87, 0x34, 0x14, 0x19,
            0xde, 0x82, 0xa1, 0x26, 0x62, 0xa1, 0xfe, 0x8e, 0x09, 0x3b, 0xc9,
            0x64, 0x56, 0xcb, 0x00, 0x72, 0x80, 0xa6, 0xf7, 0x46
        ])
        .expect("Expected success");
    let req = XactUncommittedHashReq {
        hash: hash.clone(),
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: 0x1234567890abcdef,
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let actual_hash = codec.hash(&req).expect("Expected success");

    assert_eq!(hash, actual_hash);

    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_uncommitted_req_soft_none_instance_hash() {
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, TEST_SERVICE_NAME.as_bytes());
    let effects_header: XactEffects<u128, _> = XactEffects::SoftNone;
    let mut codec: XactUncommittedReqHashCodec<
        u128,
        SHA3Algo,
        _,
        _,
        TestPayloadCodec,
        TestEffectsCodec
    > = XactUncommittedReqHashCodec::create(((), ()))
        .expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[
            0x31, 0x38, 0x16, 0xe3, 0x14, 0x8a, 0x9d, 0x6d, 0x2c, 0x99, 0x8a,
            0x74, 0xc7, 0xde, 0x41, 0xdb, 0x98, 0xa5, 0xd9, 0xa7, 0x89, 0x14,
            0x56, 0x2c, 0x6e, 0x5b, 0xe4, 0x23, 0x07, 0x8d, 0x6b, 0x5f, 0x66,
            0x71, 0x31, 0x1d, 0xc9, 0x53, 0xee, 0xdf, 0xae, 0x36, 0x17, 0xd9,
            0xf6, 0xc7, 0x54, 0x41, 0x46, 0x86, 0x53, 0x5e, 0x97, 0x31, 0x10,
            0xae, 0x4d, 0x37, 0xb6, 0x29, 0x3b, 0x91, 0x2c, 0x88
        ])
        .expect("Expected success");
    let req = XactUncommittedHashReq {
        hash: hash.clone(),
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: effects_header,
        instance: 0x1234567890abcdef,
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        }
    };
    let actual_hash = codec.hash(&req).expect("Expected success");

    assert_eq!(hash, actual_hash);

    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_seal_header() {
    let header = XactSealHeader {
        len: 0xaaaa5555aaaa5555
    };
    let mut codec = XactSealHeaderPERCodec::default();
    let mut buf = [0; XactSealHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_sealed_uncommitted_req() {
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, TEST_SERVICE_NAME.as_bytes());
    let effects_header: XactEffects<u128, _> =
        XactEffects::HardNone { when: None };
    let sealed = XactSealed {
        inner: XactUncommittedReq {
            version: Version::new(1, 2, 3),
            class: uuid,
            effects: effects_header,
            instance: 0x1234567890abcdef,
            payload: TestPayload {
                effects: vec![0, 1, 2, 3, 4, 5]
            }
        },
        seal: TestPayload {
            effects: vec![6, 7, 8, 9, 0]
        }
    };
    let mut codec: XactSealedCodec<
        _,
        _,
        TestPayloadCodec,
        XactUncommittedReqCodec<u128, _, _, TestPayloadCodec, TestEffectsCodec>
    > = XactSealedCodec::create(((), ((), ()))).expect("Expected success");
    let len = codec.buf_size(&sealed);
    let mut buf = vec![0; len];
    let _ = codec.encode(&sealed, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(sealed, decoded);
}

#[test]
fn test_sealed_uncommitted_req_blob() {
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, TEST_SERVICE_NAME.as_bytes());
    let effects_header: XactEffects<u128, _> =
        XactEffects::HardNone { when: None };
    let sealed = XactSealed {
        inner: XactUncommittedReq {
            version: Version::new(1, 2, 3),
            class: uuid,
            effects: effects_header,
            instance: 0x1234567890abcdef,
            payload: TestPayload {
                effects: vec![0, 1, 2, 3, 4, 5]
            }
        },
        seal: vec![6, 7, 8, 9, 0]
    };
    let mut codec: XactSealedBlobCodec<
        _,
        XactUncommittedReqCodec<u128, _, _, TestPayloadCodec, TestEffectsCodec>
    > = XactSealedBlobCodec::create(((), ())).expect("Expected success");
    let len = codec.buf_size(&sealed);
    let mut buf = vec![0; len];
    let _ = codec.encode(&sealed, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(sealed, decoded);
}

#[test]
fn test_committed_req_header_no_effects_instance() {
    let header = XactCommittedReqHeader {
        version: Version::new(1, 2, 3),
        class: vec![0x55; 16],
        instance: 0x1234567890abcdef,
        idx: 0x0e,
        effects: None,
        len: 0xaaaa5555aaaa5555
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
        instance: 0x1234567890abcdef,
        idx: 0x0e,
        effects: Some(XactEffectsHeader {
            len: 0xfff0000ffff000,
            hard: true
        }),
        len: 0xaaaa5555aaaa5555
    };
    let mut codec = XactCommittedReqHeaderPERCodec::default();
    let mut buf = [0; XactCommittedReqHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_committed_no_effects_instance() {
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, TEST_SERVICE_NAME.as_bytes());
    let req = XactCommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: None,
        instance: 0x1234567890abcdef,
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        },
        idx: 0x0e
    };
    let mut codec: XactCommittedReqCodec<
        _,
        _,
        TestPayloadCodec,
        TestEffectsCodec
    > = XactCommittedReqCodec::create(((), ())).expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_committed_effects_instance() {
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, TEST_SERVICE_NAME.as_bytes());
    let req = XactCommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: Some(XactCommittedEffects {
            effects: TestEffects {
                effects: vec![0, 1, 2]
            },
            hard: true
        }),
        instance: 0x1234567890abcdef,
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        },
        idx: 0x0e
    };
    let mut codec: XactCommittedReqCodec<
        _,
        _,
        TestPayloadCodec,
        TestEffectsCodec
    > = XactCommittedReqCodec::create(((), ())).expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_committed_no_effects_instance_blob() {
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, TEST_SERVICE_NAME.as_bytes());
    let req = XactCommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: None,
        instance: 0x1234567890abcdef,
        payload: vec![0, 1, 2, 3, 4, 5],
        idx: 0x0e
    };
    let mut codec: XactCommittedReqBlobCodec =
        XactCommittedReqBlobCodec::create(()).expect("Expected success");
    let len = codec.buf_size(&req);
    let mut buf = vec![0; len];
    let _ = codec.encode(&req, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(req, decoded);
}

#[test]
fn test_committed_effects_instance_blob() {
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, TEST_SERVICE_NAME.as_bytes());
    let req = XactCommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: Some(XactCommittedEffects {
            effects: vec![0, 1, 2],
            hard: true
        }),
        instance: 0x1234567890abcdef,
        payload: vec![0, 1, 2, 3, 4, 5],
        idx: 0x0e
    };
    let mut codec: XactCommittedReqBlobCodec =
        XactCommittedReqBlobCodec::create(()).expect("Expected success");
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
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, TEST_SERVICE_NAME.as_bytes());
    let req = XactCommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: Some(XactCommittedEffects {
            effects: TestEffects {
                effects: vec![0, 1, 2]
            },
            hard: true
        }),
        instance: 0x1234567890abcdef,
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
    let mut codec: XactCommittedRoundCodec<
        _,
        SHA3Algo,
        _,
        _,
        _,
        TestPayloadCodec,
        TestPayloadCodec,
        TestEffectsCodec
    > = XactCommittedRoundCodec::create(((), (), ()))
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
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, TEST_SERVICE_NAME.as_bytes());
    let req = XactCommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: Some(XactCommittedEffects {
            effects: TestEffects {
                effects: vec![0, 1, 2]
            },
            hard: true
        }),
        instance: 0x1234567890abcdef,
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
                    .expect("Expected success"),
            ],
            seals: vec![
                TestPayload {
                    effects: vec![0, 1, 2, 3, 4, 5]
                },
                TestPayload {
                    effects: vec![6, 7, 8, 9]
                },
            ]
        }),
        reqs: vec![req]
    };
    let mut codec: XactCommittedRoundCodec<
        _,
        SHA3Algo,
        _,
        _,
        _,
        TestPayloadCodec,
        TestPayloadCodec,
        TestEffectsCodec
    > = XactCommittedRoundCodec::create(((), (), ()))
        .expect("Expected success");
    let len = codec.buf_size(&header);
    let mut buf = vec![0; len];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_committed_round_no_seal_blob() {
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, TEST_SERVICE_NAME.as_bytes());
    let req = XactCommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: Some(XactCommittedEffects {
            effects: vec![0, 1, 2],
            hard: true
        }),
        instance: 0x1234567890abcdef,
        payload: vec![0, 1, 2, 3, 4, 5],
        idx: 0x0e
    };
    let header = XactCommittedRound {
        round: 0x1234567890abcdef,
        seal: None,
        reqs: vec![req]
    };
    let mut codec: XactCommittedRoundBlobCodec<
        _,
        SHA3Algo,
        _,
        TestPayloadCodec
    > = XactCommittedRoundBlobCodec::create(()).expect("Expected success");
    let len = codec.buf_size(&header);
    let mut buf = vec![0; len];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_committed_round_seal_blob() {
    let hash = SHA3Algo::default();
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, TEST_SERVICE_NAME.as_bytes());
    let req = XactCommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: Some(XactCommittedEffects {
            effects: vec![0, 1, 2],
            hard: true
        }),
        instance: 0x1234567890abcdef,
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
                    .expect("Expected success"),
            ],
            seals: vec![
                TestPayload {
                    effects: vec![0, 1, 2, 3, 4, 5]
                },
                TestPayload {
                    effects: vec![6, 7, 8, 9]
                },
            ]
        }),
        reqs: vec![req]
    };
    let mut codec: XactCommittedRoundBlobCodec<
        _,
        SHA3Algo,
        _,
        TestPayloadCodec
    > = XactCommittedRoundBlobCodec::create(()).expect("Expected success");
    let len = codec.buf_size(&header);
    let mut buf = vec![0; len];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
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
fn test_notify_header_precommit_no_linpoint() {
    let state = XactNotifyStateHeader::PrecommitDispatch(XactPrecommitState {
        when: None
    });
    let header = XactNotifyHeader {
        hash: vec![0x11; 64],
        state: state
    };
    let mut codec = XactNotifyHeaderPERCodec::default();
    let mut buf = [0; XactNotifyHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_notify_header_precommit_linpoint() {
    let header = XactNotifyHeader {
        hash: vec![0x11; 64],
        state: XactNotifyStateHeader::PrecommitDispatch(
            crate::generated::xact::XactPrecommitState {
                when: Some(crate::generated::xact::XactLinPoint {
                    round: vec![0x88; 16],
                    idx: 0x7
                })
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
        state: XactNotifyStateHeader::Dispatch(
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
fn test_notify_header_success() {
    let header = XactNotifyHeader {
        hash: vec![0x11; 64],
        state: XactNotifyStateHeader::Success(XactResultHeader {
            when: crate::generated::xact::XactLinPoint {
                round: vec![0x88; 16],
                idx: 0x7
            },
            len: 0x1234567890abcdef
        })
    };
    let mut codec = XactNotifyHeaderPERCodec::default();
    let mut buf = [0; XactNotifyHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_notify_header_finished() {
    let header = XactNotifyHeader {
        hash: vec![0x11; 64],
        state: XactNotifyStateHeader::Finished(
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
fn test_notify_header_error_error() {
    let header = XactNotifyHeader {
        hash: vec![0x11; 64],
        state: XactNotifyStateHeader::Error(XactErrorHeader::Error(
            crate::generated::xact::XactValueHeader {
                len: 0x1234567890abcdef
            }
        ))
    };
    let mut codec = XactNotifyHeaderPERCodec::default();
    let mut buf = [0; XactNotifyHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_notify_header_error_unknown_class() {
    let header = XactNotifyHeader {
        hash: vec![0x11; 64],
        state: XactNotifyStateHeader::Error(XactErrorHeader::UnknownClass(
            Default::default()
        ))
    };
    let mut codec = XactNotifyHeaderPERCodec::default();
    let mut buf = [0; XactNotifyHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_notify_header_error_unknown_version() {
    let header = XactNotifyHeader {
        hash: vec![0x11; 64],
        state: XactNotifyStateHeader::Error(XactErrorHeader::UnknownVersion(
            Default::default()
        ))
    };
    let mut codec = XactNotifyHeaderPERCodec::default();
    let mut buf = [0; XactNotifyHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_notify_header_error_unknown_instance() {
    let header = XactNotifyHeader {
        hash: vec![0x11; 64],
        state: XactNotifyStateHeader::Error(XactErrorHeader::UnknownInstance(
            Default::default()
        ))
    };
    let mut codec = XactNotifyHeaderPERCodec::default();
    let mut buf = [0; XactNotifyHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_notify_header_error_invalid_payload() {
    let header = XactNotifyHeader {
        hash: vec![0x11; 64],
        state: XactNotifyStateHeader::Error(XactErrorHeader::InvalidPayload(
            Default::default()
        ))
    };
    let mut codec = XactNotifyHeaderPERCodec::default();
    let mut buf = [0; XactNotifyHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_notify_header_error_invalid_effect() {
    let header = XactNotifyHeader {
        hash: vec![0x11; 64],
        state: XactNotifyStateHeader::Error(XactErrorHeader::InvalidEffect(
            Default::default()
        ))
    };
    let mut codec = XactNotifyHeaderPERCodec::default();
    let mut buf = [0; XactNotifyHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_notify_header_error_effect_violation() {
    let header = XactNotifyHeader {
        hash: vec![0x11; 64],
        state: XactNotifyStateHeader::Error(XactErrorHeader::EffectViolation(
            Default::default()
        ))
    };
    let mut codec = XactNotifyHeaderPERCodec::default();
    let mut buf = [0; XactNotifyHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_notify_header_error_unauthorized() {
    let header = XactNotifyHeader {
        hash: vec![0x11; 64],
        state: XactNotifyStateHeader::Error(XactErrorHeader::Unauthorized(
            Default::default()
        ))
    };
    let mut codec = XactNotifyHeaderPERCodec::default();
    let mut buf = [0; XactNotifyHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_notify_header_error_uncommitted() {
    let header = XactNotifyHeader {
        hash: vec![0x11; 64],
        state: XactNotifyStateHeader::Error(XactErrorHeader::Uncommitted(
            Default::default()
        ))
    };
    let mut codec = XactNotifyHeaderPERCodec::default();
    let mut buf = [0; XactNotifyHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_notify_header_error_hash_mismatch() {
    let header = XactNotifyHeader {
        hash: vec![0x11; 64],
        state: XactNotifyStateHeader::Error(XactErrorHeader::HashMismatch(
            Default::default()
        ))
    };
    let mut codec = XactNotifyHeaderPERCodec::default();
    let mut buf = [0; XactNotifyHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_notify_header_error_internal() {
    let header = XactNotifyHeader {
        hash: vec![0x11; 64],
        state: XactNotifyStateHeader::Error(XactErrorHeader::Internal(
            Default::default()
        ))
    };
    let mut codec = XactNotifyHeaderPERCodec::default();
    let mut buf = [0; XactNotifyHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_notify_header_fail() {
    let header = XactNotifyHeader {
        hash: vec![0x11; 64],
        state: XactNotifyStateHeader::Fail(Default::default())
    };
    let mut codec = XactNotifyHeaderPERCodec::default();
    let mut buf = [0; XactNotifyHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_batch_header() {
    let header = XactBatchHeader {
        ncommitted: 0xffffff,
        nreqs: 0xffffff,
        nnotifies: 0xffffff
    };
    let mut codec = XactBatchHeaderPERCodec::default();
    let mut buf = [0; XactBatchHeaderPERCodec::MAX_BYTES];
    let _ = codec.encode(&header, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(header, decoded);
}

#[test]
fn test_notify_success_accept() {
    let mut codec: XactNotifyCodec<
        u128,
        SHA3Algo,
        _,
        _,
        TestPayloadCodec,
        TestPayloadCodec
    > = XactNotifyCodec::create(((), ())).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Accept,
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_success_precommit_dispatch_no_linpoint() {
    let mut codec: XactNotifyCodec<
        u128,
        SHA3Algo,
        _,
        _,
        TestPayloadCodec,
        TestPayloadCodec
    > = XactNotifyCodec::create(((), ())).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::PrecommitDispatch { when: None },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_success_precommit_dispatch_linpoint() {
    let mut codec: XactNotifyCodec<
        u128,
        SHA3Algo,
        _,
        _,
        TestPayloadCodec,
        TestPayloadCodec
    > = XactNotifyCodec::create(((), ())).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::PrecommitDispatch {
            when: Some(XactLinPoint {
                round: 0xaaaa4444aaaa4444,
                idx: 0x7
            })
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_success_consensus() {
    let mut codec: XactNotifyCodec<
        u128,
        SHA3Algo,
        _,
        _,
        TestPayloadCodec,
        TestPayloadCodec
    > = XactNotifyCodec::create(((), ())).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Consensus,
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_success_commit() {
    let mut codec: XactNotifyCodec<
        u128,
        SHA3Algo,
        _,
        _,
        TestPayloadCodec,
        TestPayloadCodec
    > = XactNotifyCodec::create(((), ())).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Commit {
            when: XactLinPoint {
                round: 0xaaaa4444aaaa4444,
                idx: 0x7
            }
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_success_dispatch() {
    let mut codec: XactNotifyCodec<
        u128,
        SHA3Algo,
        _,
        _,
        TestPayloadCodec,
        TestPayloadCodec
    > = XactNotifyCodec::create(((), ())).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Dispatch {
            when: XactLinPoint {
                round: 0xaaaa4444aaaa4444,
                idx: 0x7
            }
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_success_no_result() {
    let mut codec: XactNotifyCodec<
        u128,
        SHA3Algo,
        _,
        _,
        TestPayloadCodec,
        TestPayloadCodec
    > = XactNotifyCodec::create(((), ())).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Success {
            result: None,
            when: XactLinPoint {
                round: 0xaaaa4444aaaa4444,
                idx: 0x7
            }
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_success_result() {
    let mut codec: XactNotifyCodec<
        u128,
        SHA3Algo,
        _,
        _,
        TestPayloadCodec,
        TestPayloadCodec
    > = XactNotifyCodec::create(((), ())).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Success {
            result: Some(TestPayload {
                effects: vec![0, 1, 2, 3, 4, 5]
            }),
            when: XactLinPoint {
                round: 0xaaaa4444aaaa4444,
                idx: 0x7
            }
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_error_no_info() {
    let mut codec: XactNotifyCodec<
        u128,
        SHA3Algo,
        _,
        _,
        TestPayloadCodec,
        TestPayloadCodec
    > = XactNotifyCodec::create(((), ())).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Error { error: None },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_error_info_error() {
    let mut codec: XactNotifyCodec<
        u128,
        SHA3Algo,
        _,
        _,
        TestPayloadCodec,
        TestPayloadCodec
    > = XactNotifyCodec::create(((), ())).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Error {
            error: Some(XactError::Error {
                err: TestPayload {
                    effects: vec![0, 1, 2, 3, 4, 5]
                }
            })
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_error_info_unknown_class() {
    let mut codec: XactNotifyCodec<
        u128,
        SHA3Algo,
        _,
        _,
        TestPayloadCodec,
        TestPayloadCodec
    > = XactNotifyCodec::create(((), ())).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Error {
            error: Some(XactError::UnknownClass)
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_error_info_unknown_version() {
    let mut codec: XactNotifyCodec<
        u128,
        SHA3Algo,
        _,
        _,
        TestPayloadCodec,
        TestPayloadCodec
    > = XactNotifyCodec::create(((), ())).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Error {
            error: Some(XactError::UnknownVersion)
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_error_info_unknown_instance() {
    let mut codec: XactNotifyCodec<
        u128,
        SHA3Algo,
        _,
        _,
        TestPayloadCodec,
        TestPayloadCodec
    > = XactNotifyCodec::create(((), ())).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Error {
            error: Some(XactError::UnknownInstance)
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_error_info_invalid_payload() {
    let mut codec: XactNotifyCodec<
        u128,
        SHA3Algo,
        _,
        _,
        TestPayloadCodec,
        TestPayloadCodec
    > = XactNotifyCodec::create(((), ())).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Error {
            error: Some(XactError::InvalidPayload)
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_error_info_invalid_effect() {
    let mut codec: XactNotifyCodec<
        u128,
        SHA3Algo,
        _,
        _,
        TestPayloadCodec,
        TestPayloadCodec
    > = XactNotifyCodec::create(((), ())).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Error {
            error: Some(XactError::InvalidEffect)
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_error_info_effect_violation() {
    let mut codec: XactNotifyCodec<
        u128,
        SHA3Algo,
        _,
        _,
        TestPayloadCodec,
        TestPayloadCodec
    > = XactNotifyCodec::create(((), ())).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Error {
            error: Some(XactError::EffectViolation)
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_error_info_unauthorized() {
    let mut codec: XactNotifyCodec<
        u128,
        SHA3Algo,
        _,
        _,
        TestPayloadCodec,
        TestPayloadCodec
    > = XactNotifyCodec::create(((), ())).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Error {
            error: Some(XactError::Unauthorized)
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_error_info_uncommitted() {
    let mut codec: XactNotifyCodec<
        u128,
        SHA3Algo,
        _,
        _,
        TestPayloadCodec,
        TestPayloadCodec
    > = XactNotifyCodec::create(((), ())).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Error {
            error: Some(XactError::Uncommitted)
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_error_info_internal() {
    let mut codec: XactNotifyCodec<
        u128,
        SHA3Algo,
        _,
        _,
        TestPayloadCodec,
        TestPayloadCodec
    > = XactNotifyCodec::create(((), ())).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Error {
            error: Some(XactError::Internal)
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_success_accept_blob() {
    let mut codec: XactNotifyBlobCodec<u128, SHA3Algo> =
        XactNotifyBlobCodec::create(()).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Accept,
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_success_precommit_dispatch_no_linpoint_blob() {
    let mut codec: XactNotifyBlobCodec<u128, SHA3Algo> =
        XactNotifyBlobCodec::create(()).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::PrecommitDispatch { when: None },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_success_precommit_dispatch_linpoint_blob() {
    let mut codec: XactNotifyBlobCodec<u128, SHA3Algo> =
        XactNotifyBlobCodec::create(()).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::PrecommitDispatch {
            when: Some(XactLinPoint {
                round: 0xaaaa4444aaaa4444,
                idx: 0x7
            })
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_success_consensus_blob() {
    let mut codec: XactNotifyBlobCodec<u128, SHA3Algo> =
        XactNotifyBlobCodec::create(()).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Consensus,
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_success_commit_blob() {
    let mut codec: XactNotifyBlobCodec<u128, SHA3Algo> =
        XactNotifyBlobCodec::create(()).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Commit {
            when: XactLinPoint {
                round: 0xaaaa4444aaaa4444,
                idx: 0x7
            }
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_success_dispatch_blob() {
    let mut codec: XactNotifyBlobCodec<u128, SHA3Algo> =
        XactNotifyBlobCodec::create(()).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Dispatch {
            when: XactLinPoint {
                round: 0xaaaa4444aaaa4444,
                idx: 0x7
            }
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_success_no_result_blob() {
    let mut codec: XactNotifyBlobCodec<u128, SHA3Algo> =
        XactNotifyBlobCodec::create(()).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Success {
            result: None,
            when: XactLinPoint {
                round: 0xaaaa4444aaaa4444,
                idx: 0x7
            }
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_success_result_blob() {
    let mut codec: XactNotifyBlobCodec<u128, SHA3Algo> =
        XactNotifyBlobCodec::create(()).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Success {
            result: Some(vec![0, 1, 2, 3, 4, 5]),
            when: XactLinPoint {
                round: 0xaaaa4444aaaa4444,
                idx: 0x7
            }
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_error_no_info_blob() {
    let mut codec: XactNotifyBlobCodec<u128, SHA3Algo> =
        XactNotifyBlobCodec::create(()).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Error { error: None },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_error_info_error_blob() {
    let mut codec: XactNotifyBlobCodec<u128, SHA3Algo> =
        XactNotifyBlobCodec::create(()).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Error {
            error: Some(XactError::Error {
                err: vec![0, 1, 2, 3, 4, 5]
            })
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_error_info_unknown_class_blob() {
    let mut codec: XactNotifyBlobCodec<u128, SHA3Algo> =
        XactNotifyBlobCodec::create(()).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Error {
            error: Some(XactError::UnknownClass)
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_error_info_unknown_version_blob() {
    let mut codec: XactNotifyBlobCodec<u128, SHA3Algo> =
        XactNotifyBlobCodec::create(()).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Error {
            error: Some(XactError::UnknownVersion)
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_error_info_unknown_instance_blob() {
    let mut codec: XactNotifyBlobCodec<u128, SHA3Algo> =
        XactNotifyBlobCodec::create(()).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Error {
            error: Some(XactError::UnknownInstance)
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_error_info_invalid_payload_blob() {
    let mut codec: XactNotifyBlobCodec<u128, SHA3Algo> =
        XactNotifyBlobCodec::create(()).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Error {
            error: Some(XactError::InvalidPayload)
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_error_info_invalid_effect_blob() {
    let mut codec: XactNotifyBlobCodec<u128, SHA3Algo> =
        XactNotifyBlobCodec::create(()).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Error {
            error: Some(XactError::InvalidEffect)
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_error_info_effect_violation_blob() {
    let mut codec: XactNotifyBlobCodec<u128, SHA3Algo> =
        XactNotifyBlobCodec::create(()).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Error {
            error: Some(XactError::EffectViolation)
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_error_info_unauthorized_blob() {
    let mut codec: XactNotifyBlobCodec<u128, SHA3Algo> =
        XactNotifyBlobCodec::create(()).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Error {
            error: Some(XactError::Unauthorized)
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_error_info_uncommitted_blob() {
    let mut codec: XactNotifyBlobCodec<u128, SHA3Algo> =
        XactNotifyBlobCodec::create(()).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Error {
            error: Some(XactError::Uncommitted)
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_notify_error_info_internal_blob() {
    let mut codec: XactNotifyBlobCodec<u128, SHA3Algo> =
        XactNotifyBlobCodec::create(()).expect("Expected success");
    let hash = codec
        .hash
        .wrap_hashed_bytes(&[0; 64])
        .expect("Expected success");
    let result = XactNotify {
        state: XactNotifyState::Error {
            error: Some(XactError::Internal)
        },
        hash: hash
    };
    let len = codec.buf_size(&result);
    let mut buf = vec![0; len];
    let _ = codec.encode(&result, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(result, decoded);
}

#[test]
fn test_batch() {
    let mut codec: XactBatchCodec<
        _,
        SHA3Algo,
        _,
        _,
        _,
        _,
        _,
        TestPayloadCodec,
        TestPayloadCodec,
        TestEffectsCodec,
        TestPayloadCodec,
        TestPayloadCodec
    > = XactBatchCodec::create(((), (), (), (), ())).expect("Expected success");
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, TEST_SERVICE_NAME.as_bytes());
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
        instance: 0x1234567890abcdef,
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
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, TEST_SERVICE_NAME.as_bytes());
    let committed = XactCommittedReq {
        version: Version::new(1, 2, 3),
        class: uuid,
        effects: Some(XactCommittedEffects {
            effects: TestEffects {
                effects: vec![0, 1, 2]
            },
            hard: true
        }),
        instance: 0x1234567890abcdef,
        payload: TestPayload {
            effects: vec![0, 1, 2, 3, 4, 5]
        },
        idx: 0x0e
    };
    let hasher = SHA3Algo::default();
    let round = XactCommittedRound {
        round: 0x1234567890abcdef,
        seal: Some(XactConsensusSeal {
            hashes: vec![
                hasher
                    .wrap_hashed_bytes(&[0x00; 64])
                    .expect("Expected success"),
                hasher
                    .wrap_hashed_bytes(&[0x11; 64])
                    .expect("Expected success"),
                hasher
                    .wrap_hashed_bytes(&[0x22; 64])
                    .expect("Expected success"),
                hasher
                    .wrap_hashed_bytes(&[0x33; 64])
                    .expect("Expected success"),
                hasher
                    .wrap_hashed_bytes(&[0x44; 64])
                    .expect("Expected success"),
                hasher
                    .wrap_hashed_bytes(&[0x55; 64])
                    .expect("Expected success"),
                hasher
                    .wrap_hashed_bytes(&[0x66; 64])
                    .expect("Expected success"),
                hasher
                    .wrap_hashed_bytes(&[0x77; 64])
                    .expect("Expected success"),
                hasher
                    .wrap_hashed_bytes(&[0x88; 64])
                    .expect("Expected success"),
                hasher
                    .wrap_hashed_bytes(&[0x99; 64])
                    .expect("Expected success"),
                hasher
                    .wrap_hashed_bytes(&[0xaa; 64])
                    .expect("Expected success"),
                hasher
                    .wrap_hashed_bytes(&[0xbb; 64])
                    .expect("Expected success"),
                hasher
                    .wrap_hashed_bytes(&[0xcc; 64])
                    .expect("Expected success"),
                hasher
                    .wrap_hashed_bytes(&[0xdd; 64])
                    .expect("Expected success"),
                hasher
                    .wrap_hashed_bytes(&[0xee; 64])
                    .expect("Expected success"),
                hasher
                    .wrap_hashed_bytes(&[0xff; 64])
                    .expect("Expected success"),
            ],
            seals: vec![
                TestPayload {
                    effects: vec![0, 1, 2, 3, 4, 5]
                },
                TestPayload {
                    effects: vec![6, 7, 8, 9]
                },
            ]
        }),
        reqs: vec![committed]
    };
    let hash = hasher
        .wrap_hashed_bytes(&[0x11; 64])
        .expect("Expected success");
    let notify = XactNotify {
        hash: hash,
        state: XactNotifyState::Success {
            result: Some(TestPayload {
                effects: vec![0, 1, 2, 3, 4, 5]
            }),
            when: XactLinPoint {
                round: 0x1234567890abcdef,
                idx: 0x7
            }
        }
    };
    let batch = XactBatch {
        reqs: vec![sealed],
        committed: vec![round],
        notifies: vec![notify]
    };
    let len = codec.buf_size(&batch);
    let mut buf = vec![0; len];
    let _ = codec.encode(&batch, &mut buf).expect("Expected success");
    let (decoded, _) = codec.decode(&buf).expect("Expected success");

    assert_eq!(batch, decoded);
}
