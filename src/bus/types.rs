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

use std::convert::Infallible;
use std::fmt::Debug;
use std::fmt::Display;
use std::hash::Hash;
use std::io::Error;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;

use constellation_auth::authn::AuthNMsgRecv;
use constellation_auth::authn::AuthNed;
use constellation_auth::authn::AuthNedDestruct;
use constellation_auth::authn::AuthNedMap;
use constellation_auth::authn::MsgAuthN;
use constellation_auth::authn::SessionAuthN;
use constellation_channels::config::CompoundFarChannelXfrmPeerAddr;
use constellation_channels::config::CompoundFarEndpoint;
use constellation_channels::far::channels::CompoundFarChannels;
use constellation_channels::far::compound::CompoundFarChannelAddr;
use constellation_channels::far::compound::CompoundFlow;
use constellation_channels::far::types::CompoundFarChannelsDatagramChan;
use constellation_channels::far::types::CompoundFarChannelsLargeObjChan;
use constellation_channels::resolve::cache::NSNameCachesCtx;
use constellation_common::config::Create;
use constellation_common::config::CreateWithParam;
use constellation_common::codec::Decoder;
use constellation_common::codec::Encoder;
use constellation_common::error::CodecStreamError;
use constellation_common::error::ScopedError;
use constellation_common::hashid::HashAlgo;
use constellation_common::hashid::HashID;
use constellation_common::net::DatagramXfrmCreate;
use constellation_common::net::PrivateMsgs;
use constellation_common::net::SharedMsgs;
use constellation_common::net::Session;
use constellation_common::unix::UnixSocketPath;
use constellation_streams::addrs::AddrsCreate;
use constellation_streams::codec::CodecBatchID;
use constellation_streams::codec::DatagramCodecFragError;
use constellation_streams::frags::OutboundFrags;
use constellation_streams::large_obj::LargeObjID;
use constellation_streams::large_obj::LargeObjMsg;
use constellation_streams::large_obj::LargeObjMsgCodec;
use constellation_streams::large_obj::LargeObjMsgEncodeError;
use constellation_streams::large_obj::LargeObjMsgs;
use constellation_streams::large_obj::LargeObjProtoTypes;
use constellation_streams::multicast::MulticastStreamIdx;
use constellation_streams::stream::LargeObjOfferStream;
use constellation_streams::stream::PullStream;
use constellation_streams::stream::PushStreamAdd;
use constellation_streams::stream::PushStreamPrivate;
use constellation_streams::stream::RefCellStreamError;
use constellation_streams::threads::poll::MsgsWaker;
use constellation_streams::threads::poll::PollThreadCtx;

/// XXX Refactor to remove the stream instance from AuthNChan, then we
/// can get rid of a lot of the stray types in here.
pub trait UnicastDatagramBusTypes<Ctx>
where
    Ctx: 'static + NSNameCachesCtx + Send {
    type OutMsg: Clone;
    type InMsg;
    type Wrapper;
    type MsgPrin: Clone + Display + Eq + Hash;
    type SessionPrin: Display + Send + Sync;
    type AuthNMsg: AuthNed<Self::MsgPrin>;
    type SessionAuth: CreateWithParam<bool,
                                      Config = Self::SessionAuthConfig>
        + SessionAuthN<CompoundFlow<Self::Unix, Self::UDP>,
                       Prin = Self::SessionPrin,
                       AuthNSession = Self::AuthNSession,
                       Param = (),
                       NegotiateError = Self::SessionAuthNError>;
    type SessionAuthConfig: Clone + Send;
    type SessionAuthNError: ScopedError;
    type AuthNSession:
        AuthNedMap<
            Self::SessionPrin,
            CompoundFlow<Self::Unix, Self::UDP>,
            CompoundFarChannelsDatagramChan<
                Self::Wrapper,
                Self::OutMsg,
                Self::Unix,
                Self::UDP,
                Self::Encoder,
                Self::Decoder
            >,
            Self::AuthNChan
        > + Session<
            PeerAddr = CompoundFarChannelXfrmPeerAddr,
            LocalAddr = CompoundFarChannelAddr
        > + Read + Write;
    type AuthNChan: Clone
        + AuthNed<Self::SessionPrin>
        + AuthNedDestruct<
            Self::SessionPrin,
            CompoundFarChannelsDatagramChan<
                Self::Wrapper,
                Self::OutMsg,
                Self::Unix,
                Self::UDP,
                Self::Encoder,
                Self::Decoder
            >
        >
        + PushStreamAdd<
            Self::OutMsg,
            PollThreadCtx<
                Self::SessionPrin,
                CompoundFarChannels<
                    Self::SessionAuth,
                    Self::AuthNChan,
                    Self::Unix,
                    Self::UDP,
                    Self::OutMsg,
                    Self::Wrapper,
                    Self::Encoder,
                    Self::Decoder
                >,
                Ctx,
            >,
            BatchID = CodecBatchID,
            AddError = RefCellStreamError<
                CodecStreamError<Self::EncodeError, std::io::Error>
            >
        >
        + PushStreamPrivate<
            PollThreadCtx<
                Self::SessionPrin,
                CompoundFarChannels<
                    Self::SessionAuth,
                    Self::AuthNChan,
                    Self::Unix,
                    Self::UDP,
                    Self::OutMsg,
                    Self::Wrapper,
                    Self::Encoder,
                    Self::Decoder
                >,
                Ctx
            >,
            StartBatchError = RefCellStreamError<Infallible>,
            CancelBatchError = RefCellStreamError<Infallible>,
            FinishBatchError = RefCellStreamError<Infallible>
        >
        + PullStream<Self::Wrapper>;
    type MsgAuth: Create<
            Config = Self::MsgAuthConfig,
        > + MsgAuthN<
            Self::InMsg,
            Self::Wrapper,
            Prin = Self::MsgPrin,
            AuthNMsg = Self::AuthNMsg,
            SessionPrin = Self::SessionPrin,
        >;
    type MsgAuthConfig: Send;
    type Encoder: Create<Config = Self::EncoderConfig,
                     CreateError = Self::EncoderCreateError>
        + Encoder<Self::OutMsg>;
    type EncoderConfig: Clone + Default + Send;
    type EncodeError: Debug + Display + ScopedError;
    type EncoderCreateError: Debug + Display + ScopedError;
    type Decoder: Create<Config = Self::DecoderConfig,
                     CreateError = Self::DecoderCreateError>
        + Decoder<Self::Wrapper>;
    type DecoderConfig: Clone + Default + Send;
    type DecoderCreateError: Debug + Display + ScopedError;
    type Unix: DatagramXfrmCreate<Addr = UnixSocketPath,
                                  CreateParam = Self::UnixConfig,
                                  Error = Self::UnixError,
                                  PeerAddr = UnixSocketPath,
                                  LocalAddr = UnixSocketPath>;
    type UnixConfig: Clone + Default + Send;
    type UnixError: Debug + Display + ScopedError;
    type UDP: DatagramXfrmCreate<Addr = SocketAddr,
                                 CreateParam = Self::UDPConfig,
                                 Error = Self::UDPError,
                                 PeerAddr = SocketAddr,
                                 LocalAddr = SocketAddr>;
    type UDPConfig: Clone + Default + Send;
    type UDPError: Debug + Display + ScopedError;
    type Epoch: Clone + Debug + Default + Display + Eq + Hash;
    type Epochs: Create<Config = Self::EpochsConfig>
        + Iterator<Item = Self::Epoch>;
    type EpochsConfig: Default + Send;
    type Origin: Clone + Debug + Display + Eq + Hash;
    type Resolver: AddrsCreate<
        PollThreadCtx<
            Self::SessionPrin,
            CompoundFarChannels<
                Self::SessionAuth,
                Self::AuthNChan,
                Self::Unix,
                Self::UDP,
                Self::OutMsg,
                Self::Wrapper,
                Self::Encoder,
                Self::Decoder
            >,
            Ctx
        >,
        Addr = CompoundFarChannelXfrmPeerAddr,
        Origin = Self::Origin,
        OriginConfig = CompoundFarEndpoint,
        Config = Self::ResolverConfig,
    >;
    type ResolverConfig: Clone + Default + Send;
    type Recv: AuthNMsgRecv<Self::MsgPrin, Self::AuthNMsg> + Send;
    type Msgs: PrivateMsgs<Self::OutMsg> + MsgsWaker + Send;
}

pub trait UnicastLargeObjBusTypes<Ctx>
where
    Ctx: 'static + NSNameCachesCtx + Send {
    type OutMsg: Clone + Send;
    type InMsg: Send;
    type Wrapper;
    type MsgPrin: Clone + Debug + Display + Eq + Hash;
    type SessionPrin: Clone + Debug + Display + Eq + Hash + Send + Sync;
    type AuthNMsg: AuthNed<Self::MsgPrin>;
    type Hash: Clone + Default
        + Create<Config = Self::HashConfig,
                 CreateError = Self::HashCreateError>
        + HashAlgo<HashID = Self::HashID> + Send;
    type HashID: Clone + Debug + Display + Eq + Hash + HashID + Send;
    type HashConfig: Default;
    type HashCreateError: Debug + Display;
    type IDs: Create<Config = Self::IDsConfig,
                     CreateError = Self::IDsCreateError>
        + Iterator<Item = LargeObjID> + Send;
    type IDsConfig: Default + Send;
    type IDsCreateError: Debug + Display;
    type LargeObjWrapper;
    type LargeObjAuthNMsg: AuthNed<Self::MsgPrin>;
    type LargeObjMsgAuth: Create<
            Config = Self::LargeObjMsgAuthConfig,
        > + MsgAuthN<
            LargeObjMsg<Self::HashID>,
            Self::LargeObjWrapper,
            Prin = Self::SessionPrin,
            AuthNMsg = Self::LargeObjAuthNMsg,
            SessionPrin = Self::SessionPrin,
        >;
    type LargeObjMsgAuthConfig: Send;
    type SessionAuth: CreateWithParam<bool,
                                      Config = Self::SessionAuthConfig>
        + SessionAuthN<CompoundFlow<Self::Unix, Self::UDP>,
                       Prin = Self::SessionPrin,
                       AuthNSession = Self::AuthNSession,
                       Param = (),
                       NegotiateError = Self::SessionAuthNError>;
    type SessionAuthConfig: Clone + Send;
    type SessionAuthNError: ScopedError;
    type AuthNSession:
        AuthNedMap<
            Self::SessionPrin,
            CompoundFlow<Self::Unix, Self::UDP>,
            CompoundFarChannelsLargeObjChan<
                Self::Hash,
                Self::Unix,
                Self::UDP,
            >,
            Self::AuthNChan
        > + Session<
            PeerAddr = CompoundFarChannelXfrmPeerAddr,
            LocalAddr = CompoundFarChannelAddr
        > + Read + Write;
    type AuthNChan: Clone
        + AuthNed<Self::SessionPrin>
        + AuthNedDestruct<
            Self::SessionPrin,
            CompoundFarChannelsLargeObjChan<
                Self::Hash,
                Self::Unix,
                Self::UDP,
            >,
        >
        + PushStreamAdd<
            LargeObjMsg<Self::HashID>,
            PollThreadCtx<
                Self::SessionPrin,
                CompoundFarChannels<
                    Self::SessionAuth,
                    Self::AuthNChan,
                    Self::Unix,
                    Self::UDP,
                    LargeObjMsg<Self::HashID>,
                    LargeObjMsg<Self::HashID>,
                    LargeObjMsgCodec<Self::Hash>,
                    LargeObjMsgCodec<Self::Hash>
                >,
                Ctx,
            >,
            BatchID = CodecBatchID,
            AddError = RefCellStreamError<
                CodecStreamError<LargeObjMsgEncodeError, std::io::Error>
            >
        >
        + PushStreamPrivate<
            PollThreadCtx<
                Self::SessionPrin,
                CompoundFarChannels<
                    Self::SessionAuth,
                    Self::AuthNChan,
                    Self::Unix,
                    Self::UDP,
                    LargeObjMsg<Self::HashID>,
                    LargeObjMsg<Self::HashID>,
                    LargeObjMsgCodec<Self::Hash>,
                    LargeObjMsgCodec<Self::Hash>
                >,
                Ctx
            >,
            BatchID = CodecBatchID,
            StartBatchError = RefCellStreamError<Infallible>,
            CancelBatchError = RefCellStreamError<Infallible>,
            FinishBatchError = RefCellStreamError<Infallible>
        > + LargeObjOfferStream<
            Self::HashID,
            PollThreadCtx<
                Self::SessionPrin,
                CompoundFarChannels<
                    Self::SessionAuth,
                    Self::AuthNChan,
                    Self::Unix,
                    Self::UDP,
                    LargeObjMsg<Self::HashID>,
                    LargeObjMsg<Self::HashID>,
                    LargeObjMsgCodec<Self::Hash>,
                    LargeObjMsgCodec<Self::Hash>
                >,
                Ctx
            >,
            Frags = OutboundFrags,
            PushFragError = RefCellStreamError<
                DatagramCodecFragError<
                    CodecStreamError<LargeObjMsgEncodeError, Error>
                >
            >,
            PushOfferError = RefCellStreamError<
                DatagramCodecFragError<
                    CodecStreamError<LargeObjMsgEncodeError, Error>
                >
            >,
        >
        + PullStream<Self::LargeObjWrapper>;
    type MsgAuth: Create<
            Config = Self::MsgAuthConfig,
            CreateError = Self::MsgAuthCreateError
        > + MsgAuthN<
            Self::InMsg,
            Self::Wrapper,
            Prin = Self::MsgPrin,
            AuthNMsg = Self::AuthNMsg,
            SessionPrin = Self::SessionPrin,
            Error = Self::MsgAuthError
        > + Send;
    type MsgAuthError: Debug + Display + ScopedError;
    type MsgAuthConfig: Send;
    type MsgAuthCreateError: Debug + Display;
    type Encoder: Create<Config = Self::EncoderConfig,
                         CreateError = Self::EncoderCreateError>
        + Encoder<Self::OutMsg,
                  EncodeError = Self::EncodeError> + Send;
    type EncoderConfig: Clone + Default + Send;
    type EncodeError: Debug + Display + ScopedError;
    type EncoderCreateError: Debug + Display + ScopedError;
    type Decoder: Create<Config = Self::DecoderConfig,
                         CreateError = Self::DecoderCreateError>
        + Decoder<Self::Wrapper> + Send;
    type DecoderConfig: Clone + Default + Send;
    type DecoderCreateError: Debug + Display + ScopedError;
    type Unix: DatagramXfrmCreate<Addr = UnixSocketPath,
                                  CreateParam = Self::UnixConfig,
                                  Error = Self::UnixError,
                                  PeerAddr = UnixSocketPath,
                                  LocalAddr = UnixSocketPath>;
    type UnixConfig: Clone + Default + Send;
    type UnixError: Debug + Display + ScopedError;
    type UDP: DatagramXfrmCreate<Addr = SocketAddr,
                                 CreateParam = Self::UDPConfig,
                                 Error = Self::UDPError,
                                 PeerAddr = SocketAddr,
                                 LocalAddr = SocketAddr>;
    type UDPConfig: Clone + Default + Send;
    type UDPError: Debug + Display + ScopedError;
    type Epoch: Clone + Debug + Default + Display + Eq + Hash;
    type Epochs: Create<Config = Self::EpochsConfig>
        + Iterator<Item = Self::Epoch>;
    type EpochsConfig: Default + Send;
    type Origin: Clone + Debug + Display + Eq + Hash;
    type Resolver: AddrsCreate<
        PollThreadCtx<
            Self::SessionPrin,
            CompoundFarChannels<
                Self::SessionAuth,
                Self::AuthNChan,
                Self::Unix,
                Self::UDP,
                LargeObjMsg<Self::HashID>,
                LargeObjMsg<Self::HashID>,
                LargeObjMsgCodec<Self::Hash>,
                LargeObjMsgCodec<Self::Hash>
            >,
            Ctx
        >,
        Addr = CompoundFarChannelXfrmPeerAddr,
        Origin = Self::Origin,
        OriginConfig = CompoundFarEndpoint,
        Config = Self::ResolverConfig,
    >;
    type ResolverConfig: Clone + Default + Send;
    type Recv: Clone + AuthNMsgRecv<Self::MsgPrin, Self::AuthNMsg> + Send;
    type Msgs: LargeObjMsgs<Self::Hash, Self::OutMsg> + MsgsWaker + Send;
    type LargeObjTypes: LargeObjProtoTypes<
        Self::InMsg,
        Self::OutMsg,
        Prin = Self::MsgPrin,
        SessionPrin = Self::SessionPrin,
        IDsConfig = Self::IDsConfig,
        IDs = Self::IDs,
        HashID = Self::HashID,
        Hash = Self::Hash,
        Wrapper = Self::Wrapper,
        DecoderConfig = Self::DecoderConfig,
        Decoder = Self::Decoder,
        EncoderConfig = Self::EncoderConfig,
        Encoder = Self::Encoder,
        EncodeError = Self::EncodeError,
        Msgs = Self::Msgs,
        Recv = Self::Recv,
        AuthNMsg = Self::AuthNMsg,
        MsgAuthN = Self::MsgAuth,
        AuthNError = Self::MsgAuthError
    >;
}

pub trait MulticastDatagramBusTypes<Ctx>
where
    Ctx: 'static + NSNameCachesCtx + Send {
    type OutMsg: Clone;
    type InMsg;
    type Wrapper;
    type MsgPrin: Clone + Display + Eq + Hash;
    type SessionPrin: Display + Send + Sync;
    type AuthNMsg: AuthNed<Self::MsgPrin>;
    type SessionAuth: CreateWithParam<bool,
                                      Config = Self::SessionAuthConfig>
        + SessionAuthN<CompoundFlow<Self::Unix, Self::UDP>,
                       Prin = Self::SessionPrin,
                       AuthNSession = Self::AuthNSession,
                       Param = (),
                       NegotiateError = Self::SessionAuthNError>;
    type SessionAuthConfig: Clone + Send;
    type SessionAuthNError: ScopedError;
    type AuthNSession:
        AuthNedMap<
            Self::SessionPrin,
            CompoundFlow<Self::Unix, Self::UDP>,
            CompoundFarChannelsDatagramChan<
                Self::Wrapper,
                Self::OutMsg,
                Self::Unix,
                Self::UDP,
                Self::Encoder,
                Self::Decoder
            >,
            Self::AuthNChan
        > + Session<
            PeerAddr = CompoundFarChannelXfrmPeerAddr,
            LocalAddr = CompoundFarChannelAddr
        > + Read + Write;
    type AuthNChan: Clone
        + AuthNed<Self::SessionPrin>
        + AuthNedDestruct<
            Self::SessionPrin,
            CompoundFarChannelsDatagramChan<
                Self::Wrapper,
                Self::OutMsg,
                Self::Unix,
                Self::UDP,
                Self::Encoder,
                Self::Decoder
            >
        >
        + PushStreamAdd<
            Self::OutMsg,
            PollThreadCtx<
                Self::SessionPrin,
                CompoundFarChannels<
                    Self::SessionAuth,
                    Self::AuthNChan,
                    Self::Unix,
                    Self::UDP,
                    Self::OutMsg,
                    Self::Wrapper,
                    Self::Encoder,
                    Self::Decoder
                >,
                Ctx,
            >,
            BatchID = CodecBatchID,
            AddError = RefCellStreamError<
                CodecStreamError<Self::EncodeError, std::io::Error>
            >
        >
        + PushStreamPrivate<
            PollThreadCtx<
                Self::SessionPrin,
                CompoundFarChannels<
                    Self::SessionAuth,
                    Self::AuthNChan,
                    Self::Unix,
                    Self::UDP,
                    Self::OutMsg,
                    Self::Wrapper,
                    Self::Encoder,
                    Self::Decoder
                >,
                Ctx
            >,
            SelectError = RefCellStreamError<Infallible>,
            CreateBatchError = RefCellStreamError<Infallible>,
            StartBatchError = RefCellStreamError<Infallible>,
            CancelBatchError = RefCellStreamError<Infallible>,
            FinishBatchError = RefCellStreamError<Infallible>
        >
        + PullStream<Self::Wrapper>;
    type MsgAuth: Create<
            Config = Self::MsgAuthConfig,
        > + MsgAuthN<
            Self::InMsg,
            Self::Wrapper,
            Prin = Self::MsgPrin,
            AuthNMsg = Self::AuthNMsg,
            SessionPrin = Self::SessionPrin,
        >;
    type MsgAuthConfig: Send;
    type Encoder: Create<Config = Self::EncoderConfig,
                     CreateError = Self::EncoderCreateError>
        + Encoder<Self::OutMsg>;
    type EncoderConfig: Clone + Default + Send;
    type EncodeError: Debug + Display + ScopedError;
    type EncoderCreateError: Debug + Display + ScopedError;
    type Decoder: Create<Config = Self::DecoderConfig,
                     CreateError = Self::DecoderCreateError>
        + Decoder<Self::Wrapper>;
    type DecoderConfig: Clone + Default + Send;
    type DecoderCreateError: Debug + Display + ScopedError;
    type Unix: DatagramXfrmCreate<Addr = UnixSocketPath,
                                  CreateParam = Self::UnixConfig,
                                  Error = Self::UnixError,
                                  PeerAddr = UnixSocketPath,
                                  LocalAddr = UnixSocketPath>;
    type UnixConfig: Clone + Default + Send;
    type UnixError: Debug + Display + ScopedError;
    type UDP: DatagramXfrmCreate<Addr = SocketAddr,
                                 CreateParam = Self::UDPConfig,
                                 Error = Self::UDPError,
                                 PeerAddr = SocketAddr,
                                 LocalAddr = SocketAddr>;
    type UDPConfig: Clone + Default + Send;
    type UDPError: Debug + Display + ScopedError;
    type Epoch: Clone + Debug + Default + Display + Eq + Hash;
    type Epochs: Create<Config = Self::EpochsConfig>
        + Iterator<Item = Self::Epoch>;
    type EpochsConfig: Default + Send;
    type Origin: Clone + Debug + Display + Eq + Hash;
    type Resolver: AddrsCreate<
        PollThreadCtx<
            Self::SessionPrin,
            CompoundFarChannels<
                Self::SessionAuth,
                Self::AuthNChan,
                Self::Unix,
                Self::UDP,
                Self::OutMsg,
                Self::Wrapper,
                Self::Encoder,
                Self::Decoder
            >,
            Ctx
        >,
        Addr = CompoundFarChannelXfrmPeerAddr,
        Origin = Self::Origin,
        OriginConfig = CompoundFarEndpoint,
        Config = Self::ResolverConfig,
    >;
    type ResolverConfig: Clone + Default + Send;
    type Recv: AuthNMsgRecv<Self::MsgPrin, Self::AuthNMsg> + Send;
    type Msgs: SharedMsgs<MulticastStreamIdx, Self::OutMsg> + MsgsWaker + Send;
}

pub trait MulticastLargeObjBusTypes<Ctx>
where
    Ctx: 'static + NSNameCachesCtx + Send {
    type OutMsg: Clone + Send;
    type InMsg: Send;
    type Wrapper;
    type MsgPrin: Clone + Debug + Display + Eq + Hash;
    type SessionPrin: Clone + Debug + Display + Eq + Hash + Send + Sync;
    type AuthNMsg: AuthNed<Self::MsgPrin>;
    type Hash: Clone + Default
        + Create<Config = Self::HashConfig,
                 CreateError = Self::HashCreateError>
        + HashAlgo<HashID = Self::HashID> + Send;
    type HashID: Clone + Debug + Display + Eq + Hash + HashID + Send;
    type HashConfig: Default;
    type HashCreateError: Debug + Display;
    type IDs: Create<Config = Self::IDsConfig,
                     CreateError = Self::IDsCreateError>
        + Iterator<Item = LargeObjID> + Send;
    type IDsConfig: Default + Send;
    type IDsCreateError: Debug + Display;
    type LargeObjWrapper;
    type LargeObjAuthNMsg: AuthNed<Self::MsgPrin>;
    type LargeObjMsgAuth: Create<
            Config = Self::LargeObjMsgAuthConfig,
        > + MsgAuthN<
            LargeObjMsg<Self::HashID>,
            Self::LargeObjWrapper,
            Prin = Self::SessionPrin,
            AuthNMsg = Self::LargeObjAuthNMsg,
            SessionPrin = Self::SessionPrin,
        >;
    type LargeObjMsgAuthConfig: Send;
    type SessionAuth: CreateWithParam<bool,
                                      Config = Self::SessionAuthConfig>
        + SessionAuthN<CompoundFlow<Self::Unix, Self::UDP>,
                       Prin = Self::SessionPrin,
                       AuthNSession = Self::AuthNSession,
                       Param = (),
                       NegotiateError = Self::SessionAuthNError>;
    type SessionAuthConfig: Clone + Send;
    type SessionAuthNError: ScopedError;
    type AuthNSession:
        AuthNedMap<
            Self::SessionPrin,
            CompoundFlow<Self::Unix, Self::UDP>,
            CompoundFarChannelsLargeObjChan<
                Self::Hash,
                Self::Unix,
                Self::UDP,
            >,
            Self::AuthNChan
        > + Session<
            PeerAddr = CompoundFarChannelXfrmPeerAddr,
            LocalAddr = CompoundFarChannelAddr
        > + Read + Write;
    type AuthNChan: Clone
        + AuthNed<Self::SessionPrin>
        + AuthNedDestruct<
            Self::SessionPrin,
            CompoundFarChannelsLargeObjChan<
                Self::Hash,
                Self::Unix,
                Self::UDP,
            >,
        >
        + PushStreamAdd<
            LargeObjMsg<Self::HashID>,
            PollThreadCtx<
                Self::SessionPrin,
                CompoundFarChannels<
                    Self::SessionAuth,
                    Self::AuthNChan,
                    Self::Unix,
                    Self::UDP,
                    LargeObjMsg<Self::HashID>,
                    LargeObjMsg<Self::HashID>,
                    LargeObjMsgCodec<Self::Hash>,
                    LargeObjMsgCodec<Self::Hash>
                >,
                Ctx,
            >,
            BatchID = CodecBatchID,
            AddError = RefCellStreamError<
                CodecStreamError<LargeObjMsgEncodeError, std::io::Error>
            >
        >
        + PushStreamPrivate<
            PollThreadCtx<
                Self::SessionPrin,
                CompoundFarChannels<
                    Self::SessionAuth,
                    Self::AuthNChan,
                    Self::Unix,
                    Self::UDP,
                    LargeObjMsg<Self::HashID>,
                    LargeObjMsg<Self::HashID>,
                    LargeObjMsgCodec<Self::Hash>,
                    LargeObjMsgCodec<Self::Hash>
                >,
                Ctx
            >,
            BatchID = CodecBatchID,
            SelectError = RefCellStreamError<Infallible>,
            CreateBatchError = RefCellStreamError<Infallible>,
            StartBatchError = RefCellStreamError<Infallible>,
            CancelBatchError = RefCellStreamError<Infallible>,
            FinishBatchError = RefCellStreamError<Infallible>
        > + LargeObjOfferStream<
            Self::HashID,
            PollThreadCtx<
                Self::SessionPrin,
                CompoundFarChannels<
                    Self::SessionAuth,
                    Self::AuthNChan,
                    Self::Unix,
                    Self::UDP,
                    LargeObjMsg<Self::HashID>,
                    LargeObjMsg<Self::HashID>,
                    LargeObjMsgCodec<Self::Hash>,
                    LargeObjMsgCodec<Self::Hash>
                >,
                Ctx
            >,
            Frags = OutboundFrags,
            PushFragError = RefCellStreamError<
                DatagramCodecFragError<
                    CodecStreamError<LargeObjMsgEncodeError, Error>
                >
            >,
            PushOfferError = RefCellStreamError<
                DatagramCodecFragError<
                    CodecStreamError<LargeObjMsgEncodeError, Error>
                >
            >,
        >
        + PullStream<Self::LargeObjWrapper>;
    type MsgAuth: Create<
            Config = Self::MsgAuthConfig,
            CreateError = Self::MsgAuthCreateError
        > + MsgAuthN<
            Self::InMsg,
            Self::Wrapper,
            Prin = Self::MsgPrin,
            AuthNMsg = Self::AuthNMsg,
            SessionPrin = Self::SessionPrin,
            Error = Self::MsgAuthError
        > + Send;
    type MsgAuthError: Debug + Display + ScopedError;
    type MsgAuthConfig: Send;
    type MsgAuthCreateError: Debug + Display;
    type Encoder: Create<Config = Self::EncoderConfig,
                         CreateError = Self::EncoderCreateError>
        + Encoder<Self::OutMsg,
                  EncodeError = Self::EncodeError> + Send;
    type EncoderConfig: Clone + Default + Send;
    type EncodeError: Debug + Display + ScopedError;
    type EncoderCreateError: Debug + Display + ScopedError;
    type Decoder: Create<Config = Self::DecoderConfig,
                         CreateError = Self::DecoderCreateError>
        + Decoder<Self::Wrapper> + Send;
    type DecoderConfig: Clone + Default + Send;
    type DecoderCreateError: Debug + Display + ScopedError;
    type Unix: DatagramXfrmCreate<Addr = UnixSocketPath,
                                  CreateParam = Self::UnixConfig,
                                  Error = Self::UnixError,
                                  PeerAddr = UnixSocketPath,
                                  LocalAddr = UnixSocketPath>;
    type UnixConfig: Clone + Default + Send;
    type UnixError: Debug + Display + ScopedError;
    type UDP: DatagramXfrmCreate<Addr = SocketAddr,
                                 CreateParam = Self::UDPConfig,
                                 Error = Self::UDPError,
                                 PeerAddr = SocketAddr,
                                 LocalAddr = SocketAddr>;
    type UDPConfig: Clone + Default + Send;
    type UDPError: Debug + Display + ScopedError;
    type Epoch: Clone + Debug + Default + Display + Eq + Hash;
    type Epochs: Create<Config = Self::EpochsConfig>
        + Iterator<Item = Self::Epoch>;
    type EpochsConfig: Default + Send;
    type Origin: Clone + Debug + Display + Eq + Hash + Send;
    type Resolver: AddrsCreate<
        PollThreadCtx<
            Self::SessionPrin,
            CompoundFarChannels<
                Self::SessionAuth,
                Self::AuthNChan,
                Self::Unix,
                Self::UDP,
                LargeObjMsg<Self::HashID>,
                LargeObjMsg<Self::HashID>,
                LargeObjMsgCodec<Self::Hash>,
                LargeObjMsgCodec<Self::Hash>
            >,
            Ctx
        >,
        Addr = CompoundFarChannelXfrmPeerAddr,
        Origin = Self::Origin,
        OriginConfig = CompoundFarEndpoint,
        Config = Self::ResolverConfig,
    >;
    type ResolverConfig: Clone + Default + Send;
    type Recv: Clone + AuthNMsgRecv<Self::MsgPrin, Self::AuthNMsg> + Send;
    type Msgs: LargeObjMsgs<Self::Hash, Self::OutMsg> + MsgsWaker + Send;
    type LargeObjTypes: LargeObjProtoTypes<
        Self::InMsg,
        Self::OutMsg,
        Prin = Self::MsgPrin,
        SessionPrin = Self::SessionPrin,
        IDsConfig = Self::IDsConfig,
        IDs = Self::IDs,
        HashID = Self::HashID,
        Hash = Self::Hash,
        Wrapper = Self::Wrapper,
        DecoderConfig = Self::DecoderConfig,
        Decoder = Self::Decoder,
        EncoderConfig = Self::EncoderConfig,
        Encoder = Self::Encoder,
        EncodeError = Self::EncodeError,
        Msgs = Self::Msgs,
        Recv = Self::Recv,
        AuthNMsg = Self::AuthNMsg,
        MsgAuthN = Self::MsgAuth,
        AuthNError = Self::MsgAuthError
    > + Send;
}
