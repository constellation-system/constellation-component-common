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

use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;
use std::hash::Hash;
use std::marker::PhantomData;
use std::thread::JoinHandle;

use constellation_auth::authn::AuthNMsgRecv;
use constellation_auth::authn::MsgAuthN;
use constellation_auth::authn::PassthruMsgAuthN;
use constellation_auth::authn::SessionAuthN;
use constellation_channels::config::ResolverConfig;
use constellation_channels::far::flows::OwnedFlowNegotiator;
use constellation_channels::far::flows::OwnedFlowsCreate;
use constellation_channels::far::flows::ThreadedFlowsListener;
use constellation_channels::far::flows::ThreadedFlowsPullStreamListener;
use constellation_channels::far::registry::FarChannelRegistryAcquireError;
use constellation_channels::far::registry::FarChannelRegistryCtx;
use constellation_channels::far::registry::RegistryAcquireError;
use constellation_channels::far::FarChannelAcquired;
use constellation_channels::far::FarChannelAcquiredResolve;
use constellation_channels::far::FarChannelCreate;
use constellation_channels::far::FarChannelFlowsError;
use constellation_channels::far::FarChannelOwnedFlows;
use constellation_channels::resolve::cache::NSNameCachesCtx;
use constellation_common::codec::DatagramCodec;
use constellation_common::hashid::HashAlgo;
use constellation_common::ids::IDGen;
use constellation_common::net::DatagramXfrm;
use constellation_common::net::DatagramXfrmCreate;
use constellation_common::net::IPEndpointAddr;
use constellation_common::net::PrivateMsgs;
use constellation_common::net::Socket;
use constellation_common::sched::RefreshError;
use constellation_common::shutdown::ShutdownFlag;
use constellation_common::sync::Notify;
use constellation_streams::addrs::Addrs;
use constellation_streams::addrs::AddrsCreate;
use constellation_streams::channels::ChannelParam;
use constellation_streams::codec::DatagramCodecStream;
use constellation_streams::config::DispatchConfig;
use constellation_streams::frags::OutboundFrags;
use constellation_streams::large_obj::LargeObjID;
use constellation_streams::large_obj::LargeObjMsg;
use constellation_streams::large_obj::LargeObjMsgCodec;
use constellation_streams::large_obj::LargeObjProto;
use constellation_streams::select::dispatch::DispatchSelector;
use constellation_streams::stream::ConcurrentStream;
use constellation_streams::stream::StreamID;
use constellation_streams::stream::ThreadedStream;
use constellation_streams::threads::dispatch::Dispatch;
use constellation_streams::threads::dispatch::DispatchEntryReporter;
use constellation_streams::threads::dispatch::Dispatched;
use constellation_streams::threads::dispatch::PullStreamsDispatchThread;
use constellation_streams::threads::push::private::PrivateLargeObjPushMode;
use log::debug;
use log::error;

use crate::config::DispatchLargeObjBusConfig;

pub trait SessionDispatch<Msg, Msgs, Prin, Recv>
where
    Msgs: PrivateMsgs<Msg> + Send,
    Recv: AuthNMsgRecv<Prin, Msg> {
    type SessionError: Display;

    fn session(
        &self,
        prin: Prin
    ) -> Result<(ShutdownFlag, Msgs, Notify, Recv), Self::SessionError>;
}

/// Type of errors that can occur when creating a [DispatchLargeObjBus].
#[derive(Debug)]
pub enum DispatchError<Session> {
    /// Error acquiring session.
    Session {
        /// The error that occurred while acquiring the session.
        err: Session
    },
    /// Error while creating [DispatchSelector]s.
    Stream {
        /// The error that occurred while creating [StreamSelector]s.
        err: RefreshError
    }
}

/// Type of errors that can occur when creating a [DispatchLargeObjBus].
#[derive(Debug)]
pub enum DispatchLargeObjBusCreateError<MsgCodec, Acquire> {
    /// Error while creating message codecs.
    MsgCodec {
        /// The error that occurred while creating message codecs.
        err: MsgCodec
    },
    Acquire {
        err: Acquire
    }
}

/// Cleanup object for [UnicastComm].
pub struct DispatchLargeObjBusCleanup {
    pull_join: JoinHandle<()>
}

pub struct DispatchLargeObjBus<
    Msg,
    Wrapper,
    WrapperCodec,
    H,
    IDs,
    MsgAuth,
    Recv,
    Epochs,
    Channel,
    F,
    SessionAuth,
    Xfrm,
    Resolver,
    Endpoint,
    Session,
    Ctx
> where
    Msg: 'static + Clone + Send,
    Wrapper: 'static + Clone + Send,
    MsgAuth: 'static
        + Clone
        + MsgAuthN<Msg, Wrapper, SessionPrin = SessionAuth::Prin>
        + Send,
    MsgAuth::SessionPrin: Send + Sync,
    IDs: 'static + Clone + IDGen + Iterator<Item = LargeObjID> + Send,
    H: 'static + Clone + Default + HashAlgo + Send,
    H::HashID: 'static + Clone + Display + Hash + Eq + Send,
    SessionAuth: 'static
        + Clone
        + SessionAuthN<<Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow>
        + Send
        + Sync,
    SessionAuth::Prin: 'static + Clone + Display + Eq + Hash + Send,
    WrapperCodec: 'static + Clone + DatagramCodec<Wrapper> + Send,
    <WrapperCodec as DatagramCodec<Wrapper>>::Param: Default,
    Recv: 'static + AuthNMsgRecv<MsgAuth::Prin, Msg> + Clone + Send,
    Epochs: 'static + IDGen + Iterator<Item = u128> + Send + Sync,
    Epochs::Config: Clone + Send,
    Channel: 'static
        + FarChannelOwnedFlows<F, SessionAuth, Xfrm>
        + FarChannelCreate
        + Send
        + Sync,
    Channel::Acquired: FarChannelAcquiredResolve<Resolved = Channel::Param>,
    Channel::Param: Clone
        + Display
        + Eq
        + Hash
        + PartialEq
        + ChannelParam<<Channel::Xfrm as DatagramXfrm>::PeerAddr>
        + Send
        + Sync,
    Channel::Acquired:
        FarChannelAcquiredResolve<Resolved = Channel::Param> + Send + Sync,
    <Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow:
        'static + ConcurrentStream + Send,
    <Channel::Xfrm as DatagramXfrm>::PeerAddr:
        'static + Eq + Hash + Send + Sync,
    F: OwnedFlowsCreate<
            Channel::Socket,
            Channel::Nego,
            SessionAuth,
            Channel::Xfrm
        > + Send,
    F::Flow: 'static + ConcurrentStream + Send,
    F::CreateParam: Clone + Default + Send + Sync,
    F::Reporter: Clone + Send + Sync,
    F::ChannelID: 'static + From<usize> + Into<usize> + Send + Sync,
    Xfrm:
        DatagramXfrm + DatagramXfrmCreate<Addr = Channel::Param> + Send + Sync,
    Xfrm::CreateParam: Clone + Default + Send + Sync,
    Xfrm::LocalAddr: From<<Channel::Socket as Socket>::Addr>,
    Resolver: Addrs<Addr = <Channel::Xfrm as DatagramXfrm>::PeerAddr>
        + AddrsCreate<Ctx, Vec<Endpoint>, Config = ResolverConfig>
        + Send
        + Sync,
    Resolver::Origin:
        Clone + Eq + Hash + Into<Option<IPEndpointAddr>> + Send + Sync,
    Endpoint: Send,
    Session: 'static
        + SessionDispatch<
            LargeObjMsg<H::HashID>,
            LargeObjProto<
                H::HashID,
                Msg,
                Wrapper,
                MsgAuth,
                (),
                WrapperCodec,
                IDs,
                Recv,
                OutboundFrags
            >,
            SessionAuth::Prin,
            LargeObjProto<
                H::HashID,
                Msg,
                Wrapper,
                MsgAuth,
                (),
                WrapperCodec,
                IDs,
                Recv,
                OutboundFrags
            >
        >
        + Send,
    Ctx: 'static
        + Clone
        + FarChannelRegistryCtx<Channel, F, SessionAuth, Xfrm>
        + NSNameCachesCtx
        + Send
        + Sync {
    pull: PullStreamsDispatchThread<
        LargeObjMsg<H::HashID>,
        PassthruMsgAuthN<LargeObjMsg<H::HashID>, SessionAuth::Prin>,
        Dispatcher<
            Msg,
            Wrapper,
            WrapperCodec,
            H,
            IDs,
            MsgAuth,
            Recv,
            Epochs,
            Channel,
            F,
            SessionAuth,
            Xfrm,
            Resolver,
            Endpoint,
            Session,
            Ctx
        >,
        ThreadedFlowsPullStreamListener<
            <Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow,
            LargeObjMsg<H::HashID>,
            LargeObjMsgCodec<H>,
            StreamID<
                <Channel::Xfrm as DatagramXfrm>::PeerAddr,
                F::ChannelID,
                Channel::Param
            >,
            SessionAuth::Prin
        >,
        PrivateLargeObjPushMode<
            H::HashID,
            DispatchSelector<
                Epochs,
                StreamID<
                    <Channel::Xfrm as DatagramXfrm>::PeerAddr,
                    F::ChannelID,
                    Channel::Param
                >,
                ThreadedStream<
                    DatagramCodecStream<
                        LargeObjMsg<H::HashID>,
                        <Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow,
                        LargeObjMsgCodec<H>
                    >
                >,
                DispatchEntryReporter<
                    LargeObjMsg<H::HashID>,
                    StreamID<
                        <Channel::Xfrm as DatagramXfrm>::PeerAddr,
                        F::ChannelID,
                        Channel::Param
                    >,
                    DatagramCodecStream<
                        LargeObjMsg<H::HashID>,
                        <Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow,
                        LargeObjMsgCodec<H>
                    >,
                    PassthruMsgAuthN<LargeObjMsg<H::HashID>, SessionAuth::Prin>,
                    LargeObjProto<
                        H::HashID,
                        Msg,
                        Wrapper,
                        MsgAuth,
                        (),
                        WrapperCodec,
                        IDs,
                        Recv,
                        OutboundFrags
                    >
                >,
                Ctx
            >,
            Ctx
        >,
        Ctx
    >
}

struct Dispatcher<
    Msg,
    Wrapper,
    WrapperCodec,
    H,
    IDs,
    MsgAuth,
    Recv,
    Epochs,
    Channel,
    F,
    SessionAuth,
    Xfrm,
    Resolver,
    Endpoint,
    Session,
    Ctx
> where
    Msg: 'static + Clone + Send,
    Wrapper: 'static + Clone + Send,
    MsgAuth: 'static
        + Clone
        + MsgAuthN<Msg, Wrapper, SessionPrin = SessionAuth::Prin>
        + Send,
    MsgAuth::SessionPrin: Send + Sync,
    IDs: 'static + Clone + IDGen + Iterator<Item = LargeObjID> + Send,
    H: 'static + Clone + Default + HashAlgo + Send,
    H::HashID: 'static + Clone + Display + Hash + Eq + Send,
    SessionAuth: 'static
        + Clone
        + SessionAuthN<<Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow>
        + Send
        + Sync,
    SessionAuth::Prin: 'static + Clone + Display + Eq + Hash + Send,
    WrapperCodec: 'static + Clone + DatagramCodec<Wrapper> + Send,
    <WrapperCodec as DatagramCodec<Wrapper>>::Param: Default,
    Recv: 'static + AuthNMsgRecv<MsgAuth::Prin, Msg> + Clone + Send,
    Epochs: 'static + IDGen + Iterator<Item = u128> + Send + Sync,
    Channel: 'static
        + FarChannelOwnedFlows<F, SessionAuth, Xfrm>
        + FarChannelCreate
        + Send
        + Sync,
    Channel::Acquired: FarChannelAcquiredResolve<Resolved = Channel::Param>,
    Channel::Param: Clone
        + Display
        + Eq
        + Hash
        + PartialEq
        + ChannelParam<<Channel::Xfrm as DatagramXfrm>::PeerAddr>
        + Send
        + Sync,
    Channel::Acquired:
        FarChannelAcquiredResolve<Resolved = Channel::Param> + Send + Sync,
    <Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow:
        'static + ConcurrentStream + Send,
    <Channel::Xfrm as DatagramXfrm>::PeerAddr:
        'static + Eq + Hash + Send + Sync,
    F: OwnedFlowsCreate<
            Channel::Socket,
            Channel::Nego,
            SessionAuth,
            Channel::Xfrm
        > + Send,
    F::Flow: 'static + ConcurrentStream + Send,
    F::CreateParam: Clone + Default + Send + Sync,
    F::Reporter: Clone + Send + Sync,
    F::ChannelID: 'static + From<usize> + Into<usize> + Send + Sync,
    Xfrm:
        DatagramXfrm + DatagramXfrmCreate<Addr = Channel::Param> + Send + Sync,
    Xfrm::CreateParam: Clone + Default + Send + Sync,
    Xfrm::LocalAddr: From<<Channel::Socket as Socket>::Addr>,
    Resolver: Addrs<Addr = <Channel::Xfrm as DatagramXfrm>::PeerAddr>
        + AddrsCreate<Ctx, Vec<Endpoint>, Config = ResolverConfig>
        + Send
        + Sync,
    Resolver::Origin:
        Clone + Eq + Hash + Into<Option<IPEndpointAddr>> + Send + Sync,
    Endpoint: Send,
    Session: SessionDispatch<
            LargeObjMsg<H::HashID>,
            LargeObjProto<
                H::HashID,
                Msg,
                Wrapper,
                MsgAuth,
                (),
                WrapperCodec,
                IDs,
                Recv,
                OutboundFrags
            >,
            SessionAuth::Prin,
            LargeObjProto<
                H::HashID,
                Msg,
                Wrapper,
                MsgAuth,
                (),
                WrapperCodec,
                IDs,
                Recv,
                OutboundFrags
            >
        > + Send,
    Ctx: FarChannelRegistryCtx<Channel, F, SessionAuth, Xfrm>
        + NSNameCachesCtx
        + Send
        + Sync {
    msg: PhantomData<Msg>,
    wrapper: PhantomData<Wrapper>,
    ids: PhantomData<IDs>,
    hash: PhantomData<H>,
    msg_auth: PhantomData<MsgAuth>,
    codec: PhantomData<WrapperCodec>,
    recv: PhantomData<Recv>,
    channel: PhantomData<Channel>,
    flows: PhantomData<F>,
    session_auth: PhantomData<SessionAuth>,
    xfrm: PhantomData<Xfrm>,
    resolver: PhantomData<Resolver>,
    endpoint: PhantomData<Endpoint>,
    ctx: PhantomData<Ctx>,
    session: Session,
    config: DispatchConfig<Epochs::Config>
}

impl<
        Msg,
        Wrapper,
        WrapperCodec,
        H,
        IDs,
        MsgAuth,
        Recv,
        Epochs,
        Channel,
        F,
        SessionAuth,
        Xfrm,
        Resolver,
        Endpoint,
        Session,
        Ctx
    >
    DispatchLargeObjBus<
        Msg,
        Wrapper,
        WrapperCodec,
        H,
        IDs,
        MsgAuth,
        Recv,
        Epochs,
        Channel,
        F,
        SessionAuth,
        Xfrm,
        Resolver,
        Endpoint,
        Session,
        Ctx
    >
where
    Msg: 'static + Clone + Send,
    Wrapper: 'static + Clone + Send,
    MsgAuth: 'static
        + Clone
        + MsgAuthN<Msg, Wrapper, SessionPrin = SessionAuth::Prin>
        + Send,
    MsgAuth::SessionPrin: Send + Sync,
    IDs: 'static + Clone + IDGen + Iterator<Item = LargeObjID> + Send,
    H: 'static + Clone + Default + HashAlgo + Send,
    H::HashID: 'static + Clone + Display + Hash + Eq + Send,
    SessionAuth: 'static
        + Clone
        + SessionAuthN<<Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow>
        + Send
        + Sync,
    SessionAuth::Prin: 'static + Clone + Display + Eq + Hash + Send,
    WrapperCodec: 'static + Clone + DatagramCodec<Wrapper> + Send,
    <WrapperCodec as DatagramCodec<Wrapper>>::Param: Default,
    Recv: 'static + AuthNMsgRecv<MsgAuth::Prin, Msg> + Clone + Send,
    Epochs: 'static + IDGen + Iterator<Item = u128> + Send + Sync,
    Epochs::Config: Clone + Send,
    Channel: 'static
        + FarChannelOwnedFlows<F, SessionAuth, Xfrm>
        + FarChannelCreate
        + Send
        + Sync,
    Channel::Acquired: FarChannelAcquiredResolve<Resolved = Channel::Param>,
    Channel::Param: Clone
        + Display
        + Eq
        + Hash
        + PartialEq
        + ChannelParam<<Channel::Xfrm as DatagramXfrm>::PeerAddr>
        + Send
        + Sync,
    Channel::Acquired:
        FarChannelAcquiredResolve<Resolved = Channel::Param> + Send + Sync,
    <Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow:
        'static + ConcurrentStream + Send,
    <Channel::Xfrm as DatagramXfrm>::PeerAddr:
        'static + Eq + Hash + Send + Sync,
    F: 'static
        + OwnedFlowsCreate<
            Channel::Socket,
            Channel::Nego,
            SessionAuth,
            Channel::Xfrm
        >
        + Send,
    F::Flow: 'static + ConcurrentStream + Send,
    F::CreateParam: Clone + Default + Send + Sync,
    F::Reporter: Clone + Send + Sync,
    F::ChannelID: 'static + From<usize> + Into<usize> + Send + Sync,
    Xfrm: 'static
        + DatagramXfrm
        + DatagramXfrmCreate<Addr = Channel::Param>
        + Send
        + Sync,
    Xfrm::CreateParam: Clone + Default + Send + Sync,
    Xfrm::LocalAddr: From<<Channel::Socket as Socket>::Addr>,
    Resolver: 'static
        + Addrs<Addr = <Channel::Xfrm as DatagramXfrm>::PeerAddr>
        + AddrsCreate<Ctx, Vec<Endpoint>, Config = ResolverConfig>
        + Send
        + Sync,
    Resolver::Origin:
        Clone + Eq + Hash + Into<Option<IPEndpointAddr>> + Send + Sync,
    Endpoint: 'static + Send,
    Session: 'static
        + SessionDispatch<
            LargeObjMsg<H::HashID>,
            LargeObjProto<
                H::HashID,
                Msg,
                Wrapper,
                MsgAuth,
                (),
                WrapperCodec,
                IDs,
                Recv,
                OutboundFrags
            >,
            SessionAuth::Prin,
            LargeObjProto<
                H::HashID,
                Msg,
                Wrapper,
                MsgAuth,
                (),
                WrapperCodec,
                IDs,
                Recv,
                OutboundFrags
            >
        >
        + Send,
    Ctx: 'static
        + Clone
        + FarChannelRegistryCtx<Channel, F, SessionAuth, Xfrm>
        + NSNameCachesCtx
        + Send
        + Sync
{
    pub fn create(
        config: DispatchLargeObjBusConfig<Epochs::Config>,
        session: Session,
        listener: ThreadedFlowsListener<
            <Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow,
            StreamID<
                <Channel::Xfrm as DatagramXfrm>::PeerAddr,
                F::ChannelID,
                Channel::Param
            >,
            SessionAuth::Prin
        >,
        shutdown: ShutdownFlag,
        mut ctx: Ctx
    ) -> Result<
        Self,
        DispatchLargeObjBusCreateError<
            <LargeObjMsgCodec<H> as DatagramCodec<LargeObjMsg<H::HashID>>>::CreateError,
            FarChannelRegistryAcquireError<
                RegistryAcquireError<
                    Channel::AcquireError,
                    <Channel::Acquired as FarChannelAcquiredResolve>::ResolverError,
                    FarChannelFlowsError<
                        Channel::SocketError,
                        F::CreateError,
                        Channel::XfrmError
                    >,
                    <Channel::Acquired as FarChannelAcquired>::WrapError
                >
            >
        >
    >{
        let (size_hint, dispatch_config, mode_config) = config.take();

        debug!(target: "multicast-comm",
               "initializing channels");

        // Bring up all channels.
        ctx.far_channel_registry()
            .acquire_all(&mut ctx)
            .map_err(|err| DispatchLargeObjBusCreateError::Acquire {
                err: err
            })?;

        let dispatcher = Dispatcher {
            ids: PhantomData,
            msg: PhantomData,
            hash: PhantomData,
            codec: PhantomData,
            wrapper: PhantomData,
            recv: PhantomData,
            channel: PhantomData,
            flows: PhantomData,
            session_auth: PhantomData,
            msg_auth: PhantomData,
            xfrm: PhantomData,
            resolver: PhantomData,
            endpoint: PhantomData,
            ctx: PhantomData,
            session: session,
            config: dispatch_config
        };
        // ISSUE #1: get the codec config properly
        let msg_codec = LargeObjMsgCodec::create(()).map_err(|err| {
            DispatchLargeObjBusCreateError::MsgCodec { err: err }
        })?;
        let listener =
            ThreadedFlowsPullStreamListener::create(listener, msg_codec);
        let pull = match size_hint {
            Some(size_hint) => PullStreamsDispatchThread::with_capacity(
                mode_config,
                dispatcher,
                listener,
                shutdown,
                ctx,
                size_hint
            ),
            None => PullStreamsDispatchThread::new(
                mode_config,
                dispatcher,
                listener,
                shutdown,
                ctx
            )
        };

        Ok(DispatchLargeObjBus { pull: pull })
    }

    /// Consume this `DispatchLargeObjBus`, start the threads, and return a
    /// cleanup object.
    pub fn start(self) -> DispatchLargeObjBusCleanup {
        let DispatchLargeObjBus { pull } = self;
        let pull_join = pull.start();

        DispatchLargeObjBusCleanup {
            pull_join: pull_join
        }
    }
}

impl<
        Msg,
        Wrapper,
        WrapperCodec,
        H,
        IDs,
        MsgAuth,
        Recv,
        Epochs,
        Channel,
        F,
        SessionAuth,
        Xfrm,
        Resolver,
        Endpoint,
        Session,
        Ctx
    >
    Dispatch<
        LargeObjMsg<H::HashID>,
        StreamID<
            <Channel::Xfrm as DatagramXfrm>::PeerAddr,
            F::ChannelID,
            Channel::Param
        >,
        DatagramCodecStream<
            LargeObjMsg<H::HashID>,
            <Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow,
            LargeObjMsgCodec<H>
        >,
        PassthruMsgAuthN<LargeObjMsg<H::HashID>, SessionAuth::Prin>,
        Ctx
    >
    for Dispatcher<
        Msg,
        Wrapper,
        WrapperCodec,
        H,
        IDs,
        MsgAuth,
        Recv,
        Epochs,
        Channel,
        F,
        SessionAuth,
        Xfrm,
        Resolver,
        Endpoint,
        Session,
        Ctx
    >
where
    Msg: 'static + Clone + Send,
    Wrapper: 'static + Clone + Send,
    MsgAuth: 'static
        + Clone
        + MsgAuthN<Msg, Wrapper, SessionPrin = SessionAuth::Prin>
        + Send,
    MsgAuth::SessionPrin: Send + Sync,
    IDs: 'static + Clone + IDGen + Iterator<Item = LargeObjID> + Send,
    H: 'static + Clone + Default + HashAlgo + Send,
    H::HashID: 'static + Clone + Display + Hash + Eq + Send,
    SessionAuth: 'static
        + Clone
        + SessionAuthN<<Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow>
        + Send
        + Sync,
    SessionAuth::Prin: 'static + Clone + Display + Eq + Hash + Send,
    WrapperCodec: 'static + Clone + DatagramCodec<Wrapper> + Send,
    <WrapperCodec as DatagramCodec<Wrapper>>::Param: Default,
    Recv: 'static + AuthNMsgRecv<MsgAuth::Prin, Msg> + Clone + Send,
    Epochs: 'static + IDGen + Iterator<Item = u128> + Send + Sync,
    Epochs::Config: Clone,
    Channel: 'static
        + FarChannelOwnedFlows<F, SessionAuth, Xfrm>
        + FarChannelCreate
        + Send
        + Sync,
    Channel::Acquired: FarChannelAcquiredResolve<Resolved = Channel::Param>,
    Channel::Param: Clone
        + Display
        + Eq
        + Hash
        + PartialEq
        + ChannelParam<<Channel::Xfrm as DatagramXfrm>::PeerAddr>
        + Send
        + Sync,
    Channel::Acquired:
        FarChannelAcquiredResolve<Resolved = Channel::Param> + Send + Sync,
    <Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow:
        'static + ConcurrentStream + Send,
    <Channel::Xfrm as DatagramXfrm>::PeerAddr:
        'static + Eq + Hash + Send + Sync,
    F: OwnedFlowsCreate<
            Channel::Socket,
            Channel::Nego,
            SessionAuth,
            Channel::Xfrm
        > + Send,
    F::Flow: 'static + ConcurrentStream + Send,
    F::CreateParam: Clone + Default + Send + Sync,
    F::Reporter: Clone + Send + Sync,
    F::ChannelID: 'static + From<usize> + Into<usize> + Send + Sync,
    Xfrm:
        DatagramXfrm + DatagramXfrmCreate<Addr = Channel::Param> + Send + Sync,
    Xfrm::CreateParam: Clone + Default + Send + Sync,
    Xfrm::LocalAddr: From<<Channel::Socket as Socket>::Addr>,
    Resolver: Addrs<Addr = <Channel::Xfrm as DatagramXfrm>::PeerAddr>
        + AddrsCreate<Ctx, Vec<Endpoint>, Config = ResolverConfig>
        + Send
        + Sync,
    Resolver::Origin:
        Clone + Eq + Hash + Into<Option<IPEndpointAddr>> + Send + Sync,
    Endpoint: Send,
    Session: 'static
        + SessionDispatch<
            LargeObjMsg<H::HashID>,
            LargeObjProto<
                H::HashID,
                Msg,
                Wrapper,
                MsgAuth,
                (),
                WrapperCodec,
                IDs,
                Recv,
                OutboundFrags
            >,
            SessionAuth::Prin,
            LargeObjProto<
                H::HashID,
                Msg,
                Wrapper,
                MsgAuth,
                (),
                WrapperCodec,
                IDs,
                Recv,
                OutboundFrags
            >
        >
        + Send,
    Ctx: 'static
        + FarChannelRegistryCtx<Channel, F, SessionAuth, Xfrm>
        + NSNameCachesCtx
        + Send
        + Sync
{
    type DispatchError = DispatchError<Session::SessionError>;
    type Msgs = LargeObjProto<
        H::HashID,
        Msg,
        Wrapper,
        MsgAuth,
        (),
        WrapperCodec,
        IDs,
        Recv,
        OutboundFrags
    >;
    type PushStream = DispatchSelector<
        Epochs,
        StreamID<
            <Channel::Xfrm as DatagramXfrm>::PeerAddr,
            F::ChannelID,
            Channel::Param
        >,
        ThreadedStream<
            DatagramCodecStream<
                LargeObjMsg<H::HashID>,
                <Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow,
                LargeObjMsgCodec<H>
            >
        >,
        DispatchEntryReporter<
            LargeObjMsg<H::HashID>,
            StreamID<
                <Channel::Xfrm as DatagramXfrm>::PeerAddr,
                F::ChannelID,
                Channel::Param
            >,
            DatagramCodecStream<
                LargeObjMsg<H::HashID>,
                <Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow,
                LargeObjMsgCodec<H>
            >,
            PassthruMsgAuthN<LargeObjMsg<H::HashID>, SessionAuth::Prin>,
            LargeObjProto<
                H::HashID,
                Msg,
                Wrapper,
                MsgAuth,
                (),
                WrapperCodec,
                IDs,
                Recv,
                OutboundFrags
            >
        >,
        Ctx
    >;
    type Recv = LargeObjProto<
        H::HashID,
        Msg,
        Wrapper,
        MsgAuth,
        (),
        WrapperCodec,
        IDs,
        Recv,
        OutboundFrags
    >;

    /// Obtain the components of a new private session.
    fn dispatch(
        &mut self,
        _ctx: &mut Ctx,
        prin: SessionAuth::Prin
    ) -> Result<
        (
            Self::PushStream,
            Self::Msgs,
            Notify,
            Dispatched<
                LargeObjMsg<H::HashID>,
                StreamID<
                    <Channel::Xfrm as DatagramXfrm>::PeerAddr,
                    F::ChannelID,
                    Channel::Param
                >,
                DatagramCodecStream<
                    LargeObjMsg<H::HashID>,
                    <Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow,
                    LargeObjMsgCodec<H>
                >,
                PassthruMsgAuthN<LargeObjMsg<H::HashID>, SessionAuth::Prin>,
                Self::Recv
            >
        ),
        Self::DispatchError
    > {
        let (shutdown, msgs, notify, recv) = self
            .session
            .session(prin)
            .map_err(|err| DispatchError::Session { err: err })?;
        let dispatched =
            Dispatched::new(shutdown, PassthruMsgAuthN::default(), recv);
        let reporter = dispatched.reporter();
        let stream = DispatchSelector::create(reporter, self.config.clone())
            .map_err(|err| DispatchError::Stream { err: err })?;

        Ok((stream, msgs, notify, dispatched))
    }
}

impl DispatchLargeObjBusCleanup {
    pub fn cleanup(self) {
        debug!(target: "dispatch-bus-cleanup",
               "joining pull streams");

        // XXX this won't stop the pull threads properly, but we need
        // the non-blocking I/O refactor to do that properly.

        if self.pull_join.join().is_err() {
            error!(target: "dispatch-bus-cleanup",
                   "error joining pull streams listener")
        }
    }
}

impl<Session> Display for DispatchError<Session>
where
    Session: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            DispatchError::Session { err } => err.fmt(f),
            DispatchError::Stream { err } => err.fmt(f)
        }
    }
}

impl<MsgCodec, Acquire> Display
    for DispatchLargeObjBusCreateError<MsgCodec, Acquire>
where
    MsgCodec: Display,
    Acquire: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            DispatchLargeObjBusCreateError::MsgCodec { err } => err.fmt(f),
            DispatchLargeObjBusCreateError::Acquire { err } => err.fmt(f)
        }
    }
}
