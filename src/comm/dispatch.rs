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
use constellation_common::codec::Codec;
use constellation_common::codec::DatagramCodec;
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
use constellation_streams::select::dispatch::DispatchSelector;
use constellation_streams::stream::ConcurrentStream;
use constellation_streams::stream::StreamID;
use constellation_streams::stream::ThreadedStream;
use constellation_streams::threads::dispatch::Dispatch;
use constellation_streams::threads::dispatch::DispatchEntryReporter;
use constellation_streams::threads::dispatch::Dispatched;
use constellation_streams::threads::dispatch::PullStreamsDispatchThread;
use constellation_streams::threads::push::private::PrivateSmallObjPushMode;
use log::debug;
use log::error;

use crate::config::DispatchCommConfig;

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

/// Type of errors that can occur when creating a [DispatchComm].
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

/// Type of errors that can occur when creating a [DispatchComm].
#[derive(Debug)]
pub enum DispatchCommCreateError<MsgCodec, Acquire> {
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
pub struct DispatchCommCleanup {
    pull_join: JoinHandle<()>
}

pub struct DispatchComm<
    Msg,
    MsgCodec,
    Msgs,
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
    MsgCodec: 'static + Clone + DatagramCodec<Msg> + Send,
    <MsgCodec as Codec<Msg>>::Param: Default,
    Msgs: 'static + PrivateMsgs<Msg> + Send,
    Recv: 'static + AuthNMsgRecv<SessionAuth::Prin, Msg> + Clone + Send,
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
    SessionAuth: Clone
        + SessionAuthN<<Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow>
        + Send
        + Sync,
    SessionAuth::Prin: 'static + Clone + Display + Eq + Hash + Send,
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
    Session: SessionDispatch<Msg, Msgs, SessionAuth::Prin, Recv> + Send,
    Ctx: 'static
        + Clone
        + FarChannelRegistryCtx<Channel, F, SessionAuth, Xfrm>
        + NSNameCachesCtx
        + Send
        + Sync {
    pull: PullStreamsDispatchThread<
        Msg,
        PassthruMsgAuthN<Msg, SessionAuth::Prin>,
        Dispatcher<
            Msg,
            MsgCodec,
            Msgs,
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
            Msg,
            MsgCodec,
            StreamID<
                <Channel::Xfrm as DatagramXfrm>::PeerAddr,
                F::ChannelID,
                Channel::Param
            >,
            SessionAuth::Prin
        >,
        PrivateSmallObjPushMode<
            Msg,
            DispatchSelector<
                 Epochs,
                 StreamID<
                     <Channel::Xfrm as DatagramXfrm>::PeerAddr,
                     F::ChannelID,
                     Channel::Param
                 >,
                 ThreadedStream<
                     DatagramCodecStream<
                         Msg,
                         <Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow,
                         MsgCodec
                     >
                 >,
                 DispatchEntryReporter<
                     Msg,
                     StreamID<
                         <Channel::Xfrm as DatagramXfrm>::PeerAddr,
                         F::ChannelID,
                         Channel::Param
                     >,
                     DatagramCodecStream<
                         Msg,
                         <Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow,
                         MsgCodec
                     >,
                     PassthruMsgAuthN<Msg, SessionAuth::Prin>,
                     Recv
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
    MsgCodec,
    Msgs,
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
    MsgCodec: 'static + Clone + DatagramCodec<Msg> + Send,
    <MsgCodec as Codec<Msg>>::Param: Default,
    Msgs: 'static + PrivateMsgs<Msg> + Send,
    Recv: 'static + AuthNMsgRecv<SessionAuth::Prin, Msg> + Clone + Send,
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
    SessionAuth: Clone
        + SessionAuthN<<Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow>
        + Send
        + Sync,
    SessionAuth::Prin: 'static + Clone + Display + Eq + Hash + Send,
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
    Session: SessionDispatch<Msg, Msgs, SessionAuth::Prin, Recv>,
    Ctx: FarChannelRegistryCtx<Channel, F, SessionAuth, Xfrm>
        + NSNameCachesCtx
        + Send
        + Sync {
    msg: PhantomData<Msg>,
    codec: PhantomData<MsgCodec>,
    msgs: PhantomData<Msgs>,
    recv: PhantomData<Recv>,
    channel: PhantomData<Channel>,
    flows: PhantomData<F>,
    auth: PhantomData<SessionAuth>,
    xfrm: PhantomData<Xfrm>,
    resolver: PhantomData<Resolver>,
    endpoint: PhantomData<Endpoint>,
    ctx: PhantomData<Ctx>,
    session: Session,
    config: DispatchConfig<Epochs::Config>
}

impl<
        Msg,
        MsgCodec,
        Msgs,
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
    DispatchComm<
        Msg,
        MsgCodec,
        Msgs,
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
    MsgCodec: 'static + Clone + DatagramCodec<Msg> + Send,
    <MsgCodec as Codec<Msg>>::Param: Default,
    Msgs: 'static + PrivateMsgs<Msg> + Send,
    Recv: 'static + AuthNMsgRecv<SessionAuth::Prin, Msg> + Clone + Send,
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
    SessionAuth: 'static
        + Clone
        + SessionAuthN<<Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow>
        + Send
        + Sync,
    SessionAuth::Prin: 'static + Clone + Display + Eq + Hash + Send,
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
    Session:
        'static + SessionDispatch<Msg, Msgs, SessionAuth::Prin, Recv> + Send,
    Ctx: 'static
        + Clone
        + FarChannelRegistryCtx<Channel, F, SessionAuth, Xfrm>
        + NSNameCachesCtx
        + Send
        + Sync
{
    pub fn create(
        config: DispatchCommConfig<Epochs::Config>,
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
        DispatchCommCreateError<
            MsgCodec::CreateError,
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
            .map_err(|err| DispatchCommCreateError::Acquire { err: err })?;

        let dispatcher = Dispatcher {
            msg: PhantomData,
            codec: PhantomData,
            msgs: PhantomData,
            recv: PhantomData,
            channel: PhantomData,
            flows: PhantomData,
            auth: PhantomData,
            xfrm: PhantomData,
            resolver: PhantomData,
            endpoint: PhantomData,
            ctx: PhantomData,
            session: session,
            config: dispatch_config
        };
        // ISSUE #1: get the codec config properly
        let msg_codec = MsgCodec::create(MsgCodec::Param::default())
            .map_err(|err| DispatchCommCreateError::MsgCodec { err: err })?;
        let listener =
            ThreadedFlowsPullStreamListener::create(listener, msg_codec);
        let pull = match size_hint {
            Some(size_hint) => PullStreamsDispatchThread::with_capacity(
                mode_config, dispatcher, listener, shutdown, ctx, size_hint
            ),
            None => PullStreamsDispatchThread::new(
                mode_config, dispatcher, listener, shutdown, ctx
            )
        };

        Ok(DispatchComm { pull: pull })
    }

    /// Consume this `DispatchComm`, start the threads, and return a
    /// cleanup object.
    pub fn start(self) -> DispatchCommCleanup {
        let DispatchComm { pull } = self;
        let pull_join = pull.start();

        DispatchCommCleanup {
            pull_join: pull_join
        }
    }
}

impl<
        Msg,
        MsgCodec,
        Msgs,
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
        Msg,
        StreamID<
            <Channel::Xfrm as DatagramXfrm>::PeerAddr,
            F::ChannelID,
            Channel::Param
        >,
        DatagramCodecStream<
            Msg,
            <Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow,
            MsgCodec
        >,
        PassthruMsgAuthN<Msg, SessionAuth::Prin>,
        Ctx
    >
    for Dispatcher<
        Msg,
        MsgCodec,
        Msgs,
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
    MsgCodec: 'static + Clone + DatagramCodec<Msg> + Send,
    <MsgCodec as Codec<Msg>>::Param: Default,
    Msgs: 'static + PrivateMsgs<Msg> + Send,
    Recv: 'static + AuthNMsgRecv<SessionAuth::Prin, Msg> + Clone + Send,
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
    SessionAuth: Clone
        + SessionAuthN<<Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow>
        + Send
        + Sync,
    SessionAuth::Prin: 'static + Clone + Display + Eq + Hash + Send,
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
    Session: SessionDispatch<Msg, Msgs, SessionAuth::Prin, Recv>,
    Ctx: 'static
        + FarChannelRegistryCtx<Channel, F, SessionAuth, Xfrm>
        + NSNameCachesCtx
        + Send
        + Sync
{
    type DispatchError = DispatchError<Session::SessionError>;
    type Msgs = Msgs;
    type PushStream = DispatchSelector<
        Epochs,
        StreamID<
            <Channel::Xfrm as DatagramXfrm>::PeerAddr,
            F::ChannelID,
            Channel::Param
        >,
        ThreadedStream<
            DatagramCodecStream<
                Msg,
                <Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow,
                MsgCodec
            >
        >,
        DispatchEntryReporter<
            Msg,
            StreamID<
                <Channel::Xfrm as DatagramXfrm>::PeerAddr,
                F::ChannelID,
                Channel::Param
            >,
            DatagramCodecStream<
                Msg,
                <Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow,
                MsgCodec
            >,
            PassthruMsgAuthN<Msg, SessionAuth::Prin>,
            Recv
        >,
        Ctx
    >;
    type Recv = Recv;

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
                Msg,
                StreamID<
                    <Channel::Xfrm as DatagramXfrm>::PeerAddr,
                    F::ChannelID,
                    Channel::Param
                >,
                DatagramCodecStream<
                    Msg,
                    <Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow,
                    MsgCodec
                >,
                PassthruMsgAuthN<Msg, SessionAuth::Prin>,
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

impl DispatchCommCleanup {
    pub fn cleanup(self) {
        debug!(target: "dispatch-comm-cleanup",
               "joining pull streams");

        // XXX this won't stop the pull threads properly, but we need
        // the non-blocking I/O refactor to do that properly.

        if self.pull_join.join().is_err() {
            error!(target: "dispatch-comm-cleanup",
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

impl<MsgCodec, Acquire> Display for DispatchCommCreateError<MsgCodec, Acquire>
where
    MsgCodec: Display,
    Acquire: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            DispatchCommCreateError::MsgCodec { err } => err.fmt(f),
            DispatchCommCreateError::Acquire { err } => err.fmt(f)
        }
    }
}
