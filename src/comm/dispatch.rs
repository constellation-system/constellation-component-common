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
use constellation_channels::far::registry::FarChannelRegistryCtx;
use constellation_channels::far::FarChannelAcquiredResolve;
use constellation_channels::far::FarChannelCreate;
use constellation_channels::far::FarChannelOwnedFlows;
use constellation_channels::resolve::cache::NSNameCachesCtx;
use constellation_common::codec::DatagramCodec;
use constellation_common::ids::IDGen;
use constellation_common::net::DatagramXfrm;
use constellation_common::net::DatagramXfrmCreate;
use constellation_common::net::IPEndpointAddr;
use constellation_common::net::PrivateMsgs;
use constellation_common::net::Socket;
use constellation_common::sched::DenseItemID;
use constellation_common::sched::RefreshError;
use constellation_common::shutdown::ShutdownFlag;
use constellation_common::sync::Notify;
use constellation_streams::addrs::Addrs;
use constellation_streams::addrs::AddrsCreate;
use constellation_streams::channels::ChannelParam;
use constellation_streams::codec::DatagramCodecStream;
use constellation_streams::config::DispatchConfig;
use constellation_streams::error::ErrorReportInfo;
use constellation_streams::select::dispatch::DispatchSelector;
use constellation_streams::select::dispatch::DispatchSelectorReporter;
use constellation_streams::stream::ConcurrentStream;
use constellation_streams::stream::StreamID;
use constellation_streams::stream::ThreadedStream;
use constellation_streams::threads::dispatch::Dispatch;
use constellation_streams::threads::dispatch::DispatchDropHandle;
use constellation_streams::threads::dispatch::DispatchEntryReporter;
use constellation_streams::threads::dispatch::Dispatched;
use log::debug;
use log::error;
use log::info;

pub trait SessionDispatch<Msg, Msgs, Prin, Recv, Drop>
where
    Msgs: PrivateMsgs<Msg> + Send,
    Recv: AuthNMsgRecv<Prin, Msg> {
    type SessionError: Display;

    fn session(
        &self,
        prin: Prin,
        drop: Drop
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
    <MsgCodec as DatagramCodec<Msg>>::Param: Default,
    <MsgCodec as DatagramCodec<Msg>>::EncodeError:
        ErrorReportInfo<DenseItemID<usize>>,
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
    Session: SessionDispatch<
        Msg,
        Msgs,
        SessionAuth::Prin,
        Recv,
        DispatchDropHandle<
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
            Recv,
            DispatchSelectorReporter<
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
            >
        >
    >,
    Ctx: FarChannelRegistryCtx<Channel, F, SessionAuth, Xfrm>
        + NSNameCachesCtx
        + Send
        + Sync,
    Ctx::NameCaches: NSNameCachesCtx {
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
    <MsgCodec as DatagramCodec<Msg>>::Param: Default,
    <MsgCodec as DatagramCodec<Msg>>::EncodeError:
        ErrorReportInfo<DenseItemID<usize>>,
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
    Session: SessionDispatch<
        Msg,
        Msgs,
        SessionAuth::Prin,
        Recv,
        DispatchDropHandle<
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
            Recv,
            DispatchSelectorReporter<
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
            >
        >
    >,
    Ctx: 'static
        + FarChannelRegistryCtx<Channel, F, SessionAuth, Xfrm>
        + NSNameCachesCtx
        + Send
        + Sync,
    Ctx::NameCaches: NSNameCachesCtx
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
        prin: SessionAuth::Prin,
        drop: DispatchDropHandle<
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
            Self::Recv,
            DispatchSelectorReporter<
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
            >
        >
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
        let (shutdown, msgs, notify, recv) =
            self.session
                .session(prin, drop)
                .map_err(|err| DispatchError::Session { err: err })?;
        let dispatched =
            Dispatched::new(shutdown, PassthruMsgAuthN::default(), recv);
        let reporter = dispatched.reporter();
        let stream = DispatchSelector::create(reporter, self.config.clone())
            .map_err(|err| DispatchError::Stream { err: err })?;

        Ok((stream, msgs, notify, dispatched))
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
