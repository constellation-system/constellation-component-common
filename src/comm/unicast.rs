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
use constellation_channels::config::ChannelRegistryChannelsConfig;
use constellation_channels::config::CompoundFarEndpoint;
use constellation_channels::config::ResolverConfig;
use constellation_channels::far::compound::CompoundFarChannel;
use constellation_channels::far::compound::CompoundFarChannelThreadedFlows;
use constellation_channels::far::compound::CompoundFarChannelXfrmPeerAddr;
use constellation_channels::far::flows::OwnedFlowNegotiator;
use constellation_channels::far::flows::OwnedFlowsCreate;
use constellation_channels::far::flows::ThreadedFlowsListener;
use constellation_channels::far::flows::ThreadedFlowsPullStreamListener;
use constellation_channels::far::registry::FarChannelRegistryAcquireError;
use constellation_channels::far::registry::FarChannelRegistryChannels;
use constellation_channels::far::registry::FarChannelRegistryChannelsCreateError;
use constellation_channels::far::registry::FarChannelRegistryCtx;
use constellation_channels::far::registry::FarChannelRegistryID;
use constellation_channels::far::registry::RegistryAcquireError;
use constellation_channels::far::udp::UDPDatagramXfrm;
use constellation_channels::far::unix::UnixDatagramXfrm;
use constellation_channels::far::FarChannelAcquired;
use constellation_channels::far::FarChannelAcquiredResolve;
use constellation_channels::far::FarChannelCreate;
use constellation_channels::far::FarChannelFlowsError;
use constellation_channels::far::FarChannelOwnedFlows;
use constellation_channels::resolve::cache::NSNameCachesCtx;
use constellation_channels::resolve::MixedResolver;
use constellation_common::codec::DatagramCodec;
use constellation_common::ids::IDGen;
use constellation_common::net::DatagramXfrm;
use constellation_common::net::DatagramXfrmCreate;
use constellation_common::net::IPEndpointAddr;
use constellation_common::net::PrivateMsgs;
use constellation_common::net::Socket;
use constellation_common::shutdown::ShutdownFlag;
use constellation_common::sync::Notify;
use constellation_streams::addrs::Addrs;
use constellation_streams::addrs::AddrsCreate;
use constellation_streams::channels::ChannelParam;
use constellation_streams::select::StreamSelector;
use constellation_streams::select::StreamSelectorCreateError;
use constellation_streams::select::StreamSelectorReporter;
use constellation_streams::select::ThreadedStreamSelectorError;
use constellation_streams::stream::ConcurrentStream;
use constellation_streams::stream::PushStreamReporter;
use constellation_streams::stream::StreamID;
use constellation_streams::threads::pull::PullStreams;
use constellation_streams::threads::pull::PullStreamsListenThread;
use constellation_streams::threads::pull::PullStreamsReporter;
use constellation_streams::threads::push::private::PushStreamPrivateThread;
use log::debug;
use log::error;
use log::info;

use crate::config::UnicastCommConfig;

// ISSUE #2: Need to refactor authn so we can properly handle message
// authentication.

pub type CompoundUnicastComm<
    Msg,
    MsgCodec,
    Msgs,
    Recv,
    Epochs,
    SessionAuth,
    Xfrm,
    Ctx
> = UnicastComm<
    Msg,
    MsgCodec,
    Msgs,
    Recv,
    Epochs,
    CompoundFarChannel,
    CompoundFarChannelThreadedFlows<
        SessionAuth,
        UnixDatagramXfrm,
        UDPDatagramXfrm,
        FarChannelRegistryID
    >,
    SessionAuth,
    Xfrm,
    MixedResolver<CompoundFarChannelXfrmPeerAddr, CompoundFarEndpoint>,
    CompoundFarEndpoint,
    Ctx
>;

pub struct UnicastComm<
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
    Ctx
> where
    Msg: 'static + Clone + Send,
    Msgs: PrivateMsgs<Msg>,
    SessionAuth: Clone
        + SessionAuthN<<Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow>
        + Send
        + Sync,
    SessionAuth::Prin: 'static + Clone + Display + Eq + Hash + Send,
    MsgCodec: 'static + Clone + DatagramCodec<Msg> + Send,
    <MsgCodec as DatagramCodec<Msg>>::Param: Default,
    Recv: 'static + AuthNMsgRecv<SessionAuth::Prin, Msg> + Clone + Send,
    Epochs: IDGen + Iterator<Item = u128> + Send + Sync,
    Channel: FarChannelOwnedFlows<F, SessionAuth, Xfrm>
        + FarChannelCreate
        + Send
        + Sync,
    Channel::Acquired: FarChannelAcquiredResolve<Resolved = Channel::Param>,
    Channel::Param: 'static
        + Clone
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
    Ctx: 'static
        + FarChannelRegistryCtx<Channel, F, SessionAuth, Xfrm>
        + NSNameCachesCtx
        + Send
        + Sync,
    Ctx::NameCaches: NSNameCachesCtx,
    Endpoint: 'static + Send,
    Resolver: 'static
        + Addrs<Addr = <Channel::Xfrm as DatagramXfrm>::PeerAddr>
        + AddrsCreate<Ctx, Vec<Endpoint>, Config = ResolverConfig>
        + Send
        + Sync,
    Resolver::Origin: 'static
        + Clone
        + Eq
        + Hash
        + Into<Option<IPEndpointAddr>>
        + Send
        + Sync {
    endpoint: PhantomData<Endpoint>,
    push: PushStreamPrivateThread<
        Msg,
        Msgs,
        StreamSelector<
            Epochs,
            FarChannelRegistryChannels<
                Msg,
                MsgCodec,
                PullStreamsReporter<
                    Msg,
                    Msg,
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
                    PassthruMsgAuthN<Msg, SessionAuth::Prin>,
                    Recv
                >,
                Channel,
                F,
                SessionAuth,
                Xfrm
            >,
            Resolver,
            Ctx
        >,
        Ctx
    >,
    pull: PullStreamsListenThread<
        Msg,
        Msg,
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
        >
    >,
    reporter: StreamSelectorReporter<
        Epochs,
        FarChannelRegistryChannels<
            Msg,
            MsgCodec,
            PullStreamsReporter<
                Msg,
                Msg,
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
                PassthruMsgAuthN<Msg, SessionAuth::Prin>,
                Recv
            >,
            Channel,
            F,
            SessionAuth,
            Xfrm
        >,
        Resolver,
        Ctx
    >
}

/// Cleanup object for [UnicastComm].
pub struct UnicastCommCleanup {
    notify: Notify,
    sender_join: JoinHandle<()>,
    pull_join: JoinHandle<()>
}

/// Type of errors that can occur when creating a [UnicastComm].
#[derive(Debug)]
pub enum UnicastCommCreateError<Acquire, MsgCodec, Stream, Refresh> {
    /// Error acquiring channels.
    Acquire {
        /// The error that occurred while acquiring the channels.
        err: Acquire
    },
    /// Error while creating message codecs.
    MsgCodec {
        /// The error that occurred while creating message codecs.
        err: MsgCodec
    },
    /// Error while creating [StreamSelector]s.
    Stream {
        /// The error that occurred while creating [StreamSelector]s.
        err: Stream
    },
    /// Error while [refresh](StreamSelector::refresh)ing the
    /// [StreamSelector]s.
    Refresh { err: Refresh }
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
        Ctx
    >
    UnicastComm<
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
        Ctx
    >
where
    Msg: 'static + Clone + Send,
    Msgs: 'static + PrivateMsgs<Msg> + Send,
    SessionAuth: 'static
        + Clone
        + SessionAuthN<<Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow>
        + Send
        + Sync,
    SessionAuth::Prin: 'static + Clone + Display + Eq + Hash + Send,
    MsgCodec: 'static + Clone + DatagramCodec<Msg> + Send,
    <MsgCodec as DatagramCodec<Msg>>::Param: Default,
    Recv: 'static + AuthNMsgRecv<SessionAuth::Prin, Msg> + Clone + Send,
    Epochs: 'static + IDGen + Iterator<Item = u128> + Send + Sync,
    Channel: 'static
        + FarChannelOwnedFlows<F, SessionAuth, Xfrm>
        + FarChannelCreate
        + Send
        + Sync,
    Channel::Acquired: FarChannelAcquiredResolve<Resolved = Channel::Param>,
    Channel::Param: 'static
        + Clone
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
    Ctx: 'static
        + FarChannelRegistryCtx<Channel, F, SessionAuth, Xfrm>
        + NSNameCachesCtx
        + Send
        + Sync,
    Ctx::NameCaches: NSNameCachesCtx,
    Endpoint: 'static + Send,
    Resolver: 'static
        + Addrs<Addr = <Channel::Xfrm as DatagramXfrm>::PeerAddr>
        + AddrsCreate<Ctx, Vec<Endpoint>, Config = ResolverConfig>
        + Send
        + Sync,
    Resolver::Origin: 'static
        + Clone
        + Eq
        + Hash
        + Into<Option<IPEndpointAddr>>
        + Send
        + Sync
{
    pub fn create(
        config: UnicastCommConfig<
            ChannelRegistryChannelsConfig<MsgCodec::Param>,
            Epochs::Config,
            Endpoint
        >,
        listener: ThreadedFlowsListener<
            <Channel::Nego as OwnedFlowNegotiator<F::Flow>>::Flow,
            StreamID<
                <Channel::Xfrm as DatagramXfrm>::PeerAddr,
                F::ChannelID,
                Channel::Param
            >,
            SessionAuth::Prin
        >,
        mut ctx: Ctx,
        shutdown: ShutdownFlag,
        sender_notify: Notify,
        upstream_msg_recv: Recv,
        msgs: Msgs
    ) -> Result<
        Self,
        UnicastCommCreateError<
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
            >,
            MsgCodec::CreateError,
            StreamSelectorCreateError<
                FarChannelRegistryChannelsCreateError<MsgCodec::CreateError>,
                Resolver::CreateError
            >,
            ThreadedStreamSelectorError<
                Resolver::AddrsError,
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
        >
    >{
        info!(target: "unicast-comm",
              "creating unicast comm");

        debug!(target: "unicast-comm",
               "initializing channels");

        // Bring up all channels.
        ctx.far_channel_registry()
            .acquire_all(&mut ctx)
            .map_err(|err| UnicastCommCreateError::Acquire { err: err })?;

        // Bring up the pull-side.
        debug!(target: "unicast-comm",
               "initializing pull streams");

        let party_config = config.take();

        // ISSUE #1: get the codec config properly
        let msg_codec = MsgCodec::create(MsgCodec::Param::default())
            .map_err(|err| UnicastCommCreateError::MsgCodec { err: err })?;
        let listener =
            ThreadedFlowsPullStreamListener::create(listener, msg_codec);
        let (pull_streams, pull_listener) = PullStreams::with_capacity(
            listener,
            upstream_msg_recv,
            shutdown.clone(),
            PassthruMsgAuthN::default(),
            1
        );
        let stream_reporter = pull_streams.reporter();

        // Bring up the push-side.
        debug!(target: "unicast-comm",
               "initializing push streams");

        let mut stream = StreamSelector::<
            Epochs,
            FarChannelRegistryChannels<
                Msg,
                MsgCodec,
                PullStreamsReporter<Msg, _, _, _, _>,
                Channel,
                F,
                SessionAuth,
                Xfrm
            >,
            Resolver,
            Ctx
        >::create(
            &mut ctx,
            shutdown.clone(),
            stream_reporter.clone(),
            party_config
        )
        .map_err(|err| UnicastCommCreateError::Stream { err: err })?;

        // Refresh the streams to ensure no bad stream
        // reporting.
        stream
            .refresh(&mut ctx)
            .map_err(|err| UnicastCommCreateError::Refresh { err: err })?;

        let reporter = stream.reporter();
        let sender = PushStreamPrivateThread::create(
            ctx,
            msgs,
            sender_notify.clone(),
            stream,
            shutdown.clone()
        );

        Ok(UnicastComm {
            endpoint: PhantomData,
            reporter: reporter,
            pull: pull_listener,
            push: sender
        })
    }

    #[inline]
    pub fn notify(&self) -> Notify {
        self.push.notify()
    }

    /// Consume this `UnicastComm`, start the threads, and return a
    /// cleanup object.
    pub fn start(self) -> UnicastCommCleanup {
        let UnicastComm {
            pull,
            push,
            reporter,
            ..
        } = self;
        let pull_join = pull.start(reporter);
        let notify = push.notify();
        let sender_join = push.start();

        UnicastCommCleanup {
            notify: notify,
            sender_join: sender_join,
            pull_join: pull_join
        }
    }
}

impl UnicastCommCleanup {
    pub fn cleanup(self) {
        if let Err(err) = self.notify.notify() {
            error!(target: "unicast-comm-cleanup",
                   "error notifying sender: {}",
                   err)
        }

        debug!(target: "unicast-comm-cleanup",
               "joining sender");

        if self.sender_join.join().is_err() {
            error!(target: "unicast-comm-cleanup",
                   "error joining sender")
        }

        debug!(target: "unicast-comm-cleanup",
               "joining pull streams");

        if self.pull_join.join().is_err() {
            error!(target: "unicast-comm-cleanup",
                   "error joining pull streams listener")
        }
    }
}

impl<Acquire, MsgCodec, Stream, Refresh> Display
    for UnicastCommCreateError<Acquire, MsgCodec, Stream, Refresh>
where
    Acquire: Display,
    MsgCodec: Display,
    Stream: Display,
    Refresh: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            UnicastCommCreateError::Acquire { err } => err.fmt(f),
            UnicastCommCreateError::MsgCodec { err } => err.fmt(f),
            UnicastCommCreateError::Stream { err } => err.fmt(f),
            UnicastCommCreateError::Refresh { err } => err.fmt(f)
        }
    }
}
