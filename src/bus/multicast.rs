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
use std::fmt::Formatter;
use std::hash::Hash;
use std::io::Error;
use std::thread::JoinHandle;
use std::vec::IntoIter;

use constellation_auth::authn::AuthNed;
use constellation_auth::authn::AuthNMsgRecv;
use constellation_channels::far::FarChannelAcquired;
use constellation_channels::far::FarChannelAcquiredResolve;
use constellation_channels::far::FarChannelCreate;
use constellation_channels::far::FarChannelFlowsError;
use constellation_common::config::Create;
use constellation_common::config::CreateWithParam;
use constellation_common::error::ScopedError;
use constellation_common::net::DatagramXfrmCreate;
use constellation_common::retry::RetryWhen;
use constellation_common::sync::Notify;
use constellation_streams::addrs::Addrs;
use constellation_streams::addrs::AddrsCreate;
use constellation_streams::channels::Channels;
use constellation_streams::channels::ChannelsListen;
use constellation_streams::channels::ChannelsShutdown;
use constellation_streams::config::SharedDatagramModeConfig;
use constellation_streams::multicast::DatagramStreamMulticaster;
use constellation_streams::multicast::StreamMulticaster;
use constellation_streams::select::StreamSelector;
use constellation_streams::select::StreamSelectorCreateError;
use constellation_streams::select::ThreadedStreamSelectorError;
use constellation_streams::stream::PullStream;
use constellation_streams::stream::PushStream;
use constellation_streams::threads::poll::PollThread;
use constellation_streams::threads::poll::PollThreadCreateError;
use constellation_streams::threads::poll::PollThreadCtx;
use constellation_streams::threads::poll::PollThreadTypes;
use log::debug;
use log::error;
use log::info;

use crate::config::MulticastDatagramBusConfig;
use crate::config::PartiesConfig;
use crate::PartyStreamIdx;

pub trait MulticastDatagramBusTypes<Ctx>
where Ctx: 'static + Send {
    type Addr: 'static + Clone + Debug + Display + Eq + Hash + Send;
    type ChannelParam: 'static + Clone + Debug + Display + Eq + Hash + Send;
    type ChannelID: 'static + Clone + Debug + Display + Eq + Hash + Send;
    type InMsg;
    type MsgPrin: Clone + Display + Eq + Hash;
    type AuthNMsg: AuthNed<Self::MsgPrin, Self::InMsg>;
    type SessionPrin: Clone + Display + Eq + Hash;
    type Chan: Clone + PullStream<Self::Wrapper, PullError = Self::PullError>;
    type Wrapper;
    type PullError: Debug + Display + ScopedError;
    type AuthNChan: 'static
        + Clone
        + AuthNed<Self::SessionPrin, Self::Chan>
        + PushStream<PollThreadCtx<Self::Chans, Ctx>>
        + Send;
    type EpochsConfig: Default;
    type EpochsCreateError: Debug + Display;
    type Epochs: Iterator<Item = u128>
        + Create<Config = Self::EpochsConfig,
                 CreateError = Self::EpochsCreateError>;
    type MsgAuthConfig;
    type MsgAuthCreateError: Debug + Display;
    type Msgs: 'static + Send;
    type ResolveConfig: Clone + Default;
    type ResolveOrigin: Clone + Display + Eq + Hash;
    type ResolveCreateError: Debug + Display;
    type Resolve: Addrs<Addr = Self::Addr>
        + AddrsCreate<
            PollThreadCtx<Self::Chans, Ctx>,
            Config = Self::ResolveConfig,
            Origin = Self::ResolveOrigin,
            CreateError = Self::ResolveCreateError
        >;
    type RecvError: Debug + Display + ScopedError;
    type Recv: 'static
        + AuthNMsgRecv<
            Self::MsgPrin,
            Self::InMsg,
            Self::AuthNMsg,
            RecvError = Self::RecvError
        >
        + Send;
    type ModeCreateError: Debug + Display;
    type ChansOutNegoParam: Clone + Eq + Hash;
    type ChansConfig;
    type ChansCreateError: Debug + Display;
    type ChanShutdownError: Debug + Display + ScopedError;
    type ChanShutdownRetry: RetryWhen;
    type Chans: 'static
        + for<'a> CreateWithParam<
            &'a mut Ctx,
            Config = Self::ChansConfig,
            CreateError = Self::ChansCreateError,
        >
        + Channels<
            Ctx,
            Addr = Self::Addr,
            Param = Self::ChannelParam,
            Stream = Self::AuthNChan,
            ChannelID = Self::ChannelID,
            OutNegoParam = Self::ChansOutNegoParam
        >
        + ChannelsListen<Ctx>
        + ChannelsShutdown<
            Ctx,
            ShutdownStreamError = Self::ChanShutdownError,
            ShutdownStreamRetry = Self::ChanShutdownRetry
        >
        + Send;
    type ThreadTypes: PollThreadTypes<
        Ctx,
        Addr = Self::Addr,
        InMsg = Self::InMsg,
        SessionPrin = Self::SessionPrin,
        MsgPrin = Self::MsgPrin,
        AuthNMsg = Self::AuthNMsg,
        Recv = Self::Recv,
        Msgs = Self::Msgs,
        Stream = DatagramStreamMulticaster<
            Self::SessionPrin,
            PartyStreamIdx,
            StreamSelector<
                Self::Epochs,
                Self::Resolve,
                PollThreadCtx<Self::Chans, Ctx>
            >,
            PollThreadCtx<Self::Chans, Ctx>
        >,
        MsgAuthConfig = Self::MsgAuthConfig,
        ChansConfig = Self::ChansConfig,
        MsgAuthCreateError = Self::MsgAuthCreateError,
        ModeConfig = SharedDatagramModeConfig,
        ModeCreateError = Self::ModeCreateError,
        ChansCreateError = Self::ChansCreateError
    >;
}

pub struct MulticastDatagramBus<Types, Ctx>
where
    Ctx: 'static + Send,
    Types: MulticastDatagramBusTypes<Ctx> {
    poll: PollThread<Ctx, Types::ThreadTypes>
}

/// Cleanup object for [MulticastDatagramBus].
pub struct MulticastDatagramBusCleanup {
    poll_join: JoinHandle<()>
}

/// Type of errors that can occur when creating a [MulticastDatagramBus].
#[derive(Debug)]
pub enum MulticastDatagramBusCreateError<Stream, Refresh, Poll> {
    /// Error while creating [StreamSelector]s.
    Stream {
        /// The error that occurred while creating [StreamSelector]s.
        err: Stream
    },
    /// Error while [refresh](StreamSelector::refresh)ing the
    /// [StreamSelector]s.
    Refresh {
        /// The error that occurred while
        /// [refresh](StreamSelector::refresh)ing the
        /// [StreamSelector]s.
        err: Refresh
    },
    /// Error while creating the [PollThread].
    Poll {
        /// The error that occurred while creating the [PollThread].
        err: Poll
    }
}

impl<Types, Ctx> MulticastDatagramBus<Types, Ctx>
where
    Ctx: 'static + Send,
    Types: 'static + MulticastDatagramBusTypes<Ctx> {
    pub fn create(
        self_party: Option<Types::SessionPrin>,
        config: MulticastDatagramBusConfig<
            Types::ChansConfig,
            Types::SessionPrin,
            Types::EpochsConfig,
            Types::MsgAuthConfig,
            Types::Addr
        >,
        mut ctx: Ctx,
        recv: Types::Recv,
        msgs: Types::Msgs
    ) -> Result<
        Self,
        MulticastDatagramBusCreateError<
            StreamSelectorCreateError<
                Types::ChansCreateError,
                Types::ResolveCreateError
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
            >,
            PollThreadCreateError<
                Types::ModeCreateError,
                Types::ChansCreateError,
                Types::MsgAuthCreateError
            >
        >
    >{
        info!(target: "multicast-small-obj-bus",
              "creating multicast bus");

        let (slots_config, parties_config, poll_config) = config.take();

        // Bring up the push-side.
        debug!(target: "multicast-small_obj-bus",
               "initializing push streams");

        let stream = match parties_config {
            PartiesConfig::Static { stat } => {
                let mut party_streams = Vec::with_capacity(stat.len());

                for party in stat {
                    let (party, frags, party_config) = party.take();

                    debug!(target: "multicast-bus",
                           "creating stream for party {}",
                           party);

                    if self_party.as_ref() != Some(&party) {
                        let mut stream = StreamSelector::<
                            Types::Epochs,
                            Types::Resolve,
                            Ctx
                        >::create(
                            &mut ctx,
                            party_config
                        )
                        .map_err(|err| {
                            MulticastDatagramBusCreateError::Stream { err: err }
                        })?;

                        // Refresh the streams to ensure no bad stream
                        // reporting.
                        stream.refresh(&mut ctx).map_err(|err| {
                            MulticastDatagramBusCreateError::Refresh {
                                err: err
                            }
                        })?;

                        party_streams.push((party, frags, stream))
                    }
                }

                let stream: DatagramStreamMulticaster<
                    Types::SessionPrin,
                    PartyStreamIdx,
                    StreamSelector<
                        Types::Epochs,
                        Types::Resolve,
                        Ctx
                    >,
                    Ctx
                > = StreamMulticaster::create(
                    party_streams.into_iter(),
                    slots_config
                );

                stream
            }
        };
        let poll = PollThread::create(poll_config, ctx, recv, msgs, stream)
            .map_err(|err| MulticastDatagramBusCreateError::Poll { err: err })?;

        Ok(MulticastDatagramBus {
            poll: poll
        })
    }

    #[inline]
    pub fn parties(
        &self
    ) -> Result<IntoIter<(PartyStreamIdx, Types::SessionPrin)>, Infallible> {
        self.push.parties()
    }

    #[inline]
    pub fn notify(&self) -> Notify {
        self.poll.notify()
    }

    /// Consume this `MulticastDatagramBus`, start the threads, and return a
    /// cleanup object.
    pub fn start(self) -> Result<MulticastDatagramBusCleanup, Error> {
        let MulticastDatagramBus { poll } = self;
        let poll_join = poll.start()?;

        Ok(MulticastDatagramBusCleanup {
            poll_join: poll_join
        })
    }
}

impl MulticastDatagramBusCleanup {
    pub fn cleanup(self) {
        debug!(target: "multicast-small-obj-bus-cleanup",
               "joining poll thread");

        if self.poll_join.join().is_err() {
            error!(target: "multicast-small-obj-bus-cleanup",
                   "error joining pull streams listener")
        }
    }
}

impl<Stream, Refresh, Poll> Display
    for MulticastDatagramBusCreateError<Stream, Refresh, Poll>
where
    Stream: Display,
    Refresh: Display,
    Poll: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            MulticastDatagramBusCreateError::Stream { err } => err.fmt(f),
            MulticastDatagramBusCreateError::Refresh { err } => err.fmt(f),
            MulticastDatagramBusCreateError::Poll { err } => err.fmt(f)
        }
    }
}
