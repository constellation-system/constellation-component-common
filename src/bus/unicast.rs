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

use std::fmt::Display;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::hash::Hash;
use std::io::Error;
use std::sync::Arc;
use std::thread::JoinHandle;

use constellation_auth::authn::AuthNed;
use constellation_auth::authn::AuthNMsgRecv;
use constellation_common::config::Create;
use constellation_common::config::CreateWithParam;
use constellation_common::error::ScopedError;
use constellation_common::retry::RetryWhen;
use constellation_streams::addrs::Addrs;
use constellation_streams::addrs::AddrsCreate;
use constellation_streams::channels::Channels;
use constellation_streams::channels::ChannelsListen;
use constellation_streams::channels::ChannelsShutdown;
use constellation_streams::config::PrivateDatagramModeConfig;
use constellation_streams::stream::PullStream;
use constellation_streams::stream::PushStream;
use constellation_streams::select::StreamSelector;
use constellation_streams::select::StreamSelectorCreateError;
use constellation_streams::threads::poll::PollThread;
use constellation_streams::threads::poll::PollThreadCreateError;
use constellation_streams::threads::poll::PollThreadCtx;
use constellation_streams::threads::poll::PollThreadTypes;
use log::debug;
use log::error;
use log::info;
use mio::Waker;

use crate::config::UnicastDatagramBusConfig;

pub trait UnicastDatagramBusTypes<Ctx>
where Ctx: 'static + Send {
    type Addr: 'static + Clone + Debug + Display + Eq + Hash + Send;
    type ChannelParam: 'static + Clone + Debug + Display + Eq + Hash + Send;
    type ChannelID: 'static + Clone + Debug + Display + Eq + Hash + Send;
    type SessionPrin: Display;
    type InMsg;
    type MsgPrin: Clone + Display + Eq + Hash;
    type AuthNMsg: AuthNed<Self::MsgPrin, Self::InMsg>;
    type Wrapper;
    type PullError: Debug + Display + ScopedError;
    type Chan: Clone + PullStream<Self::Wrapper, PullError = Self::PullError>;
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
        Stream = StreamSelector<
            Self::Epochs,
            Self::Resolve,
            PollThreadCtx<Self::Chans, Ctx>
        >,
        MsgAuthConfig = Self::MsgAuthConfig,
        ChansConfig = Self::ChansConfig,
        MsgAuthCreateError = Self::MsgAuthCreateError,
        ModeConfig = PrivateDatagramModeConfig,
        ModeCreateError = Self::ModeCreateError,
        ChansCreateError = Self::ChansCreateError
    >;
}

pub struct UnicastDatagramBus<Ctx, Types>
where
    Ctx: 'static + Send,
    Types: UnicastDatagramBusTypes<Ctx>
{
    poll: PollThread<Ctx, Types::ThreadTypes>
}

/// Cleanup object for [UnicastDatagramBus].
pub struct UnicastDatagramBusCleanup {
    poll_join: JoinHandle<()>
}

/// Type of errors that can occur when creating a [UnicastDatagramBus].
#[derive(Debug)]
pub enum UnicastDatagramBusCreateError<Stream, Poll> {
    /// Error while creating the [StreamSelector].
    Stream {
        /// The error that occurred while creating [StreamSelector]s.
        err: Stream
    },
    /// Error while creating the [PollThread].
    Poll {
        /// The error that occurred while creating [StreamSelector]s.
        err: Poll
    },
}

impl<Ctx, Types> UnicastDatagramBus<Ctx, Types>
where
    Ctx: 'static + Send,
    Types: 'static + UnicastDatagramBusTypes<Ctx>
{
    pub fn create(
        config: UnicastDatagramBusConfig<
            Types::ChansConfig,
            Types::EpochsConfig,
            Types::MsgAuthConfig,
            Types::Addr
        >,
        mut ctx: Ctx,
        recv: Types::Recv,
        msgs: Types::Msgs
    ) -> Result<
        Self,
        UnicastDatagramBusCreateError<
            StreamSelectorCreateError<
                Types::ResolveCreateError,
                Types::EpochsCreateError
            >,
            PollThreadCreateError<
                Types::ModeCreateError,
                Types::ChansCreateError,
                Types::MsgAuthCreateError
            >
        >
    > {
        info!(target: "unicast-small-obj-bus",
              "creating unicast bus");

        let (party_config, poll_config) = config.take();

        debug!(target: "unicast-small-obj-bus",
               "initializing push streams");

        let stream = StreamSelector::<
            Types::Epochs,
            Types::Resolve,
            PollThreadCtx<Types::Chans, Ctx>
        >::create(
            &mut ctx,
            party_config
        )
        .map_err(|err| UnicastDatagramBusCreateError::Stream { err: err })?;
        let poll = PollThread::create(poll_config, ctx, recv, msgs, stream)
            .map_err(|err| UnicastDatagramBusCreateError::Poll { err: err })?;

        Ok(UnicastDatagramBus { poll: poll })
    }

    #[inline]
    pub fn notify(&self) -> Arc<Waker> {
        self.poll.notify()
    }

    /// Consume this `UnicastDatagramBus`, start the threads, and return a
    /// cleanup object.
    pub fn start(self) -> Result<UnicastDatagramBusCleanup, Error> {
        let UnicastDatagramBus { poll } = self;
        let poll_join = poll.start()?;

        Ok(UnicastDatagramBusCleanup {
            poll_join: poll_join
        })
    }
}

impl UnicastDatagramBusCleanup {
    pub fn cleanup(self) {
        debug!(target: "unicast-small-obj-bus-cleanup",
               "joining poll thread");

        if self.poll_join.join().is_err() {
            error!(target: "unicast-small-obj-bus-cleanup",
                   "error joining poll thread")
        }
    }
}

impl<Stream, Poll> Display for UnicastDatagramBusCreateError<Stream, Poll>
where
    Stream: Display,
    Poll: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            UnicastDatagramBusCreateError::Stream { err } => err.fmt(f),
            UnicastDatagramBusCreateError::Poll { err } => err.fmt(f),
        }
    }
}
