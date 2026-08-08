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
use constellation_channels::config::ResolverConfig;
use constellation_common::error::ScopedError;
use constellation_streams::config::PartyConfig;
use constellation_streams::select::StreamSelectorCreateError;
use constellation_streams::threads::poll::PollThread;
use constellation_streams::threads::poll::PollThreadCreateError;
use constellation_streams::threads::poll::PollThreadTypes;
use log::debug;
use log::error;
use log::info;
use mio::Waker;

use crate::config::UnicastBusConfig;

pub trait UnicastBusTypes<Ctx>
where Ctx: 'static + Send {
    type Addr: 'static + Clone + Debug + Display + Eq + Hash + Send;
    type InMsg;
    type MsgPrin: Clone + Display + Eq + Hash;
    type AuthNMsg: AuthNed<Self::MsgPrin, Self::InMsg>;
    type Msgs: 'static + Send;
    type RecvError: Debug + Display + ScopedError;
    type Recv: 'static
        + AuthNMsgRecv<
            Self::MsgPrin,
            Self::InMsg,
            Self::AuthNMsg,
            RecvError = Self::RecvError
        >
        + Send;
    type ResolveCreateError: Debug + Display;
    type MsgAuthConfig;
    type MsgAuthCreateError: Debug + Display;
    type EpochsConfig: Default;
    type EpochsCreateError: Debug + Display;
    type ModeConfig: Default;
    type ModeCreateError: Debug + Display;
    type ChansConfig;
    type ChansCreateError: Debug + Display;
    type ThreadTypes: PollThreadTypes<
        Ctx,
        Addr = Self::Addr,
        InMsg = Self::InMsg,
        MsgPrin = Self::MsgPrin,
        AuthNMsg = Self::AuthNMsg,
        Recv = Self::Recv,
        Msgs = Self::Msgs,
        ChansConfig = Self::ChansConfig,
        StreamConfig = PartyConfig<
            ResolverConfig,
            Self::EpochsConfig,
            String,
            Self::Addr
        >,
        StreamCreateError = StreamSelectorCreateError<
            Self::ResolveCreateError,
            Self::EpochsCreateError
        >,
        MsgAuthConfig = Self::MsgAuthConfig,
        ModeConfig = Self::ModeConfig,
        ModeCreateError = Self::ModeCreateError,
        MsgAuthCreateError = Self::MsgAuthCreateError,
        ChansCreateError = Self::ChansCreateError
    >;
}

pub struct UnicastBus<Ctx, Types>
where
    Ctx: 'static + Send,
    Types: UnicastBusTypes<Ctx>
{
    poll: PollThread<Ctx, Types::ThreadTypes>
}

/// Cleanup object for [UnicastBus].
pub struct UnicastBusCleanup {
    poll_join: JoinHandle<()>
}

/// Type of errors that can occur when creating a [UnicastBus].
#[derive(Debug)]
pub enum UnicastBusCreateError<Poll> {
    /// Error while creating the [PollThread].
    Poll {
        /// The error that occurred while creating [StreamSelector]s.
        err: Poll
    },
}

impl<Ctx, Types> UnicastBus<Ctx, Types>
where
    Ctx: 'static + Send,
    Types: 'static + UnicastBusTypes<Ctx>
{
    pub fn create(
        config: UnicastBusConfig<
            Types::ChansConfig,
            Types::EpochsConfig,
            Types::ModeConfig,
            Types::MsgAuthConfig,
            Types::Addr
        >,
        ctx: Ctx,
        recv: Types::Recv,
        msgs: Types::Msgs
    ) -> Result<
        Self,
        UnicastBusCreateError<
            PollThreadCreateError<
                Types::ModeCreateError,
                Types::ChansCreateError,
                StreamSelectorCreateError<
                    Types::ResolveCreateError,
                    Types::EpochsCreateError
                >,
                Types::MsgAuthCreateError
            >
        >
    > {
        info!(target: "unicast-bus",
              "creating unicast bus");

        let poll_config = config.take();
        let poll = PollThread::create(poll_config, ctx, recv, msgs)
            .map_err(|err| UnicastBusCreateError::Poll { err: err })?;

        Ok(UnicastBus { poll: poll })
    }

    #[inline]
    pub fn notify(&self) -> Arc<Waker> {
        self.poll.notify()
    }

    /// Consume this `UnicastBus`, start the threads, and return a
    /// cleanup object.
    pub fn start(self) -> Result<UnicastBusCleanup, Error> {
        let UnicastBus { poll } = self;
        let poll_join = poll.start()?;

        Ok(UnicastBusCleanup {
            poll_join: poll_join
        })
    }
}

impl UnicastBusCleanup {
    pub fn cleanup(self) {
        debug!(target: "unicast-bus-cleanup",
               "joining poll thread");

        if self.poll_join.join().is_err() {
            error!(target: "unicast-bus-cleanup",
                   "error joining poll thread")
        }
    }
}

impl<Poll> Display for UnicastBusCreateError<Poll>
where Poll: Display {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            UnicastBusCreateError::Poll { err } => err.fmt(f),
        }
    }
}
