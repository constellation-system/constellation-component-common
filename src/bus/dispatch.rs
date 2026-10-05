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

use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::hash::Hash;
use std::io::Error;
use std::thread::JoinHandle;

use constellation_auth::authn::AuthNMsgRecv;
use constellation_auth::authn::AuthNed;
use constellation_auth::authn::MsgAuthN;
use constellation_common::config::Create;
use constellation_common::config::CreateWithParam;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::net::PrivateMsgs;
use constellation_common::shutdown::ShutdownFlag;
use constellation_common::sync::Notify;
use constellation_streams::channels::ChannelParam;
use constellation_streams::channels::Channels;
use constellation_streams::config::DispatchConfig;
use constellation_streams::select::dispatch::DispatchSelector;
use constellation_streams::select::dispatch::DispatchSelectorCreateError;
use constellation_streams::stream::PullStream;
use constellation_streams::stream::PushStream;
use constellation_streams::stream::StreamID;
use constellation_streams::threads::ThreadInnerCtx;
use constellation_streams::threads::dispatch::Dispatch;
use constellation_streams::threads::dispatch::DispatchThread;
use constellation_streams::threads::dispatch::DispatchThreadCtx;
use constellation_streams::threads::dispatch::Dispatched;
use constellation_streams::threads::types::DispatchTypes;
use log::debug;
use log::error;
use log::info;

use crate::config::DispatchBusConfig;

pub trait SessionDispatchTypes {
    type InMsg;
    type OutMsg;
    type Msgs: PrivateMsgs<Self::OutMsg>;
    type AuthNMsg: AuthNed<Self::MsgPrin>;
    type SessionPrin: Display;
    type MsgPrin: Clone + Display + Eq + Hash;
    type RecvError: Debug + Display + ScopedError;
    type Recv: 'static
        + AuthNMsgRecv<
            Self::MsgPrin,
            Self::AuthNMsg,
            RecvError = Self::RecvError
        >
        + Send;
}

pub trait DispatcherTypes<Ctx> {
    type Addr: Clone + Debug + Display + Eq + Hash + Send;
    type ChannelParam: Clone
        + Debug
        + Display
        + Eq
        + Hash
        + ChannelParam<Self::Addr>
        + Send;
    type ChannelID: Clone + Debug + Display + Eq + Hash + Send;
    type InMsg;
    type Wrapper;
    type OutMsg: Send;
    type SessionPrin: Clone + Display + Eq + Hash + Send;
    type MsgPrin: Clone + Display + Eq + Hash;
    type AuthNMsg: AuthNed<Self::MsgPrin>;
    type MsgAuthError: Debug + Display + ScopedError;
    type MsgAuthConfig: Clone;
    type MsgAuthCreateError: Debug + Display + ScopedError;
    type MsgAuth: Clone
        + MsgAuthN<
            Self::InMsg,
            Self::Wrapper,
            Prin = Self::MsgPrin,
            SessionPrin = Self::SessionPrin,
            AuthNMsg = Self::AuthNMsg,
            Error = Self::MsgAuthError
        > + Create<
            Config = Self::MsgAuthConfig,
            CreateError = Self::MsgAuthCreateError
        > + Send;
    type Epoch: Clone + Default + Display + Eq + Hash;
    type EpochsConfig: Clone + Default + Send;
    type EpochsCreateError: Debug + Display + ScopedError;
    type Epochs: Create<
            Config = Self::EpochsConfig,
            CreateError = Self::EpochsCreateError
        > + Iterator<Item = Self::Epoch>;
    type Msgs: PrivateMsgs<Self::OutMsg>;
    type RecvError: Debug + Display + ScopedError;
    type Recv: 'static
        + AuthNMsgRecv<
            Self::MsgPrin,
            Self::AuthNMsg,
            RecvError = Self::RecvError
        >
        + Send;
    type Chan: Clone
        + PullStream<Self::Wrapper, PullError = Self::PullError>
        + PushStream<DispatchThreadCtx<Self::Chans, Ctx>>;
    type ChansConfig: Send;
    type Chans:  for<'a> CreateWithParam<
            &'a mut ThreadInnerCtx<Ctx>,
            Config = Self::ChansConfig,
        > + Channels<
            ThreadInnerCtx<Ctx>,
            Addr = Self::Addr,
            Param = Self::ChannelParam,
            ChannelID = Self::ChannelID,
        >;
    type ModeConfig: Clone + Send;
    type SessionDispTypes: SessionDispatchTypes<
            InMsg = Self::InMsg,
            OutMsg = Self::OutMsg,
            Msgs = Self::Msgs,
            AuthNMsg = Self::AuthNMsg,
            SessionPrin = Self::SessionPrin,
            MsgPrin = Self::MsgPrin,
            Recv = Self::Recv,
            RecvError = Self::RecvError
        >;
    type DispTypes: DispatchTypes<
            Ctx,
            InMsg = Self::InMsg,
            Wrapper = Self::Wrapper,
            OutMsg = Self::OutMsg,
            SessionPrin = Self::SessionPrin,
            MsgPrin = Self::MsgPrin,
            AuthNMsg = Self::AuthNMsg,
            Chans = Self::Chans,
            ChansConfig = Self::ChansConfig,
            ModeConfig = Self::ModeConfig,
            Msgs = Self::Msgs,
            Recv = Self::Recv,
            Stream = DispatchSelector<
                Self::Epochs,
                StreamID<Self::Addr, Self::ChannelID, Self::ChannelParam>,
                Self::Chan,
                DispatchThreadCtx<Self::Chans, Ctx>
            >,
            MsgAuthError = Self::MsgAuthError,
            MsgAuth = Self::MsgAuth
        >;
    type SessionDispError: Debug + Display + ScopedError;
    type SessionDisp: SessionDispatch<
            Self::SessionDispTypes,
            SessionError = Self::SessionDispError
        >;
    type PullError: Debug + Display + ScopedError;
}

pub trait DispatchBusTypes<Ctx> {
    type InMsg;
    type OutMsg: Send;
    type SessionPrin: Clone + Display + Eq + Hash + Send;
    type MsgPrin: Clone + Display + Eq + Hash;
    type AuthNMsg: AuthNed<Self::MsgPrin>;
    type MsgAuthConfig: Clone + Send;
    type EpochsConfig: Clone + Default + Send;
    type ChansConfig: Send;
    type ModeConfig: Clone + Default + Send;
    type SessionDispTypes: SessionDispatchTypes<
            InMsg = Self::InMsg,
            OutMsg = Self::OutMsg,
            AuthNMsg = Self::AuthNMsg,
            SessionPrin = Self::SessionPrin,
            MsgPrin = Self::MsgPrin
        >;
    type SessionDisp: SessionDispatch<Self::SessionDispTypes> + Send;
    type DispTypes: DispatcherTypes<
            Ctx,
            InMsg = Self::InMsg,
            OutMsg = Self::OutMsg,
            SessionPrin = Self::SessionPrin,
            MsgPrin = Self::MsgPrin,
            AuthNMsg = Self::AuthNMsg,
            MsgAuthConfig = Self::MsgAuthConfig,
            EpochsConfig = Self::EpochsConfig,
            ChansConfig = Self::ChansConfig,
            ModeConfig = Self::ModeConfig,
            SessionDisp = Self::SessionDisp
        >;
    type DispThreadTypes: DispatchTypes<
            Ctx,
            InMsg = Self::InMsg,
            OutMsg = Self::OutMsg,
            SessionPrin = Self::SessionPrin,
            MsgPrin = Self::MsgPrin,
            AuthNMsg = Self::AuthNMsg,
            ChansConfig = Self::ChansConfig,
            ModeConfig = Self::ModeConfig,
            ModeConfig = Self::ModeConfig
        >;
}

/// Trait for application-level session dispatch.
pub trait SessionDispatch<Types>
where
    Types: SessionDispatchTypes {
    /// Type of errors that can occur dispatching a session.
    type SessionError: Debug + Display + ScopedError;

    /// Dispatch a new session.
    ///
    /// # Parameters
    ///
    /// - `prin`: The principal for which the session is being created.
    ///
    /// - `shutdown`: The [ShutdownFlag] from which to derive this session's
    ///   `ShutdownFlag`.
    ///
    /// - `notify`: The [Notify] to use to signal available messages.
    fn session(
        &self,
        prin: &Types::SessionPrin,
        shutdown: ShutdownFlag,
        notify: Notify
    ) -> Result<(ShutdownFlag, Types::Msgs, Types::Recv), Self::SessionError>;
}

/// Type of errors that can occur when creating a [DispatchBus].
#[derive(Debug)]
pub enum DispatchError<Session, Stream, Auth> {
    /// Error acquiring session.
    Session {
        /// The error that occurred while acquiring the session.
        err: Session
    },
    /// Error creating message authenticator.
    Auth {
        /// The error that occurred while creating the message authenticator.
        err: Auth
    },
    /// Error while creating [DispatchSelector]s.
    Stream {
        /// The error that occurred while creating [StreamSelector]s.
        err: Stream
    }
}

/// Cleanup object for [UnicastComm].
pub struct DispatchBus {
    join_handle: JoinHandle<()>
}

pub struct Dispatcher<Types, Ctx>
where
    Types: DispatcherTypes<Ctx> {
    session: Types::SessionDisp,
    config: DispatchConfig<Types::EpochsConfig>,
    auth_config: Types::MsgAuthConfig
}

impl<Types, Ctx> Dispatch<Types::DispTypes, Ctx> for Dispatcher<Types, Ctx>
where
    Types: DispatcherTypes<Ctx>
{
    type DispatchError = DispatchError<
        Types::SessionDispError,
        DispatchSelectorCreateError<Types::EpochsCreateError>,
        Types::MsgAuthCreateError
    >;

    /// Obtain the components of a new private session.
    fn dispatch(
        &mut self,
        ctx: &mut DispatchThreadCtx<Types::Chans, Ctx>,
        prin: &Types::SessionPrin,
        shutdown: ShutdownFlag,
        notify: Notify
    ) -> Result<
        Dispatched<
            Types::DispTypes,
            Ctx
        >,
        Self::DispatchError
    > {
        let (shutdown, msgs, recv) = self
            .session
            .session(prin, shutdown, notify)
            .map_err(|err| DispatchError::Session { err: err })?;
        let stream = DispatchSelector::create(self.config.clone(), ctx)
            .map_err(|err| DispatchError::Stream { err: err })?;
        let authn = Types::MsgAuth::create(self.auth_config.clone())
            .map_err(|err| DispatchError::Auth { err: err })?;
        let dispatched = Dispatched::new(shutdown, stream, msgs, authn, recv);

        Ok(dispatched)
    }
}

impl DispatchBus {
    pub fn start<Types, Ctx>(
        config: DispatchBusConfig<
            Types::ChansConfig,
            Types::EpochsConfig,
            Types::ModeConfig,
            Types::MsgAuthConfig
        >,
        session: Types::SessionDisp,
        ctx: Ctx
    ) -> Result<Self, Error>
    where
        Types: 'static + DispatchBusTypes<Ctx>,
        Ctx: 'static + Send
    {
        info!(target: "dispatch-datagram-bus",
              "creating dispatch bus");

        let (auth_config, dispatch_config, thread_config) = config.take();

        let dispatcher: Dispatcher<Types::DispTypes, _> = Dispatcher {
            session: session,
            config: dispatch_config,
            auth_config: auth_config
        };
        let join_handle = DispatchThread::start(
            thread_config, dispatcher, ctx
        )?;

        Ok(DispatchBus { join_handle: join_handle })
    }

    pub fn cleanup(self) {
        debug!(target: "dispatch-bus-cleanup",
               "joining pull streams");

        if self.join_handle.join().is_err() {
            error!(target: "dispatch-bus-cleanup",
                   "error joining pull streams listener")
        }
    }
}

impl<Session, Stream, Auth> ScopedError for DispatchError<Session, Stream, Auth>
where
    Session: ScopedError,
    Stream: ScopedError,
    Auth: ScopedError
{
    #[inline]
    fn scope(&self) -> ErrorScope {
        match self {
            DispatchError::Session { err } => err.scope(),
            DispatchError::Stream { err } => err.scope(),
            DispatchError::Auth { err } => err.scope()
        }
    }
}

impl<Session, Stream, Auth> Display for DispatchError<Session, Stream, Auth>
where
    Session: Display,
    Stream: Display,
    Auth: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            DispatchError::Session { err } => err.fmt(f),
            DispatchError::Auth { err } => err.fmt(f),
            DispatchError::Stream { err } => write!(f, "{}", err)
        }
    }
}
