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
use std::io::Error;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread::JoinHandle;

use constellation_channels::far::channels::CompoundFarChannels;
use constellation_channels::far::types::CompoundFarChannelsDatagramDispatchTypes;
use constellation_channels::far::types::CompoundFarChannelsLargeObjDispatchTypes;
use constellation_channels::resolve::cache::NSNameCachesCtx;
use constellation_common::config::Create;
use constellation_common::config::CreateWithParam;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::shutdown::ShutdownFlag;
use constellation_common::sync::Notify;
use constellation_streams::config::DispatchConfig;
use constellation_streams::config::LargeObjProtoConfig;
use constellation_streams::large_obj::LargeObjMsg;
use constellation_streams::large_obj::LargeObjMsgCodec;
use constellation_streams::large_obj::LargeObjProto;
use constellation_streams::large_obj::LargeObjProtoCreateError;
use constellation_streams::select::dispatch::DispatchSelector;
use constellation_streams::select::dispatch::DispatchSelectorCreateError;
use constellation_streams::threads::dispatch::Dispatch;
use constellation_streams::threads::dispatch::DispatchThread;
use constellation_streams::threads::dispatch::DispatchThreadCtx;
use constellation_streams::threads::dispatch::Dispatched;
use log::debug;
use log::error;
use log::info;

use crate::bus::types::DispatchDatagramBusTypes;
use crate::bus::types::DispatchLargeObjBusTypes;
use crate::bus::types::SessionDispatchTypes;
use crate::config::DispatchDatagramBusConfig;
use crate::config::DispatchLargeObjBusConfig;

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

#[derive(Debug)]
pub enum DatagramDispatchError<Session, Stream, Auth> {
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
#[derive(Debug)]
pub enum LargeObjDispatchError<Session, Stream, Hash, ProtoAuth, Auth, Proto> {
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
    /// Error creating message authenticator.
    ProtoAuth {
        /// The error that occurred while creating the message authenticator.
        err: ProtoAuth
    },
    /// Error creating protocol instance.
    Proto {
        /// The error that occurred while creating the protocol instance.
        err: Proto
    },
    /// Error creating hash algorithm.
    Hash {
        /// The error that occurred while creating the hash algorithm.
        err: Hash
    },
    /// Error while creating [DispatchSelector]s.
    Stream {
        /// The error that occurred while creating [StreamSelector]s.
        err: Stream
    }
}

pub struct DispatchDatagramBus<Types, Ctx>
where
    Types: 'static + DispatchDatagramBusTypes<Ctx>,
    Ctx: 'static + NSNameCachesCtx + Send {
    types: PhantomData<Types>,
    ctx: PhantomData<Ctx>,
    join_handle: JoinHandle<()>
}

pub struct DispatchLargeObjBus<Types, Ctx>
where
    Types: 'static + DispatchLargeObjBusTypes<Ctx>,
    Ctx: 'static + NSNameCachesCtx + Send {
    types: PhantomData<Types>,
    ctx: PhantomData<Ctx>,
    join_handle: JoinHandle<()>
}

struct DatagramDispatcher<Types, SessionDisp, Ctx>
where
    SessionDisp: SessionDispatch<Types::DispTypes>,
    Types: DispatchDatagramBusTypes<Ctx>,
    Ctx: 'static + NSNameCachesCtx + Send {
    session: SessionDisp,
    config: DispatchConfig<Types::EpochsConfig>,
    auth_config: Types::MsgAuthConfig
}

struct LargeObjDispatcher<Types, SessionDisp, Ctx>
where
    SessionDisp: SessionDispatch<Types::DispTypes>,
    Types: DispatchLargeObjBusTypes<Ctx>,
    Ctx: 'static + NSNameCachesCtx + Send {
    session: SessionDisp,
    config: DispatchConfig<Types::EpochsConfig>,
    proto_config: LargeObjProtoConfig<
        Types::EncoderConfig,
        Types::DecoderConfig,
        Types::IDsConfig
    >,
    proto_auth_config: Types::LargeObjMsgAuthConfig,
    msg_auth_config: Types::MsgAuthConfig,
    hash_config: Types::HashConfig
}

impl<Types, SessionDisp, Ctx>
    Dispatch<
        CompoundFarChannelsDatagramDispatchTypes<
            Types::InMsg,
            Types::OutMsg,
            Types::Wrapper,
            Types::Encoder,
            Types::Decoder,
            Types::AuthNChan,
            Types::SessionAuth,
            Types::MsgAuth,
            Types::Unix,
            Types::UDP,
            Types::Epochs,
            Types::Resolver,
            Types::Msgs,
            Types::Recv,
            Ctx
        >,
        Ctx
    > for DatagramDispatcher<Types, SessionDisp, Ctx>
where
    SessionDisp: SessionDispatch<Types::DispTypes>,
    Types: DispatchDatagramBusTypes<Ctx>,
    Ctx: 'static + NSNameCachesCtx + Send
{
    type DispatchError = DatagramDispatchError<
        SessionDisp::SessionError,
        DispatchSelectorCreateError<Types::EpochsCreateError>,
        Types::MsgAuthCreateError
    >;

    /// Obtain the components of a new private session.
    fn dispatch(
        &mut self,
        ctx: &mut DispatchThreadCtx<
            CompoundFarChannels<
                Types::SessionAuth,
                Types::AuthNChan,
                Types::Unix,
                Types::UDP,
                Types::OutMsg,
                Types::Wrapper,
                Types::Encoder,
                Types::Decoder
            >,
            Ctx
        >,
        prin: &Types::SessionPrin,
        shutdown: ShutdownFlag,
        notify: Notify
    ) -> Result<
        Dispatched<
            CompoundFarChannelsDatagramDispatchTypes<
                Types::InMsg,
                Types::OutMsg,
                Types::Wrapper,
                Types::Encoder,
                Types::Decoder,
                Types::AuthNChan,
                Types::SessionAuth,
                Types::MsgAuth,
                Types::Unix,
                Types::UDP,
                Types::Epochs,
                Types::Resolver,
                Types::Msgs,
                Types::Recv,
                Ctx
            >,
            Ctx
        >,
        Self::DispatchError
    > {
        let (shutdown, msgs, recv) = self
            .session
            .session(prin, shutdown, notify)
            .map_err(|err| DatagramDispatchError::Session { err: err })?;
        let stream = DispatchSelector::create(self.config.clone(), ctx)
            .map_err(|err| DatagramDispatchError::Stream { err: err })?;
        let authn = Types::MsgAuth::create(self.auth_config.clone())
            .map_err(|err| DatagramDispatchError::Auth { err: err })?;
        let dispatched = Dispatched::new(shutdown, stream, msgs, authn, recv);

        Ok(dispatched)
    }
}

impl<Types, SessionDisp, Ctx>
    Dispatch<
        CompoundFarChannelsLargeObjDispatchTypes<
            Types::InMsg,
            Types::OutMsg,
            Types::LargeObjWrapper,
            Types::LargeObjMsgAuth,
            Types::AuthNChan,
            Types::SessionAuth,
            Types::Unix,
            Types::UDP,
            Types::Epochs,
            Types::Resolver,
            Types::LargeObjTypes,
            Ctx
        >,
        Ctx
    > for LargeObjDispatcher<Types, SessionDisp, Ctx>
where
    SessionDisp: SessionDispatch<Types::DispTypes>,
    Types: DispatchLargeObjBusTypes<Ctx>,
    Ctx: 'static + NSNameCachesCtx + Send
{
    type DispatchError = LargeObjDispatchError<
        SessionDisp::SessionError,
        DispatchSelectorCreateError<Types::EpochsCreateError>,
        Types::HashCreateError,
        Types::LargeObjMsgAuthCreateError,
        Types::MsgAuthCreateError,
        LargeObjProtoCreateError<
            Types::EncoderCreateError,
            Types::DecoderCreateError,
            Types::IDsCreateError
        >
    >;

    /// Obtain the components of a new private session.
    fn dispatch(
        &mut self,
        ctx: &mut DispatchThreadCtx<
            CompoundFarChannels<
                Types::SessionAuth,
                Types::AuthNChan,
                Types::Unix,
                Types::UDP,
                LargeObjMsg<Types::HashID>,
                LargeObjMsg<Types::HashID>,
                LargeObjMsgCodec<Types::Hash>,
                LargeObjMsgCodec<Types::Hash>
            >,
            Ctx
        >,
        prin: &Types::SessionPrin,
        shutdown: ShutdownFlag,
        notify: Notify
    ) -> Result<
        Dispatched<
            CompoundFarChannelsLargeObjDispatchTypes<
                Types::InMsg,
                Types::OutMsg,
                Types::LargeObjWrapper,
                Types::LargeObjMsgAuth,
                Types::AuthNChan,
                Types::SessionAuth,
                Types::Unix,
                Types::UDP,
                Types::Epochs,
                Types::Resolver,
                Types::LargeObjTypes,
                Ctx
            >,
            Ctx
        >,
        Self::DispatchError
    > {
        let (shutdown, msgs, recv) = self
            .session
            .session(prin, shutdown, notify)
            .map_err(|err| LargeObjDispatchError::Session { err: err })?;
        let hash = Types::Hash::create(self.hash_config.clone())
            .map_err(|err| LargeObjDispatchError::Hash { err: err })?;
        let stream = DispatchSelector::create(self.config.clone(), ctx)
            .map_err(|err| LargeObjDispatchError::Stream { err: err })?;
        let authn = Types::MsgAuth::create(self.msg_auth_config.clone())
            .map_err(|err| LargeObjDispatchError::Auth { err: err })?;
        let large_obj = LargeObjProto::create(
            self.proto_config.clone(),
            recv,
            msgs,
            authn,
            hash
        )
        .map_err(|err| LargeObjDispatchError::Proto { err: err })?;
        let large_obj = Arc::new(Mutex::new(large_obj));
        let proto_authn =
            Types::LargeObjMsgAuth::create(self.proto_auth_config.clone())
                .map_err(|err| LargeObjDispatchError::ProtoAuth { err: err })?;
        let dispatched = Dispatched::new(
            shutdown,
            stream,
            large_obj.clone(),
            proto_authn,
            large_obj
        );

        Ok(dispatched)
    }
}

impl<Types, Ctx> DispatchDatagramBus<Types, Ctx>
where
    Types: 'static + DispatchDatagramBusTypes<Ctx>,
    Ctx: 'static + NSNameCachesCtx + Send
{
    pub fn start<SessionDisp>(
        config: DispatchDatagramBusConfig<
            Types::SessionAuthConfig,
            Types::MsgAuthConfig,
            Types::UnixConfig,
            Types::UDPConfig,
            Types::EncoderConfig,
            Types::DecoderConfig,
            Types::EpochsConfig
        >,
        session: SessionDisp,
        ctx: Ctx
    ) -> Result<Self, Error>
    where
        SessionDisp: 'static + SessionDispatch<Types::DispTypes> + Send {
        info!(target: "dispatch-datagram-bus",
              "creating dispatch bus");

        let (auth_config, dispatch_config, thread_config) = config.take();

        let dispatcher: DatagramDispatcher<Types, SessionDisp, _> =
            DatagramDispatcher {
                session: session,
                config: dispatch_config,
                auth_config: auth_config
            };
        let join_handle = DispatchThread::<
            CompoundFarChannelsDatagramDispatchTypes<
                Types::InMsg,
                Types::OutMsg,
                Types::Wrapper,
                Types::Encoder,
                Types::Decoder,
                Types::AuthNChan,
                Types::SessionAuth,
                Types::MsgAuth,
                Types::Unix,
                Types::UDP,
                Types::Epochs,
                Types::Resolver,
                Types::Msgs,
                Types::Recv,
                Ctx
            >,
            _,
            _
        >::start(thread_config, dispatcher, ctx)?;

        Ok(DispatchDatagramBus {
            types: PhantomData,
            ctx: PhantomData,
            join_handle: join_handle
        })
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

impl<Types, Ctx> DispatchLargeObjBus<Types, Ctx>
where
    Types: 'static + DispatchLargeObjBusTypes<Ctx>,
    Ctx: 'static + NSNameCachesCtx + Send
{
    pub fn start<SessionDisp>(
        config: DispatchLargeObjBusConfig<
            Types::HashConfig,
            Types::SessionAuthConfig,
            Types::MsgAuthConfig,
            Types::LargeObjMsgAuthConfig,
            Types::UnixConfig,
            Types::UDPConfig,
            Types::EncoderConfig,
            Types::DecoderConfig,
            Types::IDsConfig,
            Types::EpochsConfig
        >,
        session: SessionDisp,
        ctx: Ctx
    ) -> Result<Self, Error>
    where
        SessionDisp: 'static + SessionDispatch<Types::DispTypes> + Send {
        info!(target: "dispatch-datagram-bus",
              "creating dispatch bus");

        let (
            msg_auth_config,
            dispatch_config,
            thread_config,
            proto_config,
            proto_auth_config,
            hash_config
        ) = config.take();
        let dispatcher: LargeObjDispatcher<Types, SessionDisp, _> =
            LargeObjDispatcher {
                session: session,
                config: dispatch_config,
                proto_auth_config: proto_auth_config,
                msg_auth_config: msg_auth_config,
                proto_config: proto_config,
                hash_config: hash_config
            };
        let join_handle = DispatchThread::<
            CompoundFarChannelsLargeObjDispatchTypes<
                Types::InMsg,
                Types::OutMsg,
                Types::LargeObjWrapper,
                Types::LargeObjMsgAuth,
                Types::AuthNChan,
                Types::SessionAuth,
                Types::Unix,
                Types::UDP,
                Types::Epochs,
                Types::Resolver,
                Types::LargeObjTypes,
                Ctx
            >,
            _,
            _
        >::start(thread_config, dispatcher, ctx)?;

        Ok(DispatchLargeObjBus {
            types: PhantomData,
            ctx: PhantomData,
            join_handle: join_handle
        })
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

impl<Session, Stream, Auth> ScopedError
    for DatagramDispatchError<Session, Stream, Auth>
where
    Session: ScopedError,
    Stream: ScopedError,
    Auth: ScopedError
{
    #[inline]
    fn scope(&self) -> ErrorScope {
        match self {
            DatagramDispatchError::Session { err } => err.scope(),
            DatagramDispatchError::Stream { err } => err.scope(),
            DatagramDispatchError::Auth { err } => err.scope()
        }
    }
}

impl<Session, Stream, Hash, ProtoAuth, Auth, Proto> ScopedError
    for LargeObjDispatchError<Session, Stream, Hash, ProtoAuth, Auth, Proto>
where
    Session: ScopedError,
    Stream: ScopedError,
    Hash: ScopedError,
    ProtoAuth: ScopedError,
    Auth: ScopedError,
    Proto: ScopedError
{
    #[inline]
    fn scope(&self) -> ErrorScope {
        match self {
            LargeObjDispatchError::Session { err } => err.scope(),
            LargeObjDispatchError::Stream { err } => err.scope(),
            LargeObjDispatchError::ProtoAuth { err } => err.scope(),
            LargeObjDispatchError::Auth { err } => err.scope(),
            LargeObjDispatchError::Hash { err } => err.scope(),
            LargeObjDispatchError::Proto { err } => err.scope()
        }
    }
}

impl<Session, Stream, Auth> Display
    for DatagramDispatchError<Session, Stream, Auth>
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
            DatagramDispatchError::Session { err } => err.fmt(f),
            DatagramDispatchError::Auth { err } => err.fmt(f),
            DatagramDispatchError::Stream { err } => write!(f, "{}", err)
        }
    }
}

impl<Session, Stream, Hash, ProtoAuth, Auth, Proto> Display
    for LargeObjDispatchError<Session, Stream, Hash, ProtoAuth, Auth, Proto>
where
    Session: Display,
    Stream: Display,
    Hash: Display,
    ProtoAuth: Display,
    Auth: Display,
    Proto: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            LargeObjDispatchError::Session { err } => err.fmt(f),
            LargeObjDispatchError::Hash { err } => err.fmt(f),
            LargeObjDispatchError::Auth { err } => err.fmt(f),
            LargeObjDispatchError::ProtoAuth { err } => err.fmt(f),
            LargeObjDispatchError::Proto { err } => err.fmt(f),
            LargeObjDispatchError::Stream { err } => write!(f, "{}", err)
        }
    }
}
