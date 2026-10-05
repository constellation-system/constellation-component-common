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

use constellation_channels::far::types::CompoundFarChannelsDatagramSelectorPollTypes;
use constellation_channels::far::types::CompoundFarChannelsLargeObjSelectorPollTypes;
use constellation_channels::resolve::cache::NSNameCachesCtx;
use constellation_common::config::Create;
use constellation_streams::large_obj::LargeObjProto;
use constellation_streams::large_obj::LargeObjProtoCreateError;
use constellation_streams::threads::poll::PollThread;
use log::debug;
use log::error;
use log::info;

use crate::config::UnicastDatagramBusConfig;
use crate::config::UnicastLargeObjBusConfig;
use crate::bus::types::UnicastDatagramBusTypes;
use crate::bus::types::UnicastLargeObjBusTypes;

pub struct UnicastDatagramBus<Types, Ctx>
where
    Types: UnicastDatagramBusTypes<Ctx>,
    Ctx: 'static + NSNameCachesCtx + Send {
    types: PhantomData<Types>,
    ctx: PhantomData<Ctx>,
    poll_join: JoinHandle<()>
}

pub struct UnicastLargeObjBus<Types, Ctx>
where
    Types: UnicastLargeObjBusTypes<Ctx>,
    Ctx: 'static + NSNameCachesCtx + Send {
    types: PhantomData<Types>,
    ctx: PhantomData<Ctx>,
    poll_join: JoinHandle<()>
}

#[derive(Debug)]
pub enum UnicastLargeObjBusCreateError<Hash, Auth, Proto> {
    Hash {
        err: Hash
    },
    IO {
        err: Error
    },
    Auth {
        err: Auth
    },
    Proto {
        err: Proto
    },
}

impl<Types, Ctx> UnicastDatagramBus<Types, Ctx>
where
    Types: 'static + UnicastDatagramBusTypes<Ctx>,
    Ctx: 'static + NSNameCachesCtx + Send {
    pub fn start(
        config: UnicastDatagramBusConfig<
            Types::SessionAuthConfig,
            Types::UnixConfig,
            Types::UDPConfig,
            Types::EncoderConfig,
            Types::DecoderConfig,
            Types::ResolverConfig,
            Types::EpochsConfig,
            Types::MsgAuthConfig
        >,
        ctx: Ctx,
        recv: Types::Recv,
        msgs: Types::Msgs
    ) -> Result<Self, Error> {
        info!(target: "unicast-datagram-bus",
              "creating unicast datagram bus");

        let poll_config = config.take();
        let poll_join = PollThread::<
            Ctx,
            CompoundFarChannelsDatagramSelectorPollTypes<
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
            >
        >::start(
            poll_config, None, ctx, recv, msgs
        )?;

        Ok(UnicastDatagramBus {
            types: PhantomData,
            ctx: PhantomData,
            poll_join: poll_join
        })
    }

    pub fn cleanup(self) {
        debug!(target: "unicast-datagram-bus-cleanup",
               "joining poll thread");

        if self.poll_join.join().is_err() {
            error!(target: "unicast-datagram-bus-cleanup",
                   "error joining poll thread")
        }
    }
}

impl<Types, Ctx> UnicastLargeObjBus<Types, Ctx>
where
    Types: 'static + UnicastLargeObjBusTypes<Ctx>,
    Ctx: 'static + NSNameCachesCtx + Send {
    pub fn start(
        config: UnicastLargeObjBusConfig<
            Types::HashConfig,
            Types::SessionAuthConfig,
            Types::LargeObjMsgAuthConfig,
            Types::UnixConfig,
            Types::UDPConfig,
            Types::EncoderConfig,
            Types::DecoderConfig,
            Types::IDsConfig,
            Types::ResolverConfig,
            Types::EpochsConfig,
            Types::MsgAuthConfig
        >,
        ctx: Ctx,
        recv: Types::Recv,
        msgs: Types::Msgs
    ) -> Result<
        Self,
        UnicastLargeObjBusCreateError<
            Types::HashCreateError,
            Types::MsgAuthCreateError,
            LargeObjProtoCreateError<
                Types::EncoderCreateError,
                Types::DecoderCreateError,
                Types::IDsCreateError
            >
        >
    > {
        info!(target: "unicast-large-obj-bus",
              "creating unicast large object bus");

        let (poll_config, large_obj_config, proto_auth_config, hash_config) =
            config.take();
        let hash = Types::Hash::create(hash_config)
            .map_err(|err| UnicastLargeObjBusCreateError::Hash {
                err: err
            })?;
        let msgauth = Types::MsgAuth::create(proto_auth_config)
            .map_err(|err| UnicastLargeObjBusCreateError::Auth {
                err: err
            })?;
        let large_obj =
            LargeObjProto::create(large_obj_config, recv, msgs, msgauth, hash)
            .map_err(|err| UnicastLargeObjBusCreateError::Proto {
                err: err
            })?;
        let large_obj = Arc::new(Mutex::new(large_obj));
        let poll_join = PollThread::<
            Ctx,
            CompoundFarChannelsLargeObjSelectorPollTypes<
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
            >
        >::start(
            poll_config, None, ctx, large_obj.clone(), large_obj
        )
            .map_err(|err| UnicastLargeObjBusCreateError::IO {
                err: err
            })?;

        Ok(UnicastLargeObjBus {
            types: PhantomData,
            ctx: PhantomData,
            poll_join: poll_join
        })
    }

    pub fn cleanup(self) {
        debug!(target: "unicast-large-obj-bus-cleanup",
               "joining poll thread");

        if self.poll_join.join().is_err() {
            error!(target: "unicast-large-obj-bus-cleanup",
                   "error joining poll thread")
        }
    }
}


impl<Hash, Auth, Proto> Display
    for UnicastLargeObjBusCreateError<Hash, Auth, Proto>
where
    Proto: Display,
    Auth: Display,
    Hash: Display {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            UnicastLargeObjBusCreateError::Proto { err } => err.fmt(f),
            UnicastLargeObjBusCreateError::Auth { err } => err.fmt(f),
            UnicastLargeObjBusCreateError::Hash { err } => err.fmt(f),
            UnicastLargeObjBusCreateError::IO { err } => write!(f, "{}", err)
        }
    }
}
