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

use constellation_channels::far::types::CompoundFarChannelsDatagramMulticastPollTypes;
use constellation_channels::far::types::CompoundFarChannelsLargeObjMulticastPollTypes;
use constellation_channels::resolve::cache::NSNameCachesCtx;
use constellation_common::config::Create;
use constellation_common::error::MutexPoison;
use constellation_common::retry::Retry;
use constellation_streams::large_obj::LargeObjProto;
use constellation_streams::large_obj::LargeObjProtoCreateError;
use constellation_streams::multicast::MulticastStreamIdx;
use constellation_streams::threads::poll::PollThread;
use log::debug;
use log::error;
use log::info;

use crate::bus::types::MulticastDatagramBusTypes;
use crate::bus::types::MulticastLargeObjBusTypes;
use crate::config::MulticastDatagramBusConfig;
use crate::config::MulticastLargeObjBusConfig;

pub struct MulticastDatagramBus<Types, Ctx>
where
    Types: MulticastDatagramBusTypes<Ctx>,
    Ctx: 'static + NSNameCachesCtx + Send {
    types: PhantomData<Types>,
    ctx: PhantomData<Ctx>,
    poll_join: JoinHandle<()>
}

pub struct MulticastLargeObjBus<Types, Ctx>
where
    Types: MulticastLargeObjBusTypes<Ctx>,
    Ctx: 'static + NSNameCachesCtx + Send {
    types: PhantomData<Types>,
    ctx: PhantomData<Ctx>,
    poll_join: JoinHandle<()>
}

#[derive(Debug)]
pub enum MulticastLargeObjBusCreateError<Hash, Auth, Proto, Parties> {
    Hash { err: Hash },
    IO { err: Error },
    Auth { err: Auth },
    Proto { err: Proto },
    Parties { err: Parties }
}

impl<Types, Ctx> MulticastDatagramBus<Types, Ctx>
where
    Types: 'static + MulticastDatagramBusTypes<Ctx>,
    Ctx: 'static + NSNameCachesCtx + Send
{
    pub fn start(
        config: MulticastDatagramBusConfig<
            Types::SessionPrin,
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
        info!(target: "multicast-datagram-bus",
              "creating multicast datagram bus");

        let (poll_config, self_party) = config.take();
        let poll_join =
            PollThread::<
                Ctx,
                CompoundFarChannelsDatagramMulticastPollTypes<
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
            >::start(poll_config, self_party, ctx, recv, msgs)?;

        Ok(MulticastDatagramBus {
            types: PhantomData,
            ctx: PhantomData,
            poll_join: poll_join
        })
    }

    pub fn cleanup(self) {
        debug!(target: "multicast-datagram-bus-cleanup",
               "joining poll thread");

        if self.poll_join.join().is_err() {
            error!(target: "multicast-datagram-bus-cleanup",
                   "error joining poll thread")
        }
    }
}

impl<Types, Ctx> MulticastLargeObjBus<Types, Ctx>
where
    Types: 'static + MulticastLargeObjBusTypes<Ctx>,
    Ctx: 'static + NSNameCachesCtx + Send
{
    pub fn start(
        config: MulticastLargeObjBusConfig<
            Types::SessionPrin,
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
        MulticastLargeObjBusCreateError<
            Types::HashCreateError,
            Types::MsgAuthCreateError,
            LargeObjProtoCreateError<
                Types::EncoderCreateError,
                Types::DecoderCreateError,
                Types::IDsCreateError
            >,
            MutexPoison
        >
    > {
        info!(target: "multicast-large-obj-bus",
              "creating multicast large object bus");

        let (
            poll_config,
            large_obj_config,
            proto_auth_config,
            hash_config,
            self_party
        ) = config.take();
        let hash = Types::Hash::create(hash_config).map_err(|err| {
            MulticastLargeObjBusCreateError::Hash { err: err }
        })?;
        let msgauth =
            Types::MsgAuth::create(proto_auth_config).map_err(|err| {
                MulticastLargeObjBusCreateError::Auth { err: err }
            })?;
        let mut large_obj =
            LargeObjProto::create(large_obj_config, recv, msgs, msgauth, hash)
                .map_err(|err| MulticastLargeObjBusCreateError::Proto {
                    err: err
                })?;

        // XXX this is a hacky and wrong way to set parties; it should
        // be done in the manager thread.
        let nparties = poll_config
            .stream()
            .parties()
            .iter()
            .filter(|ent| {
                self_party
                    .as_ref()
                    .is_none_or(|self_party| self_party != ent.party())
            })
            .count();
        let parties = poll_config
            .stream()
            .parties()
            .iter()
            .filter(|ent| {
                self_party
                    .as_ref()
                    .is_none_or(|self_party| self_party != ent.party())
            })
            .enumerate()
            .map(|(i, ent)| (MulticastStreamIdx::from(i), ent.party().clone()));
        let params = vec![Retry::default(); nparties];

        large_obj.set_parties(params, parties).map_err(|err| {
            MulticastLargeObjBusCreateError::Parties { err: err }
        })?;

        let large_obj = Arc::new(Mutex::new(large_obj));
        let poll_join = PollThread::<
            Ctx,
            CompoundFarChannelsLargeObjMulticastPollTypes<
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
            poll_config,
            self_party,
            ctx,
            large_obj.clone(),
            large_obj
        )
        .map_err(|err| MulticastLargeObjBusCreateError::IO { err: err })?;

        Ok(MulticastLargeObjBus {
            types: PhantomData,
            ctx: PhantomData,
            poll_join: poll_join
        })
    }

    pub fn cleanup(self) {
        debug!(target: "multicast-large-obj-bus-cleanup",
               "joining poll thread");

        if self.poll_join.join().is_err() {
            error!(target: "multicast-large-obj-bus-cleanup",
                   "error joining poll thread")
        }
    }
}

impl<Hash, Auth, Proto, Parties> Display
    for MulticastLargeObjBusCreateError<Hash, Auth, Proto, Parties>
where
    Parties: Display,
    Proto: Display,
    Auth: Display,
    Hash: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            MulticastLargeObjBusCreateError::Parties { err } => err.fmt(f),
            MulticastLargeObjBusCreateError::Proto { err } => err.fmt(f),
            MulticastLargeObjBusCreateError::Auth { err } => err.fmt(f),
            MulticastLargeObjBusCreateError::Hash { err } => err.fmt(f),
            MulticastLargeObjBusCreateError::IO { err } => write!(f, "{}", err)
        }
    }
}
