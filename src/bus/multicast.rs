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
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread::JoinHandle;

use constellation_auth::authn::MsgAuthNTypes;
use constellation_channels::far::types::CompoundFarChannelsDatagramMulticastPollTypes;
use constellation_channels::far::types::CompoundFarChannelsLargeObjMulticastPollTypes;
use constellation_channels::resolve::cache::NSNameCachesCtx;
use constellation_common::codec::Decoder;
use constellation_common::config::Create;
use constellation_common::error::MutexPoison;
use constellation_common::retry::Retry;
use constellation_common::shutdown::ShutdownFlag;
use constellation_streams::large_obj::LargeObjProto;
use constellation_streams::large_obj::LargeObjProtoCreateError;
use constellation_streams::large_obj::LargeObjProtoTypes;
use constellation_streams::multicast::MulticastStreamIdx;
use constellation_streams::threads::poll::PollThread;
use constellation_streams::threads::poll::PollThreadStartError;
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
    shutdown: ShutdownFlag,
    poll_join: JoinHandle<()>
}

pub struct MulticastLargeObjBus<Types, Ctx>
where
    Types: MulticastLargeObjBusTypes<Ctx>,
    Ctx: 'static + NSNameCachesCtx + Send {
    types: PhantomData<Types>,
    ctx: PhantomData<Ctx>,
    shutdown: ShutdownFlag,
    poll_join: JoinHandle<()>
}

struct BusMsgAuthNTypes<Types, Ctx>
where
    Types: MulticastLargeObjBusTypes<Ctx>,
    Ctx: 'static + NSNameCachesCtx + Send {
    types: PhantomData<Types>,
    ctx: PhantomData<Ctx>
}

struct BusLargeObjTypes<Types, Ctx>
where
    Types: MulticastLargeObjBusTypes<Ctx>,
    Ctx: 'static + NSNameCachesCtx + Send {
    types: PhantomData<Types>,
    ctx: PhantomData<Ctx>
}

#[derive(Debug)]
pub enum MulticastLargeObjBusCreateError<Hash, Auth, Proto, Parties> {
    Hash { err: Hash },
    Start { err: PollThreadStartError },
    Auth { err: Auth },
    Proto { err: Proto },
    Parties { err: Parties }
}

impl<Types, Ctx> MsgAuthNTypes<Types::InMsg> for BusMsgAuthNTypes<Types, Ctx>
where
    Types: MulticastLargeObjBusTypes<Ctx>,
    Ctx: 'static + NSNameCachesCtx + Send
{
    type AuthNError = Types::MsgAuthError;
    type DecodeError = <Types::Decoder as Decoder<Types::Wrapper>>::DecodeError;
    type Decoder = Types::Decoder;
    type DecoderConfig = Types::DecoderConfig;
    type MsgAuthN = Types::MsgAuth;
    type Prin = Types::MsgPrin;
    type SessionPrin = Types::SessionPrin;
    type Wrapper = Types::Wrapper;
}

impl<Types, Ctx> LargeObjProtoTypes<Types::InMsg, Types::OutMsg>
    for BusLargeObjTypes<Types, Ctx>
where
    Types: MulticastLargeObjBusTypes<Ctx>,
    Ctx: 'static + NSNameCachesCtx + Send
{
    type AuthNError = Types::MsgAuthError;
    type AuthNMsg = Types::AuthNMsg;
    type AuthNTypes = BusMsgAuthNTypes<Types, Ctx>;
    type DecodeError = <Types::Decoder as Decoder<Types::Wrapper>>::DecodeError;
    type Decoder = Types::Decoder;
    type DecoderConfig = Types::DecoderConfig;
    type EncodeError = Types::EncodeError;
    type Encoder = Types::Encoder;
    type EncoderConfig = Types::EncoderConfig;
    type Hash = Types::Hash;
    type HashID = Types::HashID;
    type IDs = Types::IDs;
    type IDsConfig = Types::IDsConfig;
    type MsgAuthN = Types::MsgAuth;
    type Msgs = Types::Msgs;
    type Prin = Types::MsgPrin;
    type Recv = Types::Recv;
    type SessionPrin = Types::SessionPrin;
    type Wrapper = Types::Wrapper;
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
    ) -> Result<Self, PollThreadStartError> {
        info!(target: "multicast-datagram-bus",
              "creating multicast datagram bus");

        let (poll_config, self_party) = config.take();
        let (poll_join, shutdown) =
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
            shutdown: shutdown,
            poll_join: poll_join
        })
    }

    #[inline]
    pub fn shutdown_flag(&self) -> ShutdownFlag {
        self.shutdown.clone()
    }

    pub fn cleanup(mut self) {
        if let Err(err) = self.shutdown.set() {
            error!(target: "multicast-datagram-bus-cleanup",
                   "error setting shutdown flag: {}",
                   err)
        }

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
    Types: 'static + MulticastLargeObjBusTypes<Ctx> + Send,
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
        (Self, Vec<(MulticastStreamIdx, Types::SessionPrin)>),
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
        let parties: Vec<(MulticastStreamIdx, Types::SessionPrin)> =
            poll_config
                .stream()
                .parties()
                .iter()
                .filter(|ent| {
                    self_party
                        .as_ref()
                        .is_none_or(|self_party| self_party != ent.party())
                })
                .enumerate()
                .map(|(i, ent)| {
                    (MulticastStreamIdx::from(i), ent.party().clone())
                })
                .collect();
        let params = vec![Retry::default(); parties.len()];

        large_obj
            .set_parties(params, parties.iter().cloned())
            .map_err(|err| MulticastLargeObjBusCreateError::Parties {
                err: err
            })?;

        let large_obj = Arc::new(Mutex::new(large_obj));
        let (poll_join, shutdown) = PollThread::<
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
                BusLargeObjTypes<Types, Ctx>,
                Ctx
            >
        >::start(
            poll_config,
            self_party,
            ctx,
            large_obj.clone(),
            large_obj
        )
        .map_err(|err| MulticastLargeObjBusCreateError::Start { err: err })?;

        Ok((
            MulticastLargeObjBus {
                types: PhantomData,
                ctx: PhantomData,
                shutdown: shutdown,
                poll_join: poll_join
            },
            parties
        ))
    }

    pub fn cleanup(mut self) {
        if let Err(err) = self.shutdown.set() {
            error!(target: "multicast-large-obj-bus-cleanup",
                   "error setting shutdown flag: {}",
                   err)
        }

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
            MulticastLargeObjBusCreateError::Start { err } => {
                write!(f, "{}", err)
            }
        }
    }
}
