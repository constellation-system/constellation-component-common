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

use constellation_channels::config::CompoundFarMulticastPollThreadConfig;
use constellation_channels::config::CompoundFarSelectorPollThreadConfig;
use constellation_channels::config::ResolverConfig;
use constellation_streams::config::DispatchConfig;
use constellation_streams::config::DispatchThreadConfig;
use constellation_streams::config::LargeObjProtoConfig;
use constellation_streams::config::PartyConfig;
use constellation_streams::config::PrivateDatagramModeConfig;
use constellation_streams::config::PrivateLargeObjModeConfig;
use constellation_streams::config::SharedDatagramModeConfig;
use constellation_streams::config::SharedLargeObjModeConfig;
use serde::Deserialize;
use serde::Serialize;

pub type DispatchDatagramBusConfig<Channels, Epochs, Auth> =
    DispatchBusConfig<Channels, Epochs, PrivateDatagramModeConfig, Auth>;

pub type DispatchLargeObjBusConfig<Channels, Epochs, Auth> =
    DispatchBusConfig<Channels, Epochs, PrivateLargeObjModeConfig, Auth>;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename = "multicast-datagram-bus")]
#[serde(rename_all = "kebab-case")]
pub struct MulticastDatagramBusConfig<
    Party,
    AuthN,
    Unix,
    UDP,
    Enc,
    Dec,
    Resolver,
    Epochs,
    MsgAuthN
>
where
    Epochs: Default,
    Resolver: Default,
    Enc: Default,
    Dec: Default,
    Unix: Default,
    UDP: Default {
    #[serde(flatten)]
    thread: CompoundFarMulticastPollThreadConfig<
        AuthN,
        Unix,
        UDP,
        Enc,
        Dec,
        SharedDatagramModeConfig,
        Party,
        Resolver,
        Epochs,
        String,
        MsgAuthN
    >,
    #[serde(rename = "self")]
    #[serde(default)]
    self_party: Option<Party>
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename = "multicast-large-obj-bus")]
#[serde(rename_all = "kebab-case")]
pub struct MulticastLargeObjBusConfig<Party, Hash, AuthN, ProtoAuthN, Unix, UDP,
                                      Enc, Dec, IDs, Resolver, Epochs, MsgAuthN>
where
    Epochs: Default,
    Resolver: Default,
    Hash: Default,
    Enc: Default,
    Dec: Default,
    IDs: Default,
    Unix: Default,
    UDP: Default {
    #[serde(flatten)]
    thread: CompoundFarMulticastPollThreadConfig<
        AuthN,
        Unix,
        UDP,
        (),
        (),
        SharedLargeObjModeConfig,
        Party,
        Resolver,
        Epochs,
        String,
        ProtoAuthN
    >,
    #[serde(flatten)]
    large_obj: LargeObjProtoConfig<Enc, Dec, IDs>,
    large_obj_msg_authn: MsgAuthN,
    #[serde(default)]
    hash: Hash,
    #[serde(rename = "self")]
    #[serde(default)]
    self_party: Option<Party>
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename = "unicast-datagram-bus")]
#[serde(rename_all = "kebab-case")]
pub struct UnicastDatagramBusConfig<AuthN, Unix, UDP, Enc, Dec,
                                    Resolver, Epochs, MsgAuthN>
where
    Epochs: Default,
    Resolver: Default,
    Enc: Default,
    Dec: Default,
    Unix: Default,
    UDP: Default {
    #[serde(flatten)]
    thread: CompoundFarSelectorPollThreadConfig<
        AuthN, Unix, UDP, Enc, Dec, PrivateDatagramModeConfig,
        Resolver, Epochs, String, MsgAuthN
    >
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename = "unicast-large-obj-bus")]
#[serde(rename_all = "kebab-case")]
pub struct UnicastLargeObjBusConfig<Hash, AuthN, ProtoAuthN, Unix, UDP,
                                    Enc, Dec, IDs, Resolver, Epochs, MsgAuthN>
where
    Epochs: Default,
    Resolver: Default,
    Hash: Default,
    Enc: Default,
    Dec: Default,
    IDs: Default,
    Unix: Default,
    UDP: Default {
    #[serde(flatten)]
    thread: CompoundFarSelectorPollThreadConfig<
        AuthN, Unix, UDP, (), (), PrivateLargeObjModeConfig,
        Resolver, Epochs, String, ProtoAuthN
    >,
    #[serde(flatten)]
    large_obj: LargeObjProtoConfig<Enc, Dec, IDs>,
    large_obj_msg_authn: MsgAuthN,
    #[serde(default)]
    hash: Hash,
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "dispatch-bus")]
#[serde(rename_all = "kebab-case")]
pub struct DispatchBusConfig<Channels, Epochs, Mode, Auth>
where
    Mode: Default,
    Epochs: Default {
    auth: Auth,
    #[serde(default)]
    #[serde(flatten)]
    dispatch: DispatchConfig<Epochs>,
    #[serde(flatten)]
    thread: DispatchThreadConfig<Channels, Mode>
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "static-parties")]
#[serde(rename_all = "kebab-case")]
pub struct StaticPartyConfig<PartyID, Epochs, Frags, Verify, Endpoint>
where
    Verify: Default,
    Epochs: Default,
    Frags: Default {
    party: PartyID,
    #[serde(flatten)]
    config: PartyConfig<ResolverConfig, Epochs, String, Verify, Endpoint>,
    #[serde(default)]
    frags: Frags
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(untagged)]
pub enum PartiesConfig<PartyID, Epochs, Frags, Verify, Endpoint>
where
    Verify: Default,
    Epochs: Default,
    Frags: Default {
    Static {
        #[serde(rename = "static")]
        stat: Vec<StaticPartyConfig<PartyID, Epochs, Frags, Verify, Endpoint>>
    }
}

impl<Channels, Epochs, Mode, Auth>
    DispatchBusConfig<Channels, Epochs, Mode, Auth>
where
    Mode: Default,
    Epochs: Default
{
    #[inline]
    pub fn create(
        auth: Auth,
        dispatch: DispatchConfig<Epochs>,
        thread: DispatchThreadConfig<Channels, Mode>
    ) -> DispatchBusConfig<Channels, Epochs, Mode, Auth> {
        DispatchBusConfig {
            dispatch: dispatch,
            thread: thread,
            auth: auth
        }
    }

    #[inline]
    pub fn dispatch(&self) -> &DispatchConfig<Epochs> {
        &self.dispatch
    }

    #[inline]
    pub fn thread(&self) -> &DispatchThreadConfig<Channels, Mode> {
        &self.thread
    }

    #[inline]
    pub fn auth(&self) -> &Auth {
        &self.auth
    }

    #[inline]
    pub fn take(
        self
    ) -> (
        Auth,
        DispatchConfig<Epochs>,
        DispatchThreadConfig<Channels, Mode>
    ) {
        (self.auth, self.dispatch, self.thread)
    }
}

impl<AuthN, Unix, UDP, Enc, Dec, Resolver, Epochs, MsgAuthN>
    UnicastDatagramBusConfig<AuthN, Unix, UDP, Enc, Dec,
                             Resolver, Epochs, MsgAuthN>
where
    Epochs: Default,
    Resolver: Default,
    Enc: Default,
    Dec: Default,
    Unix: Default,
    UDP: Default {
    #[inline]
    pub fn take(
        self
    ) -> CompoundFarSelectorPollThreadConfig<
        AuthN, Unix, UDP, Enc, Dec, PrivateDatagramModeConfig,
        Resolver, Epochs, String, MsgAuthN
    > {
        self.thread
    }
}

impl<Hash, AuthN, ProtoAuthN, Unix, UDP, Enc, Dec,
     IDs, Resolver, Epochs, MsgAuthN>
    UnicastLargeObjBusConfig<Hash, AuthN, ProtoAuthN, Unix, UDP,
                             Enc, Dec, IDs, Resolver, Epochs, MsgAuthN>
where
    Epochs: Default,
    Resolver: Default,
    Hash: Default,
    IDs: Default,
    Enc: Default,
    Dec: Default,
    Unix: Default,
    UDP: Default {
    #[inline]
    pub fn take(
        self
    ) -> (
        CompoundFarSelectorPollThreadConfig<
            AuthN, Unix, UDP, (), (), PrivateLargeObjModeConfig,
            Resolver, Epochs, String, ProtoAuthN
        >,
        LargeObjProtoConfig<Enc, Dec, IDs>,
        MsgAuthN,
        Hash
    ) {
        (self.thread, self.large_obj, self.large_obj_msg_authn, self.hash)
    }
}

impl<Party, AuthN, Unix, UDP, Enc, Dec, Resolver, Epochs, MsgAuthN>
    MulticastDatagramBusConfig<Party, AuthN, Unix, UDP, Enc, Dec,
                               Resolver, Epochs, MsgAuthN>
where
    Epochs: Default,
    Resolver: Default,
    Enc: Default,
    Dec: Default,
    Unix: Default,
    UDP: Default {
    #[inline]
    pub fn take(
        self
    ) -> (CompoundFarMulticastPollThreadConfig<
        AuthN,
        Unix,
        UDP,
        Enc,
        Dec,
        SharedDatagramModeConfig,
        Party,
        Resolver,
        Epochs,
        String,
        MsgAuthN
    >,
    Option<Party>) {
        (self.thread, self.self_party)
    }
}

impl<Party, Hash, AuthN, ProtoAuthN, Unix, UDP, Enc, Dec,
     IDs, Resolver, Epochs, MsgAuthN>
    MulticastLargeObjBusConfig<Party, Hash, AuthN, ProtoAuthN, Unix, UDP,
                               Enc, Dec, IDs, Resolver, Epochs, MsgAuthN>
where
    Epochs: Default,
    Resolver: Default,
    Hash: Default,
    IDs: Default,
    Enc: Default,
    Dec: Default,
    Unix: Default,
    UDP: Default {
    #[inline]
    pub fn take(
        self
    ) -> (
        CompoundFarMulticastPollThreadConfig<
            AuthN,
            Unix,
            UDP,
            (),
            (),
            SharedLargeObjModeConfig,
            Party,
            Resolver,
            Epochs,
            String,
            ProtoAuthN
        >,
        LargeObjProtoConfig<Enc, Dec, IDs>,
        MsgAuthN,
        Hash,
        Option<Party>
    ) {
        (self.thread, self.large_obj, self.large_obj_msg_authn,
         self.hash, self.self_party)
    }
}

impl<PartyID, Epochs, Frags, Verify, Endpoint>
    StaticPartyConfig<PartyID, Epochs, Frags, Verify, Endpoint>
where
    Verify: Default,
    Epochs: Default,
    Frags: Default
{
    #[inline]
    pub fn create(
        party: PartyID,
        frags: Frags,
        config: PartyConfig<ResolverConfig, Epochs, String, Verify, Endpoint>
    ) -> StaticPartyConfig<PartyID, Epochs, Frags, Verify, Endpoint> {
        StaticPartyConfig {
            party: party,
            frags: frags,
            config: config
        }
    }

    #[inline]
    pub fn party(&self) -> &PartyID {
        &self.party
    }

    #[inline]
    pub fn frags(&self) -> &Frags {
        &self.frags
    }

    #[inline]
    pub fn party_config(
        &self
    ) -> &PartyConfig<ResolverConfig, Epochs, String, Verify, Endpoint> {
        &self.config
    }

    #[inline]
    pub fn take(
        self
    ) -> (
        PartyID,
        Frags,
        PartyConfig<ResolverConfig, Epochs, String, Verify, Endpoint>
    ) {
        (self.party, self.frags, self.config)
    }
}
