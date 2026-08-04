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

use constellation_channels::config::ResolverConfig;
use constellation_common::retry::Retry;
use constellation_streams::config::BatchSlotsConfig;
use constellation_streams::config::DispatchConfig;
use constellation_streams::config::DispatchThreadConfig;
use constellation_streams::config::PartyConfig;
use constellation_streams::config::PollThreadConfig;
use constellation_streams::config::PrivateDatagramModeConfig;
use constellation_streams::config::PrivateLargeObjModeConfig;
use constellation_streams::config::SharedDatagramModeConfig;
use constellation_streams::config::SharedLargeObjModeConfig;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "multicast-datagram-bus")]
#[serde(rename_all = "kebab-case")]
pub struct MulticastDatagramBusConfig<Channels, PartyID, Epochs,
                                      AuthN, Endpoint>
where
    Epochs: Default {
    #[serde(flatten)]
    #[serde(default)]
    slots: BatchSlotsConfig,
    #[serde(flatten)]
    parties: PartiesConfig<PartyID, Epochs, (), Endpoint>,
    #[serde(flatten)]
    thread: PollThreadConfig<Channels, SharedDatagramModeConfig, AuthN>
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "multicast-large-obj-bus")]
#[serde(rename_all = "kebab-case")]
pub struct MulticastLargeObjBusConfig<PartyID, Epochs, Endpoint>
where
    Epochs: Default {
    #[serde(flatten)]
    #[serde(default)]
    slots: BatchSlotsConfig,
    #[serde(flatten)]
    parties: PartiesConfig<PartyID, Epochs, Retry, Endpoint>,
    #[serde(flatten)]
    #[serde(default)]
    mode: SharedLargeObjModeConfig
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "unicast-datagram-bus")]
#[serde(rename_all = "kebab-case")]
pub struct UnicastDatagramBusConfig<Channels, Epochs, AuthN, Endpoint>
where
    Epochs: Default {
    #[serde(flatten)]
    party: PartyConfig<ResolverConfig, Epochs, String, Endpoint>,
    #[serde(flatten)]
    thread: PollThreadConfig<Channels, PrivateDatagramModeConfig, AuthN>
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "unicast-large-obj-bus")]
#[serde(rename_all = "kebab-case")]
pub struct UnicastLargeObjBusConfig<Channels, Epochs, AuthN, Endpoint>
where
    Channels: Default,
    Epochs: Default {
    #[serde(flatten)]
    party: PartyConfig<ResolverConfig, Epochs, String, Endpoint>,
    #[serde(flatten)]
    thread: PollThreadConfig<Channels, PrivateLargeObjModeConfig, AuthN>
}

#[derive(
    Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "dispatch-datagram-bus")]
#[serde(rename_all = "kebab-case")]
pub struct DispatchDatagramBusConfig<Channels, Mode, Epochs, Auth>
where
    Mode: Default,
    Epochs: Default {
    auth: Auth,
    #[serde(default)]
    #[serde(flatten)]
    dispatch: DispatchConfig<Epochs>,
    #[serde(flatten)]
    thread: DispatchThreadConfig<Channels, Mode>,
}

#[derive(
    Clone, Debug, Default, Deserialize, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "dispatch-large-obj-bus")]
#[serde(rename_all = "kebab-case")]
pub struct DispatchLargeObjBusConfig<Epochs>
where
    Epochs: Default {
    #[serde(default)]
    sessions_hint: Option<usize>,
    #[serde(default)]
    #[serde(flatten)]
    dispatch: DispatchConfig<Epochs>,
    #[serde(flatten)]
    #[serde(default)]
    mode: PrivateLargeObjModeConfig
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "static-parties")]
#[serde(rename_all = "kebab-case")]
pub struct StaticPartyConfig<PartyID, Epochs, Frags, Endpoint>
where
    Epochs: Default,
    Frags: Default {
    party: PartyID,
    #[serde(flatten)]
    config: PartyConfig<ResolverConfig, Epochs, String, Endpoint>,
    #[serde(default)]
    frags: Frags
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(untagged)]
pub enum PartiesConfig<PartyID, Epochs, Frags, Endpoint>
where
    Epochs: Default,
    Frags: Default {
    Static {
        #[serde(rename = "static")]
        stat: Vec<StaticPartyConfig<PartyID, Epochs, Frags, Endpoint>>
    }
}

impl<Epochs> DispatchLargeObjBusConfig<Epochs>
where
    Epochs: Default
{
    #[inline]
    pub fn create(
        sessions_hint: Option<usize>,
        dispatch: DispatchConfig<Epochs>,
        mode: PrivateLargeObjModeConfig
    ) -> DispatchLargeObjBusConfig<Epochs> {
        DispatchLargeObjBusConfig {
            sessions_hint: sessions_hint,
            dispatch: dispatch,
            mode: mode
        }
    }

    #[inline]
    pub fn dispatch(&self) -> &DispatchConfig<Epochs> {
        &self.dispatch
    }

    #[inline]
    pub fn sessions_hint(&self) -> Option<usize> {
        self.sessions_hint
    }

    #[inline]
    pub fn mode(&self) -> &PrivateLargeObjModeConfig {
        &self.mode
    }

    #[inline]
    pub fn take(
        self
    ) -> (
        Option<usize>,
        DispatchConfig<Epochs>,
        PrivateLargeObjModeConfig
    ) {
        (self.sessions_hint, self.dispatch, self.mode)
    }
}

impl<Channels, Mode, Epochs, Auth>
    DispatchDatagramBusConfig<Channels, Mode, Epochs, Auth>
where
    Mode: Default,
    Epochs: Default,
{
    #[inline]
    pub fn create(
        auth: Auth,
        dispatch: DispatchConfig<Epochs>,
        thread: DispatchThreadConfig<Channels, Mode>
    ) -> DispatchDatagramBusConfig<Channels, Mode, Epochs, Auth> {
        DispatchDatagramBusConfig {
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
    ) -> (Auth, DispatchConfig<Epochs>, DispatchThreadConfig<Channels, Mode>) {
        (self.auth, self.dispatch, self.thread)
    }
}

impl<Channels, Epochs, AuthN, Endpoint>
    UnicastDatagramBusConfig<Channels, Epochs, AuthN, Endpoint>
where Epochs: Default {
    #[inline]
    pub fn create(
        party: PartyConfig<ResolverConfig, Epochs, String, Endpoint>,
        thread: PollThreadConfig<Channels, PrivateDatagramModeConfig, AuthN>
    ) -> UnicastDatagramBusConfig<Channels, Epochs, AuthN, Endpoint> {
        UnicastDatagramBusConfig {
            party: party,
            thread: thread
        }
    }

    #[inline]
    pub fn party(
        &self
    ) -> &PartyConfig<ResolverConfig, Epochs, String, Endpoint> {
        &self.party
    }

    #[inline]
    pub fn thread(
        &self
    ) -> &PollThreadConfig<Channels, PrivateDatagramModeConfig, AuthN> {
        &self.thread
    }

    #[inline]
    pub fn take(
        self
    ) -> (
        PartyConfig<ResolverConfig, Epochs, String, Endpoint>,
        PollThreadConfig<Channels, PrivateDatagramModeConfig, AuthN>
    ) {
        (self.party, self.thread)
    }
}

impl<Channels, Epochs, AuthN, Endpoint>
    UnicastLargeObjBusConfig<Channels, Epochs, AuthN, Endpoint>
where
    Channels: Default,
    Epochs: Default
{
    #[inline]
    pub fn create(
        party: PartyConfig<ResolverConfig, Epochs, String, Endpoint>,
        thread: PollThreadConfig<Channels, PrivateLargeObjModeConfig, AuthN>
    ) -> UnicastLargeObjBusConfig<Channels, Epochs, AuthN, Endpoint> {
        UnicastLargeObjBusConfig {
            party: party,
            thread: thread
        }
    }

    #[inline]
    pub fn party(
        &self
    ) -> &PartyConfig<ResolverConfig, Epochs, String, Endpoint> {
        &self.party
    }

    #[inline]
    pub fn thread(
        &self
    ) -> &PollThreadConfig<Channels, PrivateLargeObjModeConfig, AuthN> {
        &self.thread
    }

    #[inline]
    pub fn take(
        self
    ) -> (
        PartyConfig<ResolverConfig, Epochs, String, Endpoint>,
        PollThreadConfig<Channels, PrivateLargeObjModeConfig, AuthN>
    ) {
        (self.party, self.thread)
    }
}

impl<Channels, PartyID, Epochs, AuthN, Endpoint>
    MulticastDatagramBusConfig<Channels, PartyID, Epochs, AuthN, Endpoint>
where
    Epochs: Default
{
    #[inline]
    pub fn create(
        slots: BatchSlotsConfig,
        parties: PartiesConfig<PartyID, Epochs, (), Endpoint>,
        thread: PollThreadConfig<Channels, SharedDatagramModeConfig, AuthN>
    ) -> MulticastDatagramBusConfig<Channels, PartyID, Epochs,
                                    AuthN, Endpoint> {
        MulticastDatagramBusConfig {
            slots: slots,
            parties: parties,
            thread: thread
        }
    }

    #[inline]
    pub fn parties(
        &self
    ) -> &PartiesConfig<PartyID, Epochs, (), Endpoint> {
        &self.parties
    }

    #[inline]
    pub fn thread(
        &self
    ) -> &PollThreadConfig<Channels, SharedDatagramModeConfig, AuthN> {
        &self.thread
    }

    #[inline]
    pub fn take(
        self
    ) -> (
        BatchSlotsConfig,
        PartiesConfig<PartyID, Epochs, (), Endpoint>,
        PollThreadConfig<Channels, SharedDatagramModeConfig, AuthN>
    ) {
        (self.slots, self.parties, self.thread)
    }
}

impl<PartyID, Epochs, Endpoint>
    MulticastLargeObjBusConfig<PartyID, Epochs, Endpoint>
where
    Epochs: Default
{
    #[inline]
    pub fn create(
        slots: BatchSlotsConfig,
        parties: PartiesConfig<PartyID, Epochs, Retry, Endpoint>,
        mode: SharedLargeObjModeConfig
    ) -> MulticastLargeObjBusConfig<PartyID, Epochs, Endpoint> {
        MulticastLargeObjBusConfig {
            slots: slots,
            parties: parties,
            mode: mode
        }
    }

    #[inline]
    pub fn parties(
        &self
    ) -> &PartiesConfig<PartyID, Epochs, Retry, Endpoint> {
        &self.parties
    }

    #[inline]
    pub fn mode(&self) -> &SharedLargeObjModeConfig {
        &self.mode
    }

    #[inline]
    pub fn take(
        self
    ) -> (
        BatchSlotsConfig,
        PartiesConfig<PartyID, Epochs, Retry, Endpoint>,
        SharedLargeObjModeConfig
    ) {
        (self.slots, self.parties, self.mode)
    }
}

impl<PartyID, Epochs, Frags, Endpoint>
    StaticPartyConfig<PartyID, Epochs, Frags, Endpoint>
where
    Epochs: Default,
    Frags: Default
{
    #[inline]
    pub fn create(
        party: PartyID,
        frags: Frags,
        config: PartyConfig<ResolverConfig, Epochs, String, Endpoint>
    ) -> StaticPartyConfig<PartyID, Epochs, Frags, Endpoint> {
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
    ) -> &PartyConfig<ResolverConfig, Epochs, String, Endpoint> {
        &self.config
    }

    #[inline]
    pub fn take(
        self
    ) -> (
        PartyID,
        Frags,
        PartyConfig<ResolverConfig, Epochs, String, Endpoint>
    ) {
        (self.party, self.frags, self.config)
    }
}
