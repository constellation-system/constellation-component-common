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
use constellation_streams::config::PartyConfig;
use constellation_streams::config::PrivateDatagramModeConfig;
use constellation_streams::config::PrivateLargeObjModeConfig;
use constellation_streams::config::SharedDatagramModeConfig;
use constellation_streams::config::SharedLargeObjModeConfig;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "multicast-datagram-bus")]
#[serde(rename_all = "kebab-case")]
pub struct MulticastDatagramBusConfig<PartyID, Channels, Epochs, Endpoint>
where
    Channels: Default,
    Epochs: Default {
    #[serde(flatten)]
    #[serde(default)]
    slots: BatchSlotsConfig,
    #[serde(flatten)]
    parties: PartiesConfig<PartyID, Channels, Epochs, (), Endpoint>,
    #[serde(flatten)]
    #[serde(default)]
    mode: SharedDatagramModeConfig
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "multicast-large-obj-bus")]
#[serde(rename_all = "kebab-case")]
pub struct MulticastLargeObjBusConfig<PartyID, Channels, Epochs, Endpoint>
where
    Channels: Default,
    Epochs: Default {
    #[serde(flatten)]
    #[serde(default)]
    slots: BatchSlotsConfig,
    #[serde(flatten)]
    parties: PartiesConfig<PartyID, Channels, Epochs, Retry, Endpoint>,
    #[serde(flatten)]
    #[serde(default)]
    mode: SharedLargeObjModeConfig
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "unicast-datagram-bus")]
#[serde(rename_all = "kebab-case")]
pub struct UnicastDatagramBusConfig<Channels, Epochs, Endpoint>
where
    Channels: Default,
    Epochs: Default {
    #[serde(flatten)]
    party: PartyConfig<ResolverConfig, Channels, Epochs, String, Endpoint>,
    #[serde(flatten)]
    #[serde(default)]
    mode: PrivateDatagramModeConfig
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "unicast-large-obj-bus")]
#[serde(rename_all = "kebab-case")]
pub struct UnicastLargeObjBusConfig<Channels, Epochs, Endpoint>
where
    Channels: Default,
    Epochs: Default {
    #[serde(flatten)]
    party: PartyConfig<ResolverConfig, Channels, Epochs, String, Endpoint>,
    #[serde(flatten)]
    #[serde(default)]
    mode: PrivateLargeObjModeConfig
}

#[derive(
    Clone, Debug, Default, Deserialize, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "dispatch-datagram-bus")]
#[serde(rename_all = "kebab-case")]
pub struct DispatchDatagramBusConfig<Epochs>
where
    Epochs: Default {
    #[serde(default)]
    sessions_hint: Option<usize>,
    #[serde(default)]
    #[serde(flatten)]
    dispatch: DispatchConfig<Epochs>,
    #[serde(flatten)]
    #[serde(default)]
    mode: PrivateDatagramModeConfig
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
pub struct StaticPartyConfig<PartyID, Channels, Epochs, Frags, Endpoint>
where
    Channels: Default,
    Epochs: Default,
    Frags: Default {
    party: PartyID,
    #[serde(flatten)]
    config: PartyConfig<ResolverConfig, Channels, Epochs, String, Endpoint>,
    #[serde(default)]
    frags: Frags
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(untagged)]
pub enum PartiesConfig<PartyID, Channels, Epochs, Frags, Endpoint>
where
    Channels: Default,
    Epochs: Default,
    Frags: Default {
    Static {
        #[serde(rename = "static")]
        stat:
            Vec<StaticPartyConfig<PartyID, Channels, Epochs, Frags, Endpoint>>
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

impl<Epochs> DispatchDatagramBusConfig<Epochs>
where
    Epochs: Default
{
    #[inline]
    pub fn create(
        sessions_hint: Option<usize>,
        dispatch: DispatchConfig<Epochs>,
        mode: PrivateDatagramModeConfig
    ) -> DispatchDatagramBusConfig<Epochs> {
        DispatchDatagramBusConfig {
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
    pub fn mode(&self) -> &PrivateDatagramModeConfig {
        &self.mode
    }

    #[inline]
    pub fn take(
        self
    ) -> (
        Option<usize>,
        DispatchConfig<Epochs>,
        PrivateDatagramModeConfig
    ) {
        (self.sessions_hint, self.dispatch, self.mode)
    }
}

impl<Channels, Epochs, Endpoint>
    UnicastDatagramBusConfig<Channels, Epochs, Endpoint>
where
    Channels: Default,
    Epochs: Default
{
    #[inline]
    pub fn create(
        party: PartyConfig<ResolverConfig, Channels, Epochs, String, Endpoint>,
        mode: PrivateDatagramModeConfig
    ) -> UnicastDatagramBusConfig<Channels, Epochs, Endpoint> {
        UnicastDatagramBusConfig {
            party: party,
            mode: mode
        }
    }

    #[inline]
    pub fn party(
        &self
    ) -> &PartyConfig<ResolverConfig, Channels, Epochs, String, Endpoint> {
        &self.party
    }

    #[inline]
    pub fn mode(&self) -> &PrivateDatagramModeConfig {
        &self.mode
    }

    #[inline]
    pub fn take(
        self
    ) -> (
        PartyConfig<ResolverConfig, Channels, Epochs, String, Endpoint>,
        PrivateDatagramModeConfig
    ) {
        (self.party, self.mode)
    }
}

impl<Channels, Epochs, Endpoint>
    UnicastLargeObjBusConfig<Channels, Epochs, Endpoint>
where
    Channels: Default,
    Epochs: Default
{
    #[inline]
    pub fn create(
        party: PartyConfig<ResolverConfig, Channels, Epochs, String, Endpoint>,
        mode: PrivateLargeObjModeConfig
    ) -> UnicastLargeObjBusConfig<Channels, Epochs, Endpoint> {
        UnicastLargeObjBusConfig {
            party: party,
            mode: mode
        }
    }

    #[inline]
    pub fn party(
        &self
    ) -> &PartyConfig<ResolverConfig, Channels, Epochs, String, Endpoint> {
        &self.party
    }

    #[inline]
    pub fn mode(&self) -> &PrivateLargeObjModeConfig {
        &self.mode
    }

    #[inline]
    pub fn take(
        self
    ) -> (
        PartyConfig<ResolverConfig, Channels, Epochs, String, Endpoint>,
        PrivateLargeObjModeConfig
    ) {
        (self.party, self.mode)
    }
}

impl<PartyID, Channels, Epochs, Endpoint>
    MulticastDatagramBusConfig<PartyID, Channels, Epochs, Endpoint>
where
    Channels: Default,
    Epochs: Default
{
    #[inline]
    pub fn create(
        slots: BatchSlotsConfig,
        parties: PartiesConfig<PartyID, Channels, Epochs, (), Endpoint>,
        mode: SharedDatagramModeConfig
    ) -> MulticastDatagramBusConfig<PartyID, Channels, Epochs, Endpoint> {
        MulticastDatagramBusConfig {
            slots: slots,
            parties: parties,
            mode: mode
        }
    }

    #[inline]
    pub fn parties(
        &self
    ) -> &PartiesConfig<PartyID, Channels, Epochs, (), Endpoint> {
        &self.parties
    }

    #[inline]
    pub fn mode(&self) -> &SharedDatagramModeConfig {
        &self.mode
    }

    #[inline]
    pub fn take(
        self
    ) -> (
        BatchSlotsConfig,
        PartiesConfig<PartyID, Channels, Epochs, (), Endpoint>,
        SharedDatagramModeConfig
    ) {
        (self.slots, self.parties, self.mode)
    }
}

impl<PartyID, Channels, Epochs, Endpoint>
    MulticastLargeObjBusConfig<PartyID, Channels, Epochs, Endpoint>
where
    Channels: Default,
    Epochs: Default
{
    #[inline]
    pub fn create(
        slots: BatchSlotsConfig,
        parties: PartiesConfig<PartyID, Channels, Epochs, Retry, Endpoint>,
        mode: SharedLargeObjModeConfig
    ) -> MulticastLargeObjBusConfig<PartyID, Channels, Epochs, Endpoint> {
        MulticastLargeObjBusConfig {
            slots: slots,
            parties: parties,
            mode: mode
        }
    }

    #[inline]
    pub fn parties(
        &self
    ) -> &PartiesConfig<PartyID, Channels, Epochs, Retry, Endpoint> {
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
        PartiesConfig<PartyID, Channels, Epochs, Retry, Endpoint>,
        SharedLargeObjModeConfig
    ) {
        (self.slots, self.parties, self.mode)
    }
}

impl<PartyID, Channels, Epochs, Frags, Endpoint>
    StaticPartyConfig<PartyID, Channels, Epochs, Frags, Endpoint>
where
    Channels: Default,
    Epochs: Default,
    Frags: Default
{
    #[inline]
    pub fn create(
        party: PartyID,
        frags: Frags,
        config: PartyConfig<ResolverConfig, Channels, Epochs, String, Endpoint>
    ) -> StaticPartyConfig<PartyID, Channels, Epochs, Frags, Endpoint> {
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
    ) -> &PartyConfig<ResolverConfig, Channels, Epochs, String, Endpoint> {
        &self.config
    }

    #[inline]
    pub fn take(
        self
    ) -> (
        PartyID,
        Frags,
        PartyConfig<ResolverConfig, Channels, Epochs, String, Endpoint>
    ) {
        (self.party, self.frags, self.config)
    }
}
