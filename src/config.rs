// Copyright © 2024-25 The Johns Hopkins Applied Physics Laboratory LLC.
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
use constellation_streams::config::BatchSlotsConfig;
use constellation_streams::config::DispatchConfig;
use constellation_streams::config::PartyConfig;
use constellation_streams::config::PrivateLargeObjModeConfig;
use constellation_streams::config::PrivateSmallObjModeConfig;
use constellation_streams::config::SharedSmallObjModeConfig;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "multicast-comm")]
#[serde(rename_all = "kebab-case")]
pub struct MulticastBusConfig<PartyID, Channels, Epochs, Endpoint>
where
    Channels: Default,
    Epochs: Default {
    #[serde(flatten)]
    #[serde(default)]
    slots: BatchSlotsConfig,
    #[serde(flatten)]
    parties: PartiesConfig<PartyID, Channels, Epochs, Endpoint>,
    #[serde(flatten)]
    #[serde(default)]
    mode: SharedSmallObjModeConfig
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "unicast-small-obj-bus")]
#[serde(rename_all = "kebab-case")]
pub struct UnicastSmallObjBusConfig<Channels, Epochs, Endpoint>
where
    Channels: Default,
    Epochs: Default {
    #[serde(flatten)]
    party: PartyConfig<ResolverConfig, Channels, Epochs, String, Endpoint>,
    #[serde(flatten)]
    #[serde(default)]
    mode: PrivateSmallObjModeConfig
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
    mode: PrivateLargeObjModeConfig,
}

#[derive(
    Clone, Debug, Default, Deserialize, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "dispatch-comm")]
#[serde(rename_all = "kebab-case")]
pub struct DispatchBusConfig<Epochs>
where
    Epochs: Default {
    #[serde(default)]
    sessions_hint: Option<usize>,
    #[serde(default)]
    #[serde(flatten)]
    dispatch: DispatchConfig<Epochs>,
    #[serde(flatten)]
    #[serde(default)]
    mode: PrivateSmallObjModeConfig
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "static-parties")]
#[serde(rename_all = "kebab-case")]
pub struct StaticPartyConfig<PartyID, Channels, Epochs, Endpoint>
where
    Channels: Default,
    Epochs: Default {
    party: PartyID,
    #[serde(flatten)]
    config: PartyConfig<ResolverConfig, Channels, Epochs, String, Endpoint>
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(untagged)]
pub enum PartiesConfig<PartyID, Channels, Epochs, Endpoint>
where
    Channels: Default,
    Epochs: Default {
    Static {
        #[serde(rename = "static")]
        stat: Vec<StaticPartyConfig<PartyID, Channels, Epochs, Endpoint>>
    }
}

impl<Epochs> DispatchBusConfig<Epochs>
where
    Epochs: Default
{
    #[inline]
    pub fn create(
        sessions_hint: Option<usize>,
        dispatch: DispatchConfig<Epochs>,
        mode: PrivateSmallObjModeConfig
    ) -> DispatchBusConfig<Epochs> {
        DispatchBusConfig {
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
    pub fn mode(&self) -> &PrivateSmallObjModeConfig {
        &self.mode
    }

    #[inline]
    pub fn take(
        self
    ) -> (
        Option<usize>,
        DispatchConfig<Epochs>,
        PrivateSmallObjModeConfig
    ) {
        (self.sessions_hint, self.dispatch, self.mode)
    }
}

impl<Channels, Epochs, Endpoint>
    UnicastSmallObjBusConfig<Channels, Epochs, Endpoint>
where
    Channels: Default,
    Epochs: Default
{
    #[inline]
    pub fn create(
        party: PartyConfig<ResolverConfig, Channels, Epochs, String, Endpoint>,
        mode: PrivateSmallObjModeConfig
    ) -> UnicastSmallObjBusConfig<Channels, Epochs, Endpoint> {
        UnicastSmallObjBusConfig {
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
    pub fn mode(&self) -> &PrivateSmallObjModeConfig {
        &self.mode
    }

    #[inline]
    pub fn take(
        self
    ) -> (
        PartyConfig<ResolverConfig, Channels, Epochs, String, Endpoint>,
        PrivateSmallObjModeConfig
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
        PrivateLargeObjModeConfig,
    ) {
        (self.party, self.mode)
    }
}

impl<PartyID, Channels, Epochs, Endpoint>
    MulticastBusConfig<PartyID, Channels, Epochs, Endpoint>
where
    Channels: Default,
    Epochs: Default
{
    #[inline]
    pub fn create(
        slots: BatchSlotsConfig,
        parties: PartiesConfig<PartyID, Channels, Epochs, Endpoint>,
        mode: SharedSmallObjModeConfig
    ) -> MulticastBusConfig<PartyID, Channels, Epochs, Endpoint> {
        MulticastBusConfig {
            slots: slots,
            parties: parties,
            mode: mode
        }
    }

    #[inline]
    pub fn parties(
        &self
    ) -> &PartiesConfig<PartyID, Channels, Epochs, Endpoint> {
        &self.parties
    }

    #[inline]
    pub fn mode(&self) -> &SharedSmallObjModeConfig {
        &self.mode
    }

    #[inline]
    pub fn take(
        self
    ) -> (
        BatchSlotsConfig,
        PartiesConfig<PartyID, Channels, Epochs, Endpoint>,
        SharedSmallObjModeConfig
    ) {
        (self.slots, self.parties, self.mode)
    }
}

impl<PartyID, Channels, Epochs, Endpoint>
    StaticPartyConfig<PartyID, Channels, Epochs, Endpoint>
where
    Channels: Default,
    Epochs: Default
{
    #[inline]
    pub fn create(
        party: PartyID,
        config: PartyConfig<ResolverConfig, Channels, Epochs, String, Endpoint>
    ) -> StaticPartyConfig<PartyID, Channels, Epochs, Endpoint> {
        StaticPartyConfig {
            party: party,
            config: config
        }
    }

    #[inline]
    pub fn party(&self) -> &PartyID {
        &self.party
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
        PartyConfig<ResolverConfig, Channels, Epochs, String, Endpoint>
    ) {
        (self.party, self.config)
    }
}
