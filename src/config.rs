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
use constellation_streams::config::PartyConfig;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "multicast")]
#[serde(rename_all = "kebab-case")]
pub struct MulticastConfig<PartyID, Channels, Epochs, Endpoint>
where
    Channels: Default,
    Epochs: Default {
    #[serde(flatten)]
    #[serde(default)]
    slots: BatchSlotsConfig,
    #[serde(flatten)]
    parties: PartiesConfig<PartyID, Channels, Epochs, Endpoint>
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "unicast")]
#[serde(rename_all = "kebab-case")]
pub struct UnicastConfig<Channels, Epochs, Endpoint>
where
    Channels: Default,
    Epochs: Default {
    #[serde(flatten)]
    party: PartyConfig<ResolverConfig, Channels, Epochs, String, Endpoint>
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

impl<Channels, Epochs, Endpoint> UnicastConfig<Channels, Epochs, Endpoint>
where
    Channels: Default,
    Epochs: Default
{
    #[inline]
    pub fn create(
        party: PartyConfig<ResolverConfig, Channels, Epochs, String, Endpoint>
    ) -> UnicastConfig<Channels, Epochs, Endpoint> {
        UnicastConfig { party: party }
    }

    #[inline]
    pub fn party(
        &self
    ) -> &PartyConfig<ResolverConfig, Channels, Epochs, String, Endpoint> {
        &self.party
    }

    #[inline]
    pub fn take(
        self
    ) -> PartyConfig<ResolverConfig, Channels, Epochs, String, Endpoint> {
        self.party
    }
}

impl<PartyID, Channels, Epochs, Endpoint>
    MulticastConfig<PartyID, Channels, Epochs, Endpoint>
where
    Channels: Default,
    Epochs: Default
{
    #[inline]
    pub fn create(
        slots: BatchSlotsConfig,
        parties: PartiesConfig<PartyID, Channels, Epochs, Endpoint>
    ) -> MulticastConfig<PartyID, Channels, Epochs, Endpoint> {
        MulticastConfig {
            slots: slots,
            parties: parties
        }
    }

    #[inline]
    pub fn parties(
        &self
    ) -> &PartiesConfig<PartyID, Channels, Epochs, Endpoint> {
        &self.parties
    }

    #[inline]
    pub fn take(
        self
    ) -> (
        BatchSlotsConfig,
        PartiesConfig<PartyID, Channels, Epochs, Endpoint>
    ) {
        (self.slots, self.parties)
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
