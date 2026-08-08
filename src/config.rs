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
use constellation_streams::config::DispatchConfig;
use constellation_streams::config::DispatchThreadConfig;
use constellation_streams::config::PartyConfig;
use constellation_streams::config::PollThreadConfig;
use constellation_streams::config::StreamMulticasterConfig;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "multicast-bus")]
#[serde(rename_all = "kebab-case")]
pub struct MulticastBusConfig<Channels, PartyID, Mode, Frags, Stream, AuthN>
where
    Mode: Default,
    Frags: Default {
    #[serde(flatten)]
    thread: PollThreadConfig<
        Channels,
        Mode,
        StreamMulticasterConfig<PartyID, Frags, Stream>,
        AuthN
    >
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "unicast-datagram-bus")]
#[serde(rename_all = "kebab-case")]
pub struct UnicastBusConfig<Channels, Epochs, Mode, AuthN, Endpoint>
where
    Mode: Default,
    Epochs: Default {
    #[serde(flatten)]
    thread: PollThreadConfig<
        Channels,
        Mode,
        PartyConfig<ResolverConfig, Epochs, String, Endpoint>,
        AuthN
    >
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

impl<Channels, Epochs, Mode, AuthN, Endpoint>
    UnicastBusConfig<Channels, Epochs, Mode, AuthN, Endpoint>
where
    Mode: Default,
    Epochs: Default {
    #[inline]
    pub fn create(
        thread: PollThreadConfig<
            Channels,
            Mode,
            PartyConfig<ResolverConfig, Epochs, String, Endpoint>,
            AuthN
        >
    ) -> UnicastBusConfig<Channels, Epochs, Mode, AuthN, Endpoint> {
        UnicastBusConfig {
            thread: thread
        }
    }

    #[inline]
    pub fn thread(
        &self
    ) -> &PollThreadConfig<
        Channels,
        Mode,
        PartyConfig<ResolverConfig, Epochs, String, Endpoint>,
        AuthN
    > {
        &self.thread
    }

    #[inline]
    pub fn take(
        self
    ) -> PollThreadConfig<
        Channels,
        Mode,
        PartyConfig<ResolverConfig, Epochs, String, Endpoint>,
        AuthN
    > {
        self.thread
    }
}

impl<Channels, PartyID, Mode, Frags, Stream, AuthN>
    MulticastBusConfig<Channels, PartyID, Mode, Frags, Stream, AuthN>
where
    Mode: Default,
    Frags: Default
{
    #[inline]
    pub fn create(
        thread: PollThreadConfig<
            Channels,
            Mode,
            StreamMulticasterConfig<PartyID, Frags, Stream>,
            AuthN
        >
    ) -> MulticastBusConfig<Channels, PartyID, Mode, Frags, Stream, AuthN> {
        MulticastBusConfig {
            thread: thread
        }
    }

    #[inline]
    pub fn thread(
        &self
    ) -> &PollThreadConfig<
        Channels,
        Mode,
        StreamMulticasterConfig<PartyID, Frags, Stream>,
        AuthN
    > {
        &self.thread
    }

    #[inline]
    pub fn take(
        self
    ) -> PollThreadConfig<
        Channels,
        Mode,
        StreamMulticasterConfig<PartyID, Frags, Stream>,
        AuthN
    > {
        self.thread
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
