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

use std::convert::Infallible;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Instant;

use constellation_auth::authn::AuthNMsgRecv;
use constellation_auth::authn::AuthNTypes;
use constellation_auth::authn::AuthNedDestruct;
use constellation_auth::authn::BasicAuthNed;
use constellation_auth::authn::MsgAuthNTypes;
use constellation_auth::authn::PassthruMsgAuthN;
use constellation_auth::authn::basic::BasicAuthN;
use constellation_auth::config::BasicAuthNConfig;
use constellation_channels::config::CompoundFarChannelXfrmPeerAddr;
use constellation_channels::config::CompoundFarEndpoint;
use constellation_channels::config::ResolverConfig;
use constellation_channels::far::compound::CompoundFlow;
use constellation_channels::far::types::CompoundFarChannelsBasicAuthNedLargeObjChan;
use constellation_channels::resolve::MixedResolver;
use constellation_channels::resolve::cache::NSNameCachesCtx;
use constellation_channels::resolve::cache::SharedNSNameCaches;
use constellation_common::codec::Encoder;
use constellation_common::codec::test::TestBytesCodec;
use constellation_common::codec::test::TestDecodeError;
use constellation_common::codec::test::TooShort;
use constellation_common::config::Create;
use constellation_common::error::ErrorScope;
use constellation_common::error::MutexPoison;
use constellation_common::error::ScopedError;
use constellation_common::hashid::SHA3Algo;
use constellation_common::hashid::SHA3ID;
use constellation_common::ids::AscendingCount;
use constellation_common::net::PassthruDatagramXfrm;
use constellation_common::net::PassthruDatagramXfrmParam;
use constellation_common::retry::Retry;
use constellation_common::unix::UnixSocketPath;
use constellation_component_common::bus::multicast::MulticastLargeObjBus;
use constellation_component_common::bus::types::MulticastLargeObjBusTypes;
use constellation_component_common::config::MulticastLargeObjBusConfig;
use constellation_streams::frags::Frags;
use constellation_streams::large_obj::LargeObjID;
use constellation_streams::large_obj::LargeObjMsg;
use constellation_streams::large_obj::LargeObjMsgs;
use constellation_streams::large_obj::LargeObjProtoAddOutboundError;
use constellation_streams::large_obj::LargeObjProtoTypes;
use constellation_streams::large_obj::LargeObjSender;
use constellation_streams::threads::Tokens;
use constellation_streams::threads::TokensCtx;
use constellation_streams::threads::poll::MsgsWaker;
use log::LevelFilter;
use log::debug;
use log::info;
use mio::Token;
use mio::Waker;

const FIRST_BYTES: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
const SECOND_BYTES: [u8; 8] = [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];

struct ExampleCtx {
    inner: SharedNSNameCaches,
    tokens: Tokens
}

struct ExampleClientMsgs {
    waker: Arc<Mutex<Option<Arc<Waker>>>>,
    live: Arc<AtomicBool>,
    nretries: usize,
    retry: Retry
}

struct ExampleServerMsgs {
    waker: Arc<Mutex<Option<Arc<Waker>>>>,
    live: Arc<AtomicBool>,
    sent: bool
}

#[derive(Clone)]
struct ExampleClientRecv {
    waker: Arc<Mutex<Option<Arc<Waker>>>>,
    live: Arc<AtomicBool>
}

#[derive(Clone)]
struct ExampleServerRecv {
    waker: Arc<Mutex<Option<Arc<Waker>>>>,
    live: Arc<AtomicBool>
}

#[derive(Debug)]
enum LargeObjMsgsErr<Encode> {
    Add {
        err: LargeObjProtoAddOutboundError<Encode>
    },
    Finished
}

struct LargeObjServer;

struct LargeObjClient;

struct ExampleAuthN;
struct ExampleServerBusTypes;
struct ExampleClientBusTypes;

impl MsgsWaker for ExampleServerMsgs {
    type Error = MutexPoison;

    fn set_waker(
        &mut self,
        waker: Arc<Waker>
    ) -> Result<(), Self::Error> {
        let mut guard = self.waker.lock().map_err(|_| MutexPoison)?;

        *guard = Some(waker);

        Ok(())
    }
}

impl MsgsWaker for ExampleClientMsgs {
    type Error = MutexPoison;

    fn set_waker(
        &mut self,
        waker: Arc<Waker>
    ) -> Result<(), Self::Error> {
        let mut guard = self.waker.lock().map_err(|_| MutexPoison)?;

        *guard = Some(waker);

        Ok(())
    }
}

impl LargeObjMsgs<SHA3Algo, Vec<u8>> for ExampleClientMsgs {
    type AddMsgsError<Encode>
        = LargeObjMsgsErr<Encode>
    where
        Encode: Debug + Display + ScopedError;

    fn add_msgs<Enc, F>(
        &mut self,
        sender: &mut LargeObjSender<SHA3Algo, Vec<u8>, Enc, F>
    ) -> Result<Option<Instant>, Self::AddMsgsError<Enc::EncodeError>>
    where
        Enc: Clone + Create + Encoder<Vec<u8>>,
        Enc::Config: Default,
        F: Frags {
        if self.live.load(Ordering::Acquire) {
            let next = self.retry.retry_delay(self.nretries);
            let msg = FIRST_BYTES.to_vec();

            self.nretries += 1;

            info!(target: "client-msgs",
                  "sending {:?}", msg);

            sender
                .add_outbound(&msg)
                .map_err(|err| LargeObjMsgsErr::Add { err: err })?;

            Ok(Some(Instant::now() + next))
        } else {
            debug!(target: "client-msgs",
                  "msgs are finished");

            Err(LargeObjMsgsErr::Finished)
        }
    }
}

impl LargeObjMsgs<SHA3Algo, Vec<u8>> for ExampleServerMsgs {
    type AddMsgsError<Encode>
        = LargeObjMsgsErr<Encode>
    where
        Encode: Debug + Display + ScopedError;

    fn add_msgs<Enc, F>(
        &mut self,
        sender: &mut LargeObjSender<SHA3Algo, Vec<u8>, Enc, F>
    ) -> Result<Option<Instant>, Self::AddMsgsError<Enc::EncodeError>>
    where
        Enc: Clone + Create + Encoder<Vec<u8>>,
        Enc::Config: Default,
        F: Frags {
        if self.live.load(Ordering::Acquire) {
            if !self.sent {
                let msg = SECOND_BYTES.to_vec();

                self.sent = true;

                info!(target: "server-msgs",
                      "sending {:?}", msg);

                sender
                    .add_outbound(&msg)
                    .map_err(|err| LargeObjMsgsErr::Add { err: err })?;

                Ok(Some(Instant::now()))
            } else {
                debug!(target: "server-msgs",
                      "msgs are finished");

                Err(LargeObjMsgsErr::Finished)
            }
        } else {
            debug!(target: "server-msgs",
                   "msgs are not started");

            Ok(None)
        }
    }
}

impl<AuthMsg> AuthNMsgRecv<String, AuthMsg> for ExampleClientRecv
where
    AuthMsg: AuthNedDestruct<String, Vec<u8>>
{
    type RecvError = Infallible;

    fn recv_auth_msg(
        &mut self,
        msg: AuthMsg
    ) -> Result<(), Self::RecvError> {
        let (prin, msg) = msg.take();

        info!(target: "client-recv",
              "received {:?} from {}", msg, prin);

        self.live.store(false, Ordering::Release);

        if let Ok(mut guard) = self.waker.lock() {
            if let Some(waker) = &mut *guard {
                if let Err(err) = waker.wake() {
                    panic!("error waking: {}", err)
                }
            } else {
                panic!("waker should not be None")
            }
        } else {
            panic!("lock failed")
        }

        assert_eq!(msg, &SECOND_BYTES[..]);

        Ok(())
    }
}

impl<AuthMsg> AuthNMsgRecv<String, AuthMsg> for ExampleServerRecv
where
    AuthMsg: AuthNedDestruct<String, Vec<u8>>
{
    type RecvError = Infallible;

    fn recv_auth_msg(
        &mut self,
        msg: AuthMsg
    ) -> Result<(), Self::RecvError> {
        let (prin, msg) = msg.take();

        info!(target: "server-recv",
              "received {:?} from {}", msg, prin);

        self.live.store(true, Ordering::Release);

        if let Ok(mut guard) = self.waker.lock() {
            if let Some(waker) = &mut *guard {
                if let Err(err) = waker.wake() {
                    panic!("error waking: {}", err)
                }
            } else {
                panic!("waker should not be None")
            }
        } else {
            panic!("lock failed")
        }

        assert_eq!(msg, &FIRST_BYTES[..]);

        Ok(())
    }
}

impl<Encode> ScopedError for LargeObjMsgsErr<Encode>
where
    Encode: ScopedError
{
    #[inline]
    fn scope(&self) -> ErrorScope {
        match self {
            LargeObjMsgsErr::Add { err } => err.scope(),
            LargeObjMsgsErr::Finished => ErrorScope::Unrecoverable
        }
    }
}

impl<Encode> Display for LargeObjMsgsErr<Encode>
where
    Encode: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            LargeObjMsgsErr::Add { err } => err.fmt(f),
            LargeObjMsgsErr::Finished => write!(f, "finished")
        }
    }
}

impl NSNameCachesCtx for ExampleCtx {
    type NameCaches = SharedNSNameCaches;

    #[inline]
    fn name_caches(&mut self) -> &mut Self::NameCaches {
        self.inner.name_caches()
    }
}

impl TokensCtx for ExampleCtx {
    #[inline]
    fn token(&mut self) -> Token {
        self.tokens.token()
    }

    #[inline]
    fn free_token(
        &mut self,
        token: Token
    ) {
        self.tokens.free_token(token)
    }
}

impl MsgAuthNTypes<Vec<u8>> for ExampleAuthN {
    type AuthNError = Infallible;
    type DecodeError = TestDecodeError;
    type Decoder = TestBytesCodec;
    type DecoderConfig = ();
    type MsgAuthN = PassthruMsgAuthN<Vec<u8>, String>;
    type Prin = String;
    type SessionPrin = String;
    type Wrapper = Vec<u8>;
}

impl
    AuthNTypes<
        CompoundFlow<
            PassthruDatagramXfrm<UnixSocketPath>,
            PassthruDatagramXfrm<SocketAddr>
        >,
        Vec<u8>
    > for ExampleAuthN
{
    type MsgAuthNTypes = ExampleAuthN;
    type SessionAuthN = BasicAuthN<String>;
}

impl LargeObjProtoTypes<Vec<u8>, Vec<u8>> for LargeObjServer {
    type AuthNError = Infallible;
    type AuthNMsg = BasicAuthNed<String, Vec<u8>>;
    type AuthNTypes = ExampleAuthN;
    type DecodeError = TestDecodeError;
    type Decoder = TestBytesCodec;
    type DecoderConfig = ();
    type EncodeError = TooShort;
    type Encoder = TestBytesCodec;
    type EncoderConfig = ();
    type Hash = SHA3Algo;
    type HashID = SHA3ID;
    type IDs = AscendingCount<LargeObjID>;
    type IDsConfig = ();
    type MsgAuthN = PassthruMsgAuthN<Vec<u8>, String>;
    type Msgs = ExampleServerMsgs;
    type Prin = String;
    type Recv = ExampleServerRecv;
    type SessionPrin = String;
    type Wrapper = Vec<u8>;
}

impl LargeObjProtoTypes<Vec<u8>, Vec<u8>> for LargeObjClient {
    type AuthNError = Infallible;
    type AuthNMsg = BasicAuthNed<String, Vec<u8>>;
    type AuthNTypes = ExampleAuthN;
    type DecodeError = TestDecodeError;
    type Decoder = TestBytesCodec;
    type DecoderConfig = ();
    type EncodeError = TooShort;
    type Encoder = TestBytesCodec;
    type EncoderConfig = ();
    type Hash = SHA3Algo;
    type HashID = SHA3ID;
    type IDs = AscendingCount<LargeObjID>;
    type IDsConfig = ();
    type MsgAuthN = PassthruMsgAuthN<Vec<u8>, String>;
    type Msgs = ExampleClientMsgs;
    type Prin = String;
    type Recv = ExampleClientRecv;
    type SessionPrin = String;
    type Wrapper = Vec<u8>;
}

impl MulticastLargeObjBusTypes<ExampleCtx> for ExampleServerBusTypes {
    type AuthNChan = CompoundFarChannelsBasicAuthNedLargeObjChan<
        String,
        SHA3Algo,
        PassthruDatagramXfrm<UnixSocketPath>,
        PassthruDatagramXfrm<SocketAddr>
    >;
    type AuthNMsg = BasicAuthNed<String, Vec<u8>>;
    type AuthNSession = BasicAuthNed<
        String,
        CompoundFlow<
            PassthruDatagramXfrm<UnixSocketPath>,
            PassthruDatagramXfrm<SocketAddr>
        >
    >;
    type Decoder = TestBytesCodec;
    type DecoderConfig = ();
    type DecoderCreateError = Infallible;
    type EncodeError = TooShort;
    type Encoder = TestBytesCodec;
    type EncoderConfig = ();
    type EncoderCreateError = Infallible;
    type Epoch = u128;
    type Epochs = AscendingCount<u128>;
    type EpochsConfig = ();
    type Hash = SHA3Algo;
    type HashConfig = ();
    type HashCreateError = Infallible;
    type HashID = SHA3ID;
    type IDs = AscendingCount<LargeObjID>;
    type IDsConfig = ();
    type IDsCreateError = Infallible;
    type InMsg = Vec<u8>;
    type LargeObjAuthNMsg = BasicAuthNed<String, LargeObjMsg<SHA3ID>>;
    type LargeObjMsgAuth = PassthruMsgAuthN<LargeObjMsg<SHA3ID>, String>;
    type LargeObjMsgAuthConfig = ();
    type LargeObjTypes = LargeObjServer;
    type LargeObjWrapper = LargeObjMsg<SHA3ID>;
    type MsgAuth = PassthruMsgAuthN<Vec<u8>, String>;
    type MsgAuthConfig = ();
    type MsgAuthCreateError = Infallible;
    type MsgAuthError = Infallible;
    type MsgPrin = String;
    type Msgs = ExampleServerMsgs;
    type Origin = CompoundFarEndpoint;
    type OutMsg = Vec<u8>;
    type Recv = ExampleServerRecv;
    type Resolver =
        MixedResolver<CompoundFarChannelXfrmPeerAddr, CompoundFarEndpoint>;
    type ResolverConfig = ResolverConfig;
    type SessionAuth = BasicAuthN<String>;
    type SessionAuthConfig = BasicAuthNConfig<String>;
    type SessionAuthNError = Infallible;
    type SessionPrin = String;
    type UDP = PassthruDatagramXfrm<SocketAddr>;
    type UDPConfig = PassthruDatagramXfrmParam;
    type UDPError = Infallible;
    type Unix = PassthruDatagramXfrm<UnixSocketPath>;
    type UnixConfig = PassthruDatagramXfrmParam;
    type UnixError = Infallible;
    type Wrapper = Vec<u8>;
}

impl MulticastLargeObjBusTypes<ExampleCtx> for ExampleClientBusTypes {
    type AuthNChan = CompoundFarChannelsBasicAuthNedLargeObjChan<
        String,
        SHA3Algo,
        PassthruDatagramXfrm<UnixSocketPath>,
        PassthruDatagramXfrm<SocketAddr>
    >;
    type AuthNMsg = BasicAuthNed<String, Vec<u8>>;
    type AuthNSession = BasicAuthNed<
        String,
        CompoundFlow<
            PassthruDatagramXfrm<UnixSocketPath>,
            PassthruDatagramXfrm<SocketAddr>
        >
    >;
    type Decoder = TestBytesCodec;
    type DecoderConfig = ();
    type DecoderCreateError = Infallible;
    type EncodeError = TooShort;
    type Encoder = TestBytesCodec;
    type EncoderConfig = ();
    type EncoderCreateError = Infallible;
    type Epoch = u128;
    type Epochs = AscendingCount<u128>;
    type EpochsConfig = ();
    type Hash = SHA3Algo;
    type HashConfig = ();
    type HashCreateError = Infallible;
    type HashID = SHA3ID;
    type IDs = AscendingCount<LargeObjID>;
    type IDsConfig = ();
    type IDsCreateError = Infallible;
    type InMsg = Vec<u8>;
    type LargeObjAuthNMsg = BasicAuthNed<String, LargeObjMsg<SHA3ID>>;
    type LargeObjMsgAuth = PassthruMsgAuthN<LargeObjMsg<SHA3ID>, String>;
    type LargeObjMsgAuthConfig = ();
    type LargeObjTypes = LargeObjClient;
    type LargeObjWrapper = LargeObjMsg<SHA3ID>;
    type MsgAuth = PassthruMsgAuthN<Vec<u8>, String>;
    type MsgAuthConfig = ();
    type MsgAuthCreateError = Infallible;
    type MsgAuthError = Infallible;
    type MsgPrin = String;
    type Msgs = ExampleClientMsgs;
    type Origin = CompoundFarEndpoint;
    type OutMsg = Vec<u8>;
    type Recv = ExampleClientRecv;
    type Resolver =
        MixedResolver<CompoundFarChannelXfrmPeerAddr, CompoundFarEndpoint>;
    type ResolverConfig = ResolverConfig;
    type SessionAuth = BasicAuthN<String>;
    type SessionAuthConfig = BasicAuthNConfig<String>;
    type SessionAuthNError = Infallible;
    type SessionPrin = String;
    type UDP = PassthruDatagramXfrm<SocketAddr>;
    type UDPConfig = PassthruDatagramXfrmParam;
    type UDPError = Infallible;
    type Unix = PassthruDatagramXfrm<UnixSocketPath>;
    type UnixConfig = PassthruDatagramXfrmParam;
    type UnixError = Infallible;
    type Wrapper = Vec<u8>;
}

fn server(conf: &str) {
    let bus_config: MulticastLargeObjBusConfig<
        String,
        (),
        BasicAuthNConfig<String>,
        (),
        PassthruDatagramXfrmParam,
        PassthruDatagramXfrmParam,
        (),
        (),
        (),
        ResolverConfig,
        (),
        ()
    > = yaml_serde::from_str(conf).unwrap();
    let live = Arc::new(AtomicBool::new(false));
    let waker = Arc::new(Mutex::new(None));
    let recv = ExampleServerRecv {
        waker: waker.clone(),
        live: live.clone()
    };
    let msgs = ExampleServerMsgs {
        waker: waker,
        live: live,
        sent: false
    };
    let ctx = ExampleCtx {
        inner: SharedNSNameCaches::new(),
        tokens: Tokens::new()
    };
    let bus = MulticastLargeObjBus::<ExampleServerBusTypes, ExampleCtx>::start(
        bus_config, ctx, recv, msgs
    )
    .unwrap();

    bus.cleanup();
}

fn client(conf: &str) {
    let bus_config: MulticastLargeObjBusConfig<
        String,
        (),
        BasicAuthNConfig<String>,
        (),
        PassthruDatagramXfrmParam,
        PassthruDatagramXfrmParam,
        (),
        (),
        (),
        ResolverConfig,
        (),
        ()
    > = yaml_serde::from_str(conf).unwrap();
    let live = Arc::new(AtomicBool::new(true));
    let waker = Arc::new(Mutex::new(None));
    let recv = ExampleClientRecv {
        waker: waker.clone(),
        live: live.clone()
    };
    let msgs = ExampleClientMsgs {
        live: live,
        waker: waker,
        retry: Retry::TERRESTRIAL_NETWORK_DEFAULT.clone(),
        nretries: 0
    };
    let ctx = ExampleCtx {
        inner: SharedNSNameCaches::new(),
        tokens: Tokens::new()
    };
    let bus = MulticastLargeObjBus::<ExampleClientBusTypes, ExampleCtx>::start(
        bus_config, ctx, recv, msgs
    )
    .unwrap();

    bus.cleanup();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} [client| server] <config>", args[0]);

        std::process::exit(1);
    }

    env_logger::builder()
        .is_test(true)
        .filter_level(LevelFilter::Trace)
        .init();

    let conf = std::fs::read_to_string(&args[2]).unwrap();

    match args[1].as_str() {
        "client" => client(&conf),
        "server" => server(&conf),
        _ => {
            eprintln!("Usage: {} [client | server]", args[0]);
            std::process::exit(1);
        }
    }
}
