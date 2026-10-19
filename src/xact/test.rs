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

use std::collections::HashSet;
use std::convert::Infallible;
use std::fmt::Display;
use std::fmt::Formatter;

use constellation_common::codec::Decoder;
use constellation_common::codec::Encoder;
use constellation_common::config::Create;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::hashid::SHA3Algo;
use constellation_common::hashid::SHA3ID;

use crate::xact::XactBatch;
use crate::xact::XactBatchCodec;
use crate::xact::XactBatchCodecCreateError;
use crate::xact::XactBatchCodecEncodeError;
use crate::xact::XactCommittedRoundCodecCreateError;
use crate::xact::XactCommittedRoundCodecEncodeError;
use crate::xact::XactHashBatch;
use crate::xact::XactHashBatchCodec;
use crate::xact::XactNotifyCodecCreateError;
use crate::xact::XactNotifyCodecEncodeError;
use crate::xact::XactReqCodecCreateError;
use crate::xact::XactReqCodecEncodeError;
use crate::xact::XactSealedCodecCreateError;
use crate::xact::XactSealedCodecError;

#[derive(Clone, Debug)]
pub struct TestEffects {
    effects: Vec<u8>
}

#[derive(Clone, Debug)]
pub struct TestPayload {
    effects: Vec<u8>,
    res: Result<TestResult, TestError>
}

#[derive(Clone, Debug)]
pub struct TestResult {
    val: Vec<u8>
}

#[derive(Clone, Debug)]
pub struct TestError {
    err: String
}

#[derive(Clone, Debug)]
pub struct TestSeal;

#[derive(Clone)]
pub struct TestEffectsCodec;

#[derive(Clone)]
pub struct TestPayloadCodec;

#[derive(Clone)]
pub struct TestResultCodec;

#[derive(Clone)]
pub struct TestErrorCodec;

#[derive(Clone)]
pub struct TestSealCodec;

#[derive(Debug)]
pub struct TestStringError;

pub type TestBatch = XactBatch<
    u128,
    SHA3ID,
    TestSeal,
    TestPayload,
    TestEffects,
    TestResult,
    TestError
>;

pub type TestBatchCodec = XactBatchCodec<
    u128,
    SHA3Algo,
    TestSeal,
    TestPayload,
    TestEffects,
    TestResult,
    TestError,
    TestSealCodec,
    TestPayloadCodec,
    TestEffectsCodec,
    TestResultCodec,
    TestErrorCodec
>;

pub type TestHashBatch = XactHashBatch<
    u128,
    SHA3ID,
    TestSeal,
    TestPayload,
    TestEffects,
    TestResult,
    TestError
>;

pub type TestHashBatchCodec = XactHashBatchCodec<
    u128,
    SHA3Algo,
    TestSeal,
    TestPayload,
    TestEffects,
    TestResult,
    TestError,
    TestSealCodec,
    TestPayloadCodec,
    TestEffectsCodec,
    TestResultCodec,
    TestErrorCodec
>;

pub type TestBatchCodecCreateError = XactBatchCodecCreateError<
    XactSealedCodecCreateError<
        Infallible,
        XactReqCodecCreateError<Infallible, Infallible>
    >,
    XactCommittedRoundCodecCreateError<
        Infallible,
        XactReqCodecCreateError<Infallible, Infallible>
    >,
    XactNotifyCodecCreateError<Infallible, Infallible>
>;

pub type TestBatchCodecEncodeError = XactBatchCodecEncodeError<
    asn1rs::io::per::err::Error,
    XactSealedCodecError<
        asn1rs::io::per::err::Error,
        Infallible,
        XactReqCodecEncodeError<
            Infallible,
            Infallible,
            asn1rs::io::per::err::Error
        >
    >,
    XactCommittedRoundCodecEncodeError<
        asn1rs::io::per::err::Error,
        Infallible,
        XactReqCodecEncodeError<
            Infallible,
            Infallible,
            asn1rs::io::per::err::Error
        >
    >,
    XactNotifyCodecEncodeError<
        asn1rs::io::per::err::Error,
        Infallible,
        Infallible
    >
>;

impl TestPayload {
    #[inline]
    pub fn take(self) -> (TestEffects, Result<TestResult, TestError>) {
        let effects = TestEffects {
            effects: self.effects
        };

        (effects, self.res)
    }
}

impl TestEffects {
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.effects.is_empty()
    }

    #[inline]
    pub fn is_subset_of(
        &self,
        other: &Self
    ) -> bool {
        let sub: HashSet<u8> = self.effects.iter().cloned().collect();
        let sup: HashSet<u8> = other.effects.iter().cloned().collect();

        sub.is_subset(&sup)
    }
}

impl Create for TestSealCodec {
    type Config = ();
    type CreateError = Infallible;

    #[inline]
    fn create(_config: ()) -> Result<Self, Infallible> {
        Ok(TestSealCodec)
    }
}

impl Decoder<TestSeal> for TestSealCodec {
    type DecodeError = Infallible;

    #[inline]
    fn decode(
        &mut self,
        _buf: &[u8]
    ) -> Result<(TestSeal, usize), Self::DecodeError> {
        Ok((TestSeal, 0))
    }
}

impl Encoder<TestSeal> for TestSealCodec {
    type EncodeError = Infallible;

    #[inline]
    fn buf_size(
        &self,
        _val: &TestSeal
    ) -> usize {
        0
    }

    #[inline]
    fn encode(
        &mut self,
        _val: &TestSeal,
        _buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        Ok(0)
    }
}

impl Create for TestEffectsCodec {
    type Config = ();
    type CreateError = Infallible;

    #[inline]
    fn create(_config: ()) -> Result<Self, Infallible> {
        Ok(TestEffectsCodec)
    }
}

impl Decoder<TestEffects> for TestEffectsCodec {
    type DecodeError = Infallible;

    #[inline]
    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(TestEffects, usize), Self::DecodeError> {
        let len = buf[0] as usize;
        let effects = buf[1..len + 1].to_vec();

        Ok((TestEffects { effects: effects }, len + 1))
    }
}

impl Encoder<TestEffects> for TestEffectsCodec {
    type EncodeError = Infallible;

    #[inline]
    fn buf_size(
        &self,
        val: &TestEffects
    ) -> usize {
        val.effects.len() + 1
    }

    #[inline]
    fn encode(
        &mut self,
        val: &TestEffects,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let len = val.effects.len();

        buf[0] = len as u8;
        buf[1..len + 1].copy_from_slice(&val.effects[..]);

        Ok(len + 1)
    }
}

impl Create for TestResultCodec {
    type Config = ();
    type CreateError = Infallible;

    #[inline]
    fn create(_config: ()) -> Result<Self, Infallible> {
        Ok(TestResultCodec)
    }
}

impl Decoder<TestResult> for TestResultCodec {
    type DecodeError = Infallible;

    #[inline]
    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(TestResult, usize), Self::DecodeError> {
        let len = buf[0] as usize;
        let val = buf[1..len + 1].to_vec();

        Ok((TestResult { val: val }, len + 1))
    }
}

impl Encoder<TestResult> for TestResultCodec {
    type EncodeError = Infallible;

    #[inline]
    fn buf_size(
        &self,
        val: &TestResult
    ) -> usize {
        val.val.len() + 1
    }

    #[inline]
    fn encode(
        &mut self,
        val: &TestResult,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let len = val.val.len();

        buf[0] = len as u8;
        buf[1..len + 1].copy_from_slice(&val.val[..]);

        Ok(len + 1)
    }
}

impl Create for TestErrorCodec {
    type Config = ();
    type CreateError = Infallible;

    #[inline]
    fn create(_config: ()) -> Result<Self, Infallible> {
        Ok(TestErrorCodec)
    }
}

impl Decoder<TestError> for TestErrorCodec {
    type DecodeError = TestStringError;

    #[inline]
    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(TestError, usize), Self::DecodeError> {
        let len = buf[0] as usize;
        let val = buf[1..len + 1].to_vec();
        let err = String::from_utf8(val).map_err(|_| TestStringError)?;

        Ok((TestError { err: err }, len + 1))
    }
}

impl Encoder<TestError> for TestErrorCodec {
    type EncodeError = Infallible;

    #[inline]
    fn buf_size(
        &self,
        val: &TestError
    ) -> usize {
        val.err.len() + 1
    }

    #[inline]
    fn encode(
        &mut self,
        val: &TestError,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let bytes = val.err.as_bytes();
        let len = bytes.len();

        buf[0] = len as u8;
        buf[1..len + 1].copy_from_slice(bytes);

        Ok(len + 1)
    }
}

impl Create for TestPayloadCodec {
    type Config = ();
    type CreateError = Infallible;

    #[inline]
    fn create(_config: ()) -> Result<Self, Infallible> {
        Ok(TestPayloadCodec)
    }
}

impl Decoder<TestPayload> for TestPayloadCodec {
    type DecodeError = <TestErrorCodec as Decoder<TestError>>::DecodeError;

    #[inline]
    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(TestPayload, usize), Self::DecodeError> {
        let effects_len = buf[0] as usize;
        let effects = buf[1..effects_len + 1].to_vec();

        let (res, res_len) = if buf[effects_len + 1] == 0 {
            let Ok((res, len)) =
                TestResultCodec.decode(&buf[effects_len + 2..]);

            (Ok(res), len)
        } else {
            let (err, len) = TestErrorCodec.decode(&buf[effects_len + 2..])?;

            (Err(err), len)
        };

        Ok((
            TestPayload {
                effects: effects,
                res: res
            },
            effects_len + res_len + 2
        ))
    }
}

impl Encoder<TestPayload> for TestPayloadCodec {
    type EncodeError = Infallible;

    #[inline]
    fn buf_size(
        &self,
        val: &TestPayload
    ) -> usize {
        let effects = val.effects.len() + 1;
        let result = match &val.res {
            Ok(res) => TestResultCodec.buf_size(res) + 1,
            Err(err) => TestErrorCodec.buf_size(err) + 1
        };

        effects + result
    }

    #[inline]
    fn encode(
        &mut self,
        val: &TestPayload,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let effects_len = val.effects.len();

        buf[0] = effects_len as u8;
        buf[1..effects_len + 1].copy_from_slice(&val.effects[..]);

        let res_len = match &val.res {
            Ok(res) => {
                buf[effects_len + 1] = 0;

                let Ok(len) =
                    TestResultCodec.encode(res, &mut buf[effects_len + 2..]);

                len + 1
            }
            Err(err) => {
                buf[effects_len + 1] = 1;

                let Ok(len) =
                    TestErrorCodec.encode(err, &mut buf[effects_len + 2..]);

                len + 1
            }
        };

        Ok(effects_len + res_len + 1)
    }
}

impl ScopedError for TestStringError {
    #[inline]
    fn scope(&self) -> ErrorScope {
        ErrorScope::Unrecoverable
    }
}

impl Display for TestSeal {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        write!(f, "test seal")
    }
}

impl Display for TestPayload {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        write!(f, "effects: ")?;

        for byte in self.effects.iter() {
            write!(f, "{:02x}", byte)?;
        }

        match &self.res {
            Ok(res) => write!(f, ", result: {}", res),
            Err(err) => write!(f, ", error: {}", err)
        }
    }
}

impl Display for TestEffects {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        write!(f, "effects: ")?;

        for byte in self.effects.iter() {
            write!(f, "{:02x}", byte)?;
        }

        Ok(())
    }
}

impl Display for TestResult {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        write!(f, "result: ")?;

        for byte in self.val.iter() {
            write!(f, "{:02x}", byte)?;
        }

        Ok(())
    }
}

impl Display for TestError {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.err)
    }
}

impl Display for TestStringError {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        write!(f, "bad UTF-8 data")
    }
}
