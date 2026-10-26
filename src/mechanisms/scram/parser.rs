use crate::alloc::{borrow::Cow, string::String, vec::Vec};
use crate::error::{MechanismError, MechanismErrorKind};
use core::fmt::{Display, Formatter};
use core::str::Utf8Error;
use thiserror::Error;

#[derive(Debug, Error, Copy, Clone, Eq, PartialEq)]
pub enum SaslNameError {
    #[error("empty string is invalid for name")]
    Empty,
    #[error("name contains invalid utf-8: {0}")]
    InvalidUtf8(
        #[from]
        #[source]
        Utf8Error,
    ),
    #[error("name contains invalid char {0}")]
    InvalidChar(u8),
    #[error("name contains invalid escape sequence")]
    InvalidEscape,
}

impl MechanismError for SaslNameError {
    fn kind(&self) -> MechanismErrorKind {
        MechanismErrorKind::Parse
    }
}

#[derive(Clone)]
enum SaslEscapeState {
    Done,
    Char(char),
    Comma,
    Comma1,
    Equals,
    Equals1,
}

impl SaslEscapeState {
    pub const fn escape(c: char) -> Self {
        match c {
            ',' => Self::Comma,
            '=' => Self::Equals,
            _ => Self::Char(c),
        }
    }
}

impl Iterator for SaslEscapeState {
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        match *self {
            Self::Done => None,
            Self::Char(c) => {
                *self = Self::Done;
                Some(c)
            }
            Self::Comma => {
                *self = Self::Comma1;
                Some('=')
            }
            Self::Comma1 => {
                *self = Self::Char('C');
                Some('2')
            }
            Self::Equals => {
                *self = Self::Equals1;
                Some('=')
            }
            Self::Equals1 => {
                *self = Self::Char('D');
                Some('3')
            }
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.len();
        (n, Some(n))
    }
}

impl ExactSizeIterator for SaslEscapeState {
    fn len(&self) -> usize {
        match self {
            Self::Done => 0,
            Self::Char(_) => 1,
            Self::Comma | Self::Equals => 3,
            Self::Comma1 | Self::Equals1 => 2,
        }
    }
}

#[repr(transparent)]
/// Escaped saslname type
pub struct SaslName<'a>(Cow<'a, str>);
impl SaslName<'_> {
    /// Convert a Rust-side string into the representation required by SCRAM
    ///
    /// This will clone the given string if characters need escaping
    pub fn escape(input: &str) -> Result<Cow<'_, str>, SaslNameError> {
        if input.is_empty() {
            return Err(SaslNameError::Empty);
        }
        if input.contains('\0') {
            return Err(SaslNameError::InvalidChar(0));
        }

        if input.contains([',', '=']) {
            let escaped: String = input.chars().flat_map(SaslEscapeState::escape).collect();
            Ok(Cow::Owned(escaped))
        } else {
            Ok(Cow::Borrowed(input))
        }
    }

    #[allow(unused)]
    /// Convert a SCRAM-side string into the representation expected by Rust
    ///
    /// This will clone the given string if characters need unescaping
    pub fn unescape(input: &[u8]) -> Result<Cow<'_, str>, SaslNameError> {
        if input.is_empty() {
            return Err(SaslNameError::Empty);
        }

        if let Some(c) = input.iter().find(|byte| matches!(**byte, b'\0' | b',')) {
            return Err(SaslNameError::InvalidChar(*c));
        }

        if let Some(bad) = input.iter().position(|b| matches!(b, b'=')) {
            let mut out = String::with_capacity(input.len());
            let good = core::str::from_utf8(&input[..bad]).map_err(SaslNameError::InvalidUtf8)?;
            out.push_str(good);
            let mut input = &input[bad..];

            while let Some(bad) = input.iter().position(|b| matches!(b, b'=')) {
                let good =
                    core::str::from_utf8(&input[..bad]).map_err(SaslNameError::InvalidUtf8)?;
                out.push_str(good);
                let c = match &input[bad + 1..bad + 3] {
                    b"2C" => ',',
                    b"3D" => '=',
                    _ => return Err(SaslNameError::InvalidEscape),
                };
                out.push(c);
                input = &input[bad..];
            }

            Ok(out.into())
        } else {
            Ok(Cow::Borrowed(core::str::from_utf8(input)?))
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Error)]
pub enum ParseError {
    #[error("bad channel flag")]
    BadCBFlag,
    #[error("channel binding name contains invalid byte {0:#x}")]
    BadCBName(u8),
    #[error("invalid gs2header")]
    BadGS2Header,
    #[error("attribute contains invalid byte {0:#x}")]
    InvalidAttribute(u8),
    #[error("required attribute is missing")]
    MissingAttributes,
    #[error("an extension is unknown but marked mandatory")]
    UnknownMandatoryExtensions,
    #[error("invalid UTF-8: {0}")]
    BadUtf8(
        #[from]
        #[source]
        Utf8Error,
    ),
    #[error("nonce contains invalid character")]
    BadNonce,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub enum GS2CBindFlag<'scram> {
    SupportedNotUsed,
    NotSupported,
    /// Channel bindings of the given name are used
    ///
    /// RFC 5056 Section 7 limits the channel binding name to "any string composed of US-ASCII
    /// alphanumeric characters, period ('.'), and dash ('-')", which is always valid UTF-8
    /// making the use of `str` here correct.
    Used(&'scram str),
}
impl<'scram> GS2CBindFlag<'scram> {
    pub fn parse(input: &'scram [u8]) -> Result<Self, ParseError> {
        match input {
            b"n" => Ok(Self::NotSupported),
            b"y" => Ok(Self::SupportedNotUsed),
            _x if input.len() > 2 && input[0] == b'p' && input[1] == b'=' => {
                let cbname = &input[2..];
                cbname
                    .iter()
                    // According to [RFC5056 Section 7](https://www.rfc-editor.org/rfc/rfc5056#section-7)
                    // valid cb names are only composed of ASCII alphanumeric, '.' and '-'
                    .find(|b| !(matches!(b, b'.' | b'-' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z')))
                    .map_or_else(
                        || {
                            // SAFE because we just checked for a subset of ASCII which is always UTF-8
                            let name = unsafe { core::str::from_utf8_unchecked(cbname) };
                            Ok(Self::Used(name))
                        },
                        |bad| Err(ParseError::BadCBName(*bad)),
                    )
            }
            _ => Err(ParseError::BadCBFlag),
        }
    }

    pub const fn as_ioslices(&self) -> [&'scram [u8]; 2] {
        match self {
            Self::NotSupported => [b"n", &[]],
            Self::SupportedNotUsed => [b"y", &[]],
            Self::Used(name) => [b"p=", name.as_bytes()],
        }
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub struct ClientFirstMessage<'scram> {
    pub cbflag: GS2CBindFlag<'scram>,
    pub authzid: Option<&'scram str>,
    pub username: &'scram str,
    pub nonce: &'scram [u8],
}
impl<'scram> ClientFirstMessage<'scram> {
    #[allow(unused)]
    pub const fn new(
        cbflag: GS2CBindFlag<'scram>,
        authzid: Option<&'scram str>,
        username: &'scram str,
        nonce: &'scram [u8],
    ) -> Self {
        Self {
            cbflag,
            authzid,
            username,
            nonce,
        }
    }

    pub fn parse(input: &'scram [u8]) -> Result<Self, ParseError> {
        let mut partiter = input.split(|b| matches!(b, b','));

        let first = partiter.next().ok_or(ParseError::BadCBFlag)?;
        let cbflag = GS2CBindFlag::parse(first)?;

        let authzid = partiter.next().ok_or(ParseError::BadGS2Header)?;
        let authzid = if authzid.is_empty() {
            None
        } else {
            Some(core::str::from_utf8(&authzid[2..]).map_err(ParseError::BadUtf8)?)
        };

        let next = partiter.next().ok_or(ParseError::MissingAttributes)?;
        if &next[0..2] == b"m=" {
            return Err(ParseError::UnknownMandatoryExtensions);
        }

        let username = if &next[0..2] == b"n=" {
            core::str::from_utf8(&next[2..]).map_err(ParseError::BadUtf8)?
        } else {
            return Err(ParseError::InvalidAttribute(next[0]));
        };

        let next = partiter.next().ok_or(ParseError::MissingAttributes)?;
        let nonce = if &next[0..2] == b"r=" {
            &next[2..]
        } else {
            return Err(ParseError::InvalidAttribute(next[0]));
        };
        if !nonce.iter().all(|b| matches!(b, 0x21..=0x2B | 0x2D..=0x7E)) {
            return Err(ParseError::BadNonce);
        }

        // Input may contain more (non-mandatory) extensions. Since we don't implement any we
        // simply ignore them.

        Ok(Self {
            cbflag,
            authzid,
            username,
            nonce,
        })
    }

    #[allow(clippy::similar_names)]
    fn gs2_header_parts(&self) -> [&'scram [u8]; 4] {
        let [cba, cbb] = self.cbflag.as_ioslices();

        let (prefix, authzid): (&[u8], &[u8]) = self
            .authzid
            .map_or((b",", &[]), |authzid| (b",a=", authzid.as_bytes()));

        [cba, cbb, prefix, authzid]
    }

    #[allow(clippy::similar_names)]
    #[allow(unused)]
    pub fn as_ioslices(&self) -> [&'scram [u8]; 8] {
        let [cba, cbb, prefix, authzid] = self.gs2_header_parts();

        [
            cba,
            cbb,
            prefix,
            authzid,
            b",n=",
            self.username.as_bytes(),
            b",r=",
            self.nonce,
        ]
    }

    #[allow(clippy::similar_names)]
    pub(super) fn build_gs2_header_vec(&self) -> Vec<u8> {
        let [cba, cbb, prefix, authzid] = self.gs2_header_parts();

        let gs2_header_len = cba.len() + cbb.len() + prefix.len() + authzid.len() + 1;
        let mut gs2_header = Vec::with_capacity(gs2_header_len);

        // y | n | p=
        gs2_header.extend_from_slice(cba);
        // &[] | cbname
        gs2_header.extend_from_slice(cbb);
        // b","
        gs2_header.extend_from_slice(prefix);
        // authzid
        gs2_header.extend_from_slice(authzid);
        // b","
        gs2_header.extend_from_slice(b",");

        gs2_header
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub struct ServerFirst<'scram> {
    /// Client or Client+Server Nonce
    ///
    /// If the field `server_nonce` is None this contains both client and server nonce
    /// concatenated, otherwise it contains only the client nonce.
    pub nonce: &'scram [u8],
    pub server_nonce: Option<&'scram [u8]>,
    pub salt: &'scram [u8],
    pub iteration_count: &'scram [u8],
}

// A server attribute must have its two-byte prefix before either parser can
// inspect it. Keep this check shared by server-first and server-final.
fn next_server_attribute<'a>(
    attributes: &mut impl Iterator<Item = &'a [u8]>,
) -> Result<([u8; 2], &'a [u8]), ParseError> {
    match attributes.next() {
        Some([name, equals, value @ ..]) => Ok(([*name, *equals], value)),
        _ => Err(ParseError::MissingAttributes),
    }
}

impl<'scram> ServerFirst<'scram> {
    pub const fn new(
        client_nonce: &'scram [u8],
        server_nonce: &'scram [u8],
        salt: &'scram [u8],
        iteration_count: &'scram [u8],
    ) -> Self {
        Self {
            nonce: client_nonce,
            server_nonce: Some(server_nonce),
            salt,
            iteration_count,
        }
    }

    pub fn parse(input: &'scram [u8]) -> Result<Self, ParseError> {
        let mut partiter = input.split(|b| matches!(b, b','));

        let (prefix, value) = next_server_attribute(&mut partiter)?;
        if &prefix == b"m=" {
            return Err(ParseError::UnknownMandatoryExtensions);
        }

        let nonce = if &prefix == b"r=" {
            value
        } else {
            return Err(ParseError::InvalidAttribute(prefix[0]));
        };

        let (prefix, value) = next_server_attribute(&mut partiter)?;
        let salt = if &prefix == b"s=" {
            value
        } else {
            return Err(ParseError::InvalidAttribute(prefix[0]));
        };

        let (prefix, value) = next_server_attribute(&mut partiter)?;
        let iteration_count = if &prefix == b"i=" {
            value
        } else {
            return Err(ParseError::InvalidAttribute(prefix[0]));
        };

        // Input may contain more (non-mandatory) extensions. Since we don't implement any we
        // simply ignore them.

        Ok(Self {
            nonce,
            server_nonce: None,
            salt,
            iteration_count,
        })
    }

    pub fn as_ioslices(&self) -> [&'scram [u8]; 7] {
        [
            b"r=",
            self.nonce,
            self.server_nonce.unwrap_or(&[]),
            b",s=",
            self.salt,
            b",i=",
            self.iteration_count,
        ]
    }
}

pub struct ClientFinal<'scram> {
    pub channel_binding: &'scram [u8],
    pub nonce: &'scram [u8],
    pub proof: &'scram [u8],
}

impl<'scram> ClientFinal<'scram> {
    pub const fn new(
        channel_binding: &'scram [u8],
        nonce: &'scram [u8],
        proof: &'scram [u8],
    ) -> Self {
        Self {
            channel_binding,
            nonce,
            proof,
        }
    }

    pub fn parse(input: &'scram [u8]) -> Result<Self, ParseError> {
        let mut partiter = input.split(|b| matches!(b, b','));

        let next = partiter.next().ok_or(ParseError::MissingAttributes)?;
        let channel_binding = if &next[0..2] == b"c=" {
            &next[2..]
        } else {
            return Err(ParseError::InvalidAttribute(next[0]));
        };

        let next = partiter.next().ok_or(ParseError::MissingAttributes)?;
        let nonce = if &next[0..2] == b"r=" {
            &next[2..]
        } else {
            return Err(ParseError::InvalidAttribute(next[0]));
        };

        let proof = loop {
            // Skip all extensions in between nonce and proof since we can't handle them.
            // The ClientFinal and ServerFinal messages notably *can not* contain mandatory extensions.
            let next = partiter.next().ok_or(ParseError::MissingAttributes)?;
            if &next[0..2] == b"p=" {
                break &next[2..];
            }
        };

        if let Some(next) = partiter.next() {
            return Err(ParseError::InvalidAttribute(next[0]));
        }

        Ok(Self {
            channel_binding,
            nonce,
            proof,
        })
    }

    pub const fn to_ioslices(&self) -> [&'scram [u8]; 6] {
        [
            b"c=",
            self.channel_binding,
            b",r=",
            self.nonce,
            b",p=",
            self.proof,
        ]
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub enum ServerErrorValue {
    InvalidEncoding,
    ExtensionsNotSupported,
    InvalidProof,
    ChannelBindingsDontMatch,
    ServerDoesSupportChannelBinding,
    ChannelBindingNotSupported,
    UnsupportedChannelBindingType,
    UnknownUser,
    InvalidUsernameEncoding,
    NoResources,
    OtherError,
}
impl ServerErrorValue {
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::InvalidEncoding => b"invalid-encoding",
            Self::ExtensionsNotSupported => b"extensions-not-supported",
            Self::InvalidProof => b"invalid-proof",
            Self::ChannelBindingsDontMatch => b"channel-bindings-dont-match",
            Self::ServerDoesSupportChannelBinding => b"server-does-support-channel-binding",
            Self::ChannelBindingNotSupported => b"channel-binding-not-supported",
            Self::UnsupportedChannelBindingType => b"unsupported-channel-binding-type",
            Self::UnknownUser => b"unknown-user",
            Self::InvalidUsernameEncoding => b"invalid-username-encoding",
            Self::NoResources => b"no-resources",
            Self::OtherError => b"other-error",
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidEncoding => "invalid encoding",
            Self::ExtensionsNotSupported => "extensions not supported",
            Self::InvalidProof => "invalid proof",
            Self::ChannelBindingsDontMatch => "channel bindings dont match",
            Self::ServerDoesSupportChannelBinding => "server does support channel binding",
            Self::ChannelBindingNotSupported => "channel binding not supported",
            Self::UnsupportedChannelBindingType => "unsupported channel binding type",
            Self::UnknownUser => "unknown user",
            Self::InvalidUsernameEncoding => "invalid username encoding",
            Self::NoResources => "no resources",
            Self::OtherError => "other error",
        }
    }
}
impl Display for ServerErrorValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

pub enum ServerFinal<'scram> {
    Verifier(&'scram [u8]),
    Error(ServerErrorValue, &'scram [u8]),
}

impl<'scram> ServerFinal<'scram> {
    pub const fn server_error(value: ServerErrorValue) -> Self {
        Self::Error(value, value.as_bytes())
    }
    pub fn parse(input: &'scram [u8]) -> Result<Self, ParseError> {
        // There may be extensions following this initial attribute, but we don't implement any of
        // them and none of them can be mandatory so we are allowed to simply ignore all input
        // following the verifier or error
        let mut partiter = input.split(|b| matches!(b, b','));
        let (prefix, value) = next_server_attribute(&mut partiter)?;

        if &prefix == b"v=" {
            Ok(Self::Verifier(value))
        } else if &prefix == b"e=" {
            use ServerErrorValue::{
                ChannelBindingNotSupported, ChannelBindingsDontMatch, ExtensionsNotSupported,
                InvalidEncoding, InvalidProof, InvalidUsernameEncoding, NoResources, OtherError,
                ServerDoesSupportChannelBinding, UnknownUser, UnsupportedChannelBindingType,
            };
            let e = match value {
                b"invalid-encoding" => InvalidEncoding,
                b"extensions-not-supported" => ExtensionsNotSupported,
                b"invalid-proof" => InvalidProof,
                b"channel-bindings-dont-match" => ChannelBindingsDontMatch,
                b"server-does-support-channel-binding" => ServerDoesSupportChannelBinding,
                b"channel-binding-not-supported" => ChannelBindingNotSupported,
                b"unsupported-channel-binding-type" => UnsupportedChannelBindingType,
                b"unknown-user" => UnknownUser,
                b"invalid-username-encoding" => InvalidUsernameEncoding,
                b"no-resources" => NoResources,
                _ => OtherError,
            };
            Ok(Self::Error(e, value))
        } else {
            Err(ParseError::InvalidAttribute(prefix[0]))
        }
    }

    pub const fn to_ioslices(&self) -> [&'scram [u8]; 2] {
        match self {
            Self::Verifier(v) => [b"v=", v],
            Self::Error(_, token) => [b"e=", token],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_final_errors_keep_their_value() {
        for (bytes, expected, token) in [
            (
                &b"e=foo-bar"[..],
                ServerErrorValue::OtherError,
                &b"foo-bar"[..],
            ),
            (
                &b"e=unknown-user,x=1"[..],
                ServerErrorValue::UnknownUser,
                &b"unknown-user"[..],
            ),
            (&b"e="[..], ServerErrorValue::OtherError, &b""[..]),
            (&b"e=a\0b"[..], ServerErrorValue::OtherError, &b"a\0b"[..]),
        ] {
            let ServerFinal::Error(value, original) = ServerFinal::parse(bytes).unwrap() else {
                panic!("expected error")
            };
            assert_eq!(value, expected);
            assert_eq!(original, token);
        }
    }
    #[test]
    fn server_error_bytes_are_unchanged() {
        use ServerErrorValue::*;
        for value in [
            InvalidEncoding,
            ExtensionsNotSupported,
            InvalidProof,
            ChannelBindingsDontMatch,
            ServerDoesSupportChannelBinding,
            ChannelBindingNotSupported,
            UnsupportedChannelBindingType,
            UnknownUser,
            InvalidUsernameEncoding,
            NoResources,
            OtherError,
        ] {
            assert_eq!(
                ServerFinal::server_error(value).to_ioslices().concat(),
                [b"e=", value.as_bytes()].concat()
            );
        }
    }
    #[test]
    fn short_server_first_attributes_are_parse_errors() {
        for input in [
            b"".as_slice(),
            b"r",
            b",x=long",
            b"r=x,,i=4096",
            b"r=x,s,i=4096",
            b"r=x,s=c2FsdA==,",
            b"r=x,s=c2FsdA==,i",
        ] {
            assert_eq!(
                ServerFirst::parse(input),
                Err(ParseError::MissingAttributes)
            );
        }
    }

    #[test]
    fn short_server_final_attributes_are_parse_errors() {
        for input in [b"".as_slice(), b"v", b"e", b",x=long"] {
            assert!(matches!(
                ServerFinal::parse(input),
                Err(ParseError::MissingAttributes)
            ));
        }
    }

    #[test]
    fn test_parse_gs2_cbind_flag() {
        let valid: [(&[u8], GS2CBindFlag); 7] = [
            (b"n", GS2CBindFlag::NotSupported),
            (b"y", GS2CBindFlag::SupportedNotUsed),
            (b"p=tls-unique", GS2CBindFlag::Used("tls-unique")),
            (b"p=.", GS2CBindFlag::Used(".")),
            (b"p=-", GS2CBindFlag::Used("-")),
            (b"p=a", GS2CBindFlag::Used("a")),
            (
                b"p=a-very-long-cb-name.indeed",
                GS2CBindFlag::Used("a-very-long-cb-name.indeed"),
            ),
        ];

        for (input, output) in &valid {
            assert_eq!(GS2CBindFlag::parse(input), Ok(*output));
        }
    }

    #[test]
    fn test_server_final_parsing() {
        let case1 = b"v=AA";
        let ServerFinal::Verifier(b"AA") =
            ServerFinal::parse(case1).expect("Failed to parse case 1")
        else {
            panic!("parsed case 1 incorrectly")
        };
        let case2 = b"e=invalid-encoding";
        let ServerFinal::Error(ServerErrorValue::InvalidEncoding, b"invalid-encoding") =
            ServerFinal::parse(case2).expect("Failed to parse case 2")
        else {
            panic!("parsed case 2 incorrectly")
        };
    }

    #[test]
    fn test_extensions_client_first() {
        let client_first = b"n,,n=testuser,r=ClientNonce,t=extension1,y=extension2,r=extension3";
        let ClientFirstMessage {
            cbflag,
            authzid,
            username,
            nonce,
        } = ClientFirstMessage::parse(client_first).expect("Failed to parse client_first");
        assert_eq!(cbflag, GS2CBindFlag::NotSupported);
        assert_eq!(authzid, None);
        assert_eq!(username, "testuser");
        assert_eq!(nonce, b"ClientNonce");
    }

    #[test]
    fn test_extensions_server_first() {
        let server_first =
            b"r=ServerNonce,s=PasswordSalt,i=1234,r=extension1,s=extension2,i=extension3";
        let ServerFirst {
            nonce,
            server_nonce,
            salt,
            iteration_count,
        } = ServerFirst::parse(server_first).expect("Failed to parse server_first");
        assert_eq!(nonce, b"ServerNonce");
        assert_eq!(server_nonce, None);
        assert_eq!(salt, b"PasswordSalt");
        assert_eq!(iteration_count, b"1234");
    }

    #[test]
    fn test_extensions_client_final() {
        let client_final = b"c=AA,r=ClientNonceServerNonce,c=extension1,r=extension2,p=BB";
        let ClientFinal {
            channel_binding,
            nonce,
            proof,
        } = ClientFinal::parse(client_final).expect("Failed to parse client_final");
        assert_eq!(channel_binding, b"AA");
        assert_eq!(nonce, b"ClientNonceServerNonce");
        assert_eq!(proof, b"BB");
    }

    #[test]
    fn test_extensions_server_final() {
        let server_final = b"v=AA,v=extension1,r=extension2";
        let fin = ServerFinal::parse(server_final).expect("Failed to parse server_final");
        let ServerFinal::Verifier(b"AA") = fin else {
            panic!("Parsed server_final incorrectly");
        };
    }

    #[test]
    fn test_fail_unknown_mandatory_extension() {
        let client_first = b"n,,m=MandatoryExtension,n=testuser,r=ClientNonce,t=extension1,y=extension2,r=extension3";
        assert_eq!(
            ClientFirstMessage::parse(client_first),
            Err(ParseError::UnknownMandatoryExtensions)
        );
    }
}
