//! Hash functions.

pub(crate) mod sha256;
pub(crate) mod sha512;
pub(crate) mod sm3;

pub(crate) use self::sha256::sha256;
pub(crate) use self::sha512::sha512;
pub(crate) use self::sm3::sm3;
