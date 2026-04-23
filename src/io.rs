//! Traits, helpers, and type definitions for core I/O functionality.
//!
//! For the time being this is a direct re-export of `std::io`, existing as redirection so the
//! remaining rsasl code can use `crate::io` without worrying about the specifics.

#[cfg(feature = "std")]
pub use std::io::*;
#[cfg(not(feature = "std"))]
compile_error!("The \"std\" feature must be enabled for rsasl to function!");
