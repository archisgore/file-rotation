pub mod error;

#[cfg(not(feature = "async"))]
mod synchronous;

#[cfg(not(feature = "async"))]
pub use synchronous::*;

#[cfg(feature = "async")]
mod asynchronous;

#[cfg(feature = "async")]
pub use asynchronous::*;
