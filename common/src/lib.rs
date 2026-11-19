//! Types and logic shared by the hl-http host and guest.
//!
//! * [`Trailers`] is the value of the trailers futures that cross the sandbox boundary.
//! * [`Redactor`] is the guest's body filter. It lives here so host unit tests cover it.

#![no_std]

extern crate alloc;

mod redact;
mod trailers;

pub use redact::Redactor;
pub use trailers::Trailers;
