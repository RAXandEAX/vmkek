//! Desktop shell for vmkek.
//!
//! Protect, inspect, and run call the library entry points the CLI uses.
//! This crate does not contain a second protection pipeline and does not
//! implement the Math or Crypto proof channels.

mod action;
mod view;

pub use action::App;
pub use view::view;
