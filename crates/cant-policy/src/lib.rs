//! Capability model for Cantainer.
//!
//! - [`Access`]: coarse rights (`r`, `w`, `x`).
//! - [`Policy`]: what a cant may touch, and [`intersect`] for attenuation across exec.
//! - [`file_args`]: the powerbox, which finds the files named on a command line.
//! - [`Protected`]: credentials and persistence points no implicit grant may reach.
//! - [`build`]: turns a manifest plus a command line into a [`Policy`].
//!
//! This crate decides *what* is allowed. `cant-launch` makes the kernel enforce it.

#![forbid(unsafe_code)]

mod access;
mod build;
mod policy;
mod powerbox;
mod protect;

pub use access::Access;
pub use build::{
    Built, Context, PolicyError, SYSTEM_BIN_DIRS, Skipped, UserGrant, build, display_path,
    find_program, resolve_entrypoint,
};
pub use policy::{Grant, Origin, Policy, intersect, not_permitted_by};
pub use powerbox::{FileArg, file_args};
pub use protect::{Collision, Protected, ProtectedPath, READ_ONLY_HOME_PATHS, SECRET_HOME_PATHS};
