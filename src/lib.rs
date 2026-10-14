//! SHA-256 verified fixed-root upgrade transactions, never linked by product runtimes.

pub mod catalog;
pub mod support;
pub mod upgrade;

pub use catalog::{Product, ProductContract};
pub use support::{FORMAL_RELEASE_TARGET, SupportMatrix, support_matrix};
