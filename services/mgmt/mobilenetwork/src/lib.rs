#![allow(clippy::module_inception)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::derive_partial_eq_without_eq)]
#[cfg(feature = "package-2023-09")]
pub mod package_2023_09;
#[cfg(all(feature = "package-2023-09", not(feature = "no-default-tag")))]
pub use package_2023_09::*;
#[cfg(feature = "package-2023-06")]
pub mod package_2023_06;
#[cfg(all(feature = "package-2023-06", not(feature = "no-default-tag")))]
pub use package_2023_06::*;
#[cfg(feature = "package-2022-11-01")]
pub mod package_2022_11_01;
#[cfg(all(feature = "package-2022-11-01", not(feature = "no-default-tag")))]
pub use package_2022_11_01::*;
#[cfg(feature = "package-2022-04-01-preview")]
pub mod package_2022_04_01_preview;
#[cfg(all(feature = "package-2022-04-01-preview", not(feature = "no-default-tag")))]
pub use package_2022_04_01_preview::*;
#[cfg(feature = "package-2022-03-01-preview")]
pub mod package_2022_03_01_preview;
#[cfg(all(feature = "package-2022-03-01-preview", not(feature = "no-default-tag")))]
pub use package_2022_03_01_preview::*;
