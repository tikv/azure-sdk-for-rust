#![allow(clippy::module_inception)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::derive_partial_eq_without_eq)]
#[cfg(feature = "package-2023-01")]
pub mod package_2023_01;
#[cfg(all(feature = "package-2023-01", not(feature = "no-default-tag")))]
pub use package_2023_01::*;
#[cfg(feature = "package-2022-08")]
pub mod package_2022_08;
#[cfg(all(feature = "package-2022-08", not(feature = "no-default-tag")))]
pub use package_2022_08::*;
#[cfg(feature = "package-2022-06")]
pub mod package_2022_06;
#[cfg(all(feature = "package-2022-06", not(feature = "no-default-tag")))]
pub use package_2022_06::*;
#[cfg(feature = "package-2021-03")]
pub mod package_2021_03;
#[cfg(all(feature = "package-2021-03", not(feature = "no-default-tag")))]
pub use package_2021_03::*;
#[cfg(feature = "package-2020-02-preview")]
pub mod package_2020_02_preview;
#[cfg(all(feature = "package-2020-02-preview", not(feature = "no-default-tag")))]
pub use package_2020_02_preview::*;
