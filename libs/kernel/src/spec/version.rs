//! Validated kernel version values.
//!
//! A `KernelVersion` accepts two to four decimal components separated by
//! periods (`6.6.13`, `7.1`, `7.1.4.1`). The first component must be greater
//! than zero. Signs, whitespace, suffixes, non-ASCII digits, empty
//! components, leading or trailing periods, leading zeros in multi-digit
//! components, and components exceeding `u32::MAX` are all rejected, as is
//! the mutable value `latest` (the `kernel-builder` CLI resolves `latest` to
//! an exact version before constructing a value).
//!
//! The value stores one canonical string generated from the parsed numeric
//! components, so `6.6.13` round-trips through `Display`/`FromStr` and
//! compares and orders numerically.

use std::fmt;
use std::str::FromStr;

/// Validation failure for [`KernelVersion`].
///
/// Every variant identifies the rejected input class with a stable reason
/// category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum KernelVersionError {
    /// The value is empty.
    #[error("kernel version must not be empty")]
    Empty,
    /// The value is the reserved mutable word `latest`.
    #[error("kernel version must not be the mutable value `latest`")]
    ReservedLatest,
    /// The value has fewer than two components.
    #[error("kernel version must have at least two components")]
    TooFewComponents,
    /// The value has more than four components.
    #[error("kernel version must have at most four components")]
    TooManyComponents,
    /// The value starts or ends with a period.
    #[error("kernel version must not start or end with a period")]
    LeadingOrTrailingPeriod,
    /// The value contains an empty component (`1..2`).
    #[error("kernel version must not contain empty components")]
    EmptyComponent,
    /// A component has a leading zero (`1.02`).
    #[error("kernel version components must not have leading zeros")]
    LeadingZero,
    /// A component contains non-decimal characters.
    #[error("kernel version components must be decimal digits")]
    NonNumericComponent,
    /// A component exceeds `u32::MAX`.
    #[error("kernel version component exceeds u32::MAX")]
    ComponentOutOfRange,
    /// The first component is zero.
    #[error("kernel version first component must be greater than zero")]
    FirstComponentZero,
}

/// A validated kernel version with a canonical string representation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KernelVersion {
    canonical: String,
    components: [u32; 4],
    len: u8,
}

impl KernelVersion {
    /// Parse `value` into its numeric components and a canonical string.
    pub fn parse(value: &str) -> Result<Self, KernelVersionError> {
        if value.is_empty() {
            return Err(KernelVersionError::Empty);
        }
        if value == "latest" {
            return Err(KernelVersionError::ReservedLatest);
        }
        if value.starts_with('.') || value.ends_with('.') {
            return Err(KernelVersionError::LeadingOrTrailingPeriod);
        }

        let mut components = [0u32; 4];
        let mut len = 0usize;
        for component in value.split('.') {
            if component.is_empty() {
                return Err(KernelVersionError::EmptyComponent);
            }
            if len >= 4 {
                return Err(KernelVersionError::TooManyComponents);
            }
            if !component.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(KernelVersionError::NonNumericComponent);
            }
            if component.len() > 1 && component.starts_with('0') {
                return Err(KernelVersionError::LeadingZero);
            }
            let parsed: u32 = component
                .parse()
                .map_err(|_| KernelVersionError::ComponentOutOfRange)?;
            components[len] = parsed;
            len += 1;
        }
        if len < 2 {
            return Err(KernelVersionError::TooFewComponents);
        }
        if components[0] == 0 {
            return Err(KernelVersionError::FirstComponentZero);
        }

        let canonical = components[..len]
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(".");
        Ok(Self {
            canonical,
            components,
            len: len as u8,
        })
    }

    /// The number of parsed components (two to four).
    pub fn component_count(&self) -> u8 {
        self.len
    }

    /// The parsed numeric components, padded to four entries; only the first
    /// [`Self::component_count`] entries are meaningful.
    pub fn components(&self) -> [u32; 4] {
        self.components
    }

    /// The canonical `major.minor[.patch[.build]]` string.
    pub fn as_str(&self) -> &str {
        &self.canonical
    }
}

impl FromStr for KernelVersion {
    type Err = KernelVersionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl TryFrom<&str> for KernelVersion {
    type Error = KernelVersionError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl AsRef<str> for KernelVersion {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Numeric ordering over the parsed components: `6.9.13 < 6.10.0`.
impl PartialOrd for KernelVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KernelVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let self_len = self.len as usize;
        let other_len = other.len as usize;
        for index in 0..self_len.max(other_len) {
            let a = if index < self_len {
                self.components[index]
            } else {
                0
            };
            let b = if index < other_len {
                other.components[index]
            } else {
                0
            };
            match a.cmp(&b) {
                std::cmp::Ordering::Equal => {}
                ordering => return ordering,
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl fmt::Display for KernelVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_two_to_four_components() {
        let version = KernelVersion::parse("6.6").expect("two");
        assert_eq!(version.component_count(), 2);
        assert_eq!(version.as_str(), "6.6");
        assert_eq!(version.components(), [6, 6, 0, 0]);

        let version = KernelVersion::parse("7.1.4").expect("three");
        assert_eq!(version.as_str(), "7.1.4");

        let version = KernelVersion::parse("7.1.4.1").expect("four");
        assert_eq!(version.component_count(), 4);
        assert_eq!(version.as_str(), "7.1.4.1");
    }

    #[test]
    fn preserves_canonical_zero_components() {
        let version = KernelVersion::parse("6.0.13").expect("valid");
        assert_eq!(version.as_str(), "6.0.13");
    }

    #[test]
    fn rejects_empty_values() {
        assert_eq!(
            KernelVersion::parse("").expect_err("empty"),
            KernelVersionError::Empty
        );
    }

    #[test]
    fn rejects_latest() {
        assert_eq!(
            KernelVersion::parse("latest").expect_err("latest"),
            KernelVersionError::ReservedLatest
        );
    }

    #[test]
    fn rejects_too_few_components() {
        assert_eq!(
            KernelVersion::parse("6").expect_err("one"),
            KernelVersionError::TooFewComponents
        );
    }

    #[test]
    fn rejects_too_many_components() {
        assert_eq!(
            KernelVersion::parse("6.6.13.1.9").expect_err("five"),
            KernelVersionError::TooManyComponents
        );
    }

    #[test]
    fn rejects_leading_and_trailing_periods() {
        assert_eq!(
            KernelVersion::parse(".6.6").expect_err("leading"),
            KernelVersionError::LeadingOrTrailingPeriod
        );
        assert_eq!(
            KernelVersion::parse("6.6.").expect_err("trailing"),
            KernelVersionError::LeadingOrTrailingPeriod
        );
    }

    #[test]
    fn rejects_empty_components() {
        assert_eq!(
            KernelVersion::parse("6..6").expect_err("empty component"),
            KernelVersionError::EmptyComponent
        );
    }

    #[test]
    fn rejects_leading_zeros() {
        assert_eq!(
            KernelVersion::parse("6.06").expect_err("leading zero"),
            KernelVersionError::LeadingZero
        );
        assert_eq!(
            KernelVersion::parse("06.6").expect_err("leading zero first"),
            KernelVersionError::LeadingZero
        );
    }

    #[test]
    fn rejects_non_numeric_components() {
        for value in ["6.6a", "6.+6", "6. 6", "6.-6", "6.6.13-rc1", "6.٦"] {
            assert_eq!(
                KernelVersion::parse(value).expect_err("non numeric"),
                KernelVersionError::NonNumericComponent,
                "{value}"
            );
        }
    }

    #[test]
    fn rejects_components_above_u32_max() {
        assert_eq!(
            KernelVersion::parse("4294967296.1").expect_err("overflow"),
            KernelVersionError::ComponentOutOfRange
        );
        assert_eq!(
            KernelVersion::parse("6.4294967296").expect_err("overflow second"),
            KernelVersionError::ComponentOutOfRange
        );
    }

    #[test]
    fn rejects_zero_first_component() {
        assert_eq!(
            KernelVersion::parse("0.1").expect_err("zero first"),
            KernelVersionError::FirstComponentZero
        );
        assert_eq!(
            KernelVersion::parse("0.0.1").expect_err("zero first three"),
            KernelVersionError::FirstComponentZero
        );
    }

    #[test]
    fn orders_numerically_not_lexically() {
        let older = KernelVersion::parse("6.9.13").expect("older");
        let newer = KernelVersion::parse("6.10.0").expect("newer");
        assert!(older < newer);
        assert!(newer > older);
    }

    #[test]
    fn round_trips_through_display_and_fromstr() {
        for value in ["6.6", "6.6.13", "7.1.4.1"] {
            let version = KernelVersion::parse(value).expect("valid");
            let reparsed = version
                .to_string()
                .parse::<KernelVersion>()
                .expect("round trip");
            assert_eq!(version, reparsed, "{value}");
        }
    }
}
