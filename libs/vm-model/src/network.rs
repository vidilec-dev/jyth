//! Validated, lifecycle-owned NAT network configuration.
//!
//! [`Nat`] is the host-neutral boundary for host and guest network settings.
//! Its fields are intentionally private: once a value has been constructed,
//! all consumers see the same parsed addresses and prefix rather than
//! reparsing caller-controlled strings at different trust boundaries.

use ipnet::Ipv4Net;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use thiserror::Error;

/// Maximum number of DNS servers accepted by the NAT API.
pub const MAX_DNS_SERVERS: usize = 8;

/// The two IPv4 addresses that must be distinct and usable inside a NAT
/// subnet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatAddress {
    /// The address used by the host-side NAT gateway.
    Gateway,
    /// The static address assigned to the guest.
    GuestIp,
}

impl fmt::Display for NatAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gateway => formatter.write_str("NAT gateway"),
            Self::GuestIp => formatter.write_str("NAT guest IP"),
        }
    }
}

/// Validation failures returned when constructing a [`Nat`].
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum NatError {
    /// The subnet text was not an IPv4 CIDR network.
    #[error("NAT subnet {value:?} is not a valid IPv4 CIDR: {reason}")]
    InvalidSubnet {
        /// The offending subnet text.
        value: String,
        /// Why the text is not a valid IPv4 CIDR.
        reason: String,
    },
    /// A gateway or guest address was not a valid IPv4 address.
    #[error("{field} address {value:?} is not a valid IPv4 address: {reason}")]
    InvalidAddress {
        /// Which address role failed validation.
        field: NatAddress,
        /// The offending address text.
        value: String,
        /// Why the text is not a valid IPv4 address.
        reason: String,
    },
    /// A subnet this narrow cannot provide distinct gateway and guest
    /// addresses while retaining its network and broadcast addresses.
    #[error("NAT subnet prefix /{prefix_len} is too narrow; the prefix length must be at most /30")]
    SubnetTooSmall {
        /// The offending prefix length.
        prefix_len: u8,
    },
    /// An endpoint address is outside the configured subnet.
    #[error("{field} address {address} is outside NAT subnet {subnet}")]
    AddressOutsideSubnet {
        /// Which address role fell outside the subnet.
        field: NatAddress,
        /// The offending endpoint address.
        address: Ipv4Addr,
        /// The configured subnet.
        subnet: Ipv4Net,
    },
    /// An endpoint address is the subnet's network address.
    #[error("{field} address {address} is the NAT subnet network address")]
    AddressIsNetwork {
        /// Which address role collided with the network address.
        field: NatAddress,
        /// The offending endpoint address.
        address: Ipv4Addr,
    },
    /// An endpoint address is the subnet's broadcast address.
    #[error("{field} address {address} is the NAT subnet broadcast address")]
    AddressIsBroadcast {
        /// Which address role collided with the broadcast address.
        field: NatAddress,
        /// The offending endpoint address.
        address: Ipv4Addr,
    },
    /// The gateway and guest cannot share one address.
    #[error("NAT gateway and guest IP must be different; both are {address}")]
    AddressesEqual {
        /// The shared address.
        address: Ipv4Addr,
    },
    /// A DNS entry was not a valid IP address.
    #[error("NAT DNS server at index {index} {value:?} is invalid: {reason}")]
    InvalidDns {
        /// The index of the offending DNS entry.
        index: usize,
        /// The offending DNS text.
        value: String,
        /// Why the text is not a valid IP address.
        reason: String,
    },
    /// More than [`MAX_DNS_SERVERS`] entries were supplied.
    #[error("NAT DNS server list has at least {actual} entries; the maximum is {maximum}")]
    TooManyDnsServers {
        /// How many DNS entries were supplied.
        actual: usize,
        /// The configured maximum.
        maximum: usize,
    },
}

/// A validated IPv4 NAT network owned by the VM lifecycle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nat {
    subnet: Ipv4Net,
    gateway: Ipv4Addr,
    guest_ip: Ipv4Addr,
    dns: Vec<IpAddr>,
}

impl Default for Nat {
    fn default() -> Self {
        Self::try_new(
            "10.77.0.0/24",
            "10.77.0.1",
            "10.77.0.10",
            ["8.8.8.8", "1.1.1.1"],
        )
        .expect("the built-in NAT defaults must be valid")
    }
}

impl Nat {
    /// Parse and validate a NAT configuration.
    ///
    /// The returned value owns parsed [`Ipv4Net`], [`Ipv4Addr`], and
    /// [`IpAddr`] values. Callers cannot mutate the fields into an invalid
    /// configuration after construction.
    pub fn try_new(
        subnet: impl AsRef<str>,
        gateway: impl AsRef<str>,
        guest_ip: impl AsRef<str>,
        dns: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Self, NatError> {
        let subnet_text = subnet.as_ref();
        let subnet = Ipv4Net::from_str(subnet_text).map_err(|error| NatError::InvalidSubnet {
            value: subnet_text.to_owned(),
            reason: error.to_string(),
        })?;
        let gateway = parse_endpoint(gateway.as_ref(), NatAddress::Gateway)?;
        let guest_ip = parse_endpoint(guest_ip.as_ref(), NatAddress::GuestIp)?;

        let mut parsed_dns = Vec::new();
        for (index, value) in dns.into_iter().enumerate() {
            if index >= MAX_DNS_SERVERS {
                return Err(NatError::TooManyDnsServers {
                    actual: index + 1,
                    maximum: MAX_DNS_SERVERS,
                });
            }

            let value = value.as_ref();
            let address = value
                .parse::<IpAddr>()
                .map_err(|error| NatError::InvalidDns {
                    index,
                    value: value.to_owned(),
                    reason: error.to_string(),
                })?;
            parsed_dns.push(address);
        }

        validate_endpoint(subnet, NatAddress::Gateway, gateway)?;
        validate_endpoint(subnet, NatAddress::GuestIp, guest_ip)?;
        if gateway == guest_ip {
            return Err(NatError::AddressesEqual { address: gateway });
        }

        Ok(Self {
            subnet,
            gateway,
            guest_ip,
            dns: parsed_dns,
        })
    }

    /// Return the validated subnet.
    pub fn subnet(&self) -> Ipv4Net {
        self.subnet
    }

    /// Return the validated host-side gateway address.
    pub fn gateway(&self) -> Ipv4Addr {
        self.gateway
    }

    /// Return the validated guest address.
    pub fn guest_ip(&self) -> Ipv4Addr {
        self.guest_ip
    }

    /// Return the validated DNS server addresses.
    pub fn dns(&self) -> &[IpAddr] {
        &self.dns
    }
}

fn parse_endpoint(value: &str, field: NatAddress) -> Result<Ipv4Addr, NatError> {
    value
        .parse::<Ipv4Addr>()
        .map_err(|error| NatError::InvalidAddress {
            field,
            value: value.to_owned(),
            reason: error.to_string(),
        })
}

fn validate_endpoint(
    subnet: Ipv4Net,
    field: NatAddress,
    address: Ipv4Addr,
) -> Result<(), NatError> {
    if subnet.prefix_len() > 30 {
        return Err(NatError::SubnetTooSmall {
            prefix_len: subnet.prefix_len(),
        });
    }
    if !subnet.contains(&address) {
        return Err(NatError::AddressOutsideSubnet {
            field,
            address,
            subnet,
        });
    }
    if address == subnet.network() {
        return Err(NatError::AddressIsNetwork { field, address });
    }
    if address == subnet.broadcast() {
        return Err(NatError::AddressIsBroadcast { field, address });
    }
    Ok(())
}

/// `From<()> for Nat` is the zero-configuration builder shorthand.
impl From<()> for Nat {
    fn from(_: ()) -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_nat() -> Nat {
        Nat::try_new(
            "192.168.42.0/24",
            "192.168.42.1",
            "192.168.42.7",
            ["9.9.9.9", "2001:4860:4860::8888"],
        )
        .expect("test NAT is valid")
    }

    #[test]
    fn default_yields_safe_private_subnet() {
        let nat = Nat::default();
        assert_eq!(nat.subnet().to_string(), "10.77.0.0/24");
        assert_eq!(nat.gateway(), Ipv4Addr::new(10, 77, 0, 1));
        assert_eq!(nat.guest_ip(), Ipv4Addr::new(10, 77, 0, 10));
        assert_eq!(
            nat.dns(),
            &[
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            ]
        );
    }

    #[test]
    fn from_unit_returns_default() {
        let nat: Nat = ().into();
        assert_eq!(nat, Nat::default());
    }

    #[test]
    fn try_new_accepts_valid_ipv4_and_ipv6_dns() {
        let nat = valid_nat();
        assert_eq!(nat.subnet().to_string(), "192.168.42.0/24");
        assert_eq!(nat.gateway(), Ipv4Addr::new(192, 168, 42, 1));
        assert_eq!(nat.guest_ip(), Ipv4Addr::new(192, 168, 42, 7));
        assert_eq!(nat.dns().len(), 2);
    }

    #[test]
    fn rejects_non_ipv4_subnet() {
        let error = Nat::try_new(
            "2001:db8::/64",
            "10.0.0.1",
            "10.0.0.2",
            std::iter::empty::<&str>(),
        )
        .unwrap_err();
        assert!(matches!(error, NatError::InvalidSubnet { .. }));
    }

    #[test]
    fn rejects_invalid_subnet_text() {
        let error = Nat::try_new(
            "not-a-cidr",
            "10.0.0.1",
            "10.0.0.2",
            std::iter::empty::<&str>(),
        )
        .unwrap_err();
        assert!(matches!(error, NatError::InvalidSubnet { .. }));
    }

    #[test]
    fn rejects_invalid_endpoint_text() {
        let error = Nat::try_new(
            "10.0.0.0/24",
            "not-an-ip",
            "10.0.0.2",
            std::iter::empty::<&str>(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            NatError::InvalidAddress {
                field: NatAddress::Gateway,
                ..
            }
        ));
    }

    #[test]
    fn rejects_subnet_without_two_usable_addresses() {
        for subnet in ["10.0.0.0/31", "10.0.0.1/32"] {
            let error = Nat::try_new(subnet, "10.0.0.1", "10.0.0.2", std::iter::empty::<&str>())
                .unwrap_err();
            assert!(matches!(error, NatError::SubnetTooSmall { .. }), "{subnet}");
        }
    }

    #[test]
    fn rejects_endpoint_outside_subnet() {
        let error = Nat::try_new(
            "10.0.0.0/24",
            "10.0.1.1",
            "10.0.0.2",
            std::iter::empty::<&str>(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            NatError::AddressOutsideSubnet {
                field: NatAddress::Gateway,
                ..
            }
        ));
    }

    #[test]
    fn rejects_network_and_broadcast_addresses() {
        let network = Nat::try_new(
            "10.0.0.0/24",
            "10.0.0.0",
            "10.0.0.2",
            std::iter::empty::<&str>(),
        )
        .unwrap_err();
        assert!(matches!(network, NatError::AddressIsNetwork { .. }));

        let broadcast = Nat::try_new(
            "10.0.0.0/24",
            "10.0.0.1",
            "10.0.0.255",
            std::iter::empty::<&str>(),
        )
        .unwrap_err();
        assert!(matches!(broadcast, NatError::AddressIsBroadcast { .. }));
    }

    #[test]
    fn rejects_identical_gateway_and_guest() {
        let error = Nat::try_new(
            "10.0.0.0/24",
            "10.0.0.1",
            "10.0.0.1",
            std::iter::empty::<&str>(),
        )
        .unwrap_err();
        assert!(matches!(error, NatError::AddressesEqual { .. }));
    }

    #[test]
    fn rejects_invalid_dns() {
        let error = Nat::try_new(
            "10.0.0.0/24",
            "10.0.0.1",
            "10.0.0.2",
            ["8.8.8.8", "not-an-ip"],
        )
        .unwrap_err();
        assert!(matches!(error, NatError::InvalidDns { index: 1, .. }));
    }

    #[test]
    fn rejects_excessive_dns_list() {
        let dns = [
            "1.0.0.1",
            "1.1.1.1",
            "8.8.8.8",
            "8.8.4.4",
            "9.9.9.9",
            "149.112.112.112",
            "208.67.222.222",
            "208.67.220.220",
            "94.140.14.14",
        ];
        let error = Nat::try_new("10.0.0.0/24", "10.0.0.1", "10.0.0.2", dns).unwrap_err();
        assert!(matches!(error, NatError::TooManyDnsServers { .. }));
    }
}
