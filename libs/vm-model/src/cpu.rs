//! Validated CPU allocation requests.

/// CPU allocation requested for a VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cpu {
    /// Allocate the specified number of virtual CPUs.
    Units(u32),
}

impl Cpu {
    /// Return the requested number of virtual CPUs.
    pub fn units(self) -> u32 {
        match self {
            Self::Units(units) => units,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_returns_the_requested_count() {
        assert_eq!(Cpu::Units(2).units(), 2);
    }

    #[test]
    fn units_round_trips() {
        let cpu = Cpu::Units(4);
        assert_eq!(cpu, Cpu::Units(cpu.units()));
    }
}
