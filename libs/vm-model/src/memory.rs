//! Validated memory allocation requests.

/// Memory allocation requested for a VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Memory {
    /// Allocate the specified number of megabytes.
    MB(u64),
}

impl Memory {
    /// Return the requested number of megabytes.
    pub fn mb(self) -> u64 {
        match self {
            Self::MB(mb) => mb,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mb_returns_the_requested_count() {
        assert_eq!(Memory::MB(512).mb(), 512);
    }

    #[test]
    fn mb_round_trips() {
        let memory = Memory::MB(1024);
        assert_eq!(memory, Memory::MB(memory.mb()));
    }
}
