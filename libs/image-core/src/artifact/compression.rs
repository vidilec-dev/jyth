#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactCompression {
    None = 1,
    Gzip = 2,
    Zstd = 3,
}

impl ArtifactCompression {
    pub fn to_bytes(self) -> u8 {
        self as u8
    }

    pub fn from_bytes(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::None),
            2 => Some(Self::Gzip),
            3 => Some(Self::Zstd),
            _ => None,
        }
    }
}
