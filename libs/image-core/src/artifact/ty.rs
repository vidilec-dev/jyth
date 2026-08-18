#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactType {
    Compressed = 1,
    ContainerTar = 2,
    ContainerCpio = 3,
    FileBzImage = 4,
}

impl ArtifactType {
    pub fn to_bytes(self) -> u8 {
        self as u8
    }

    pub fn from_bytes(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Compressed),
            2 => Some(Self::ContainerTar),
            3 => Some(Self::ContainerCpio),
            4 => Some(Self::FileBzImage),
            _ => None,
        }
    }
}
