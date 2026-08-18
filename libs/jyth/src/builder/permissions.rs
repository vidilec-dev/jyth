use bitflags::bitflags;

bitflags! {
    /// Unix-style read, write, and execute permission bits.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Permissions: u32 {
        /// Read permission.
        const READ    = 0b100;
        /// Write permission.
        const WRITE   = 0b010;
        /// Execute permission.
        const EXECUTE = 0b001;
        /// All read, write, and execute permissions.
        const ALL     = 0b111;
    }
}
