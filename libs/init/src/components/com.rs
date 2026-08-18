use std::{
    fs::{File, OpenOptions},
    io::{self, BufReader, Error, Result, Write},
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::OpenOptionsExt,
    },
};

use nix::sys::termios::{self, SetArg};
use protocol::auth::{MAX_BOOT_CONFIG_FRAME, MAX_COMMAND_FRAME};

pub struct Com {
    reader: BufReader<File>,
    writer: File,
}

impl Com {
    pub fn open(path: &str) -> Result<Self> {
        // A guest serial port may not advertise modem carrier. Use
        // O_NONBLOCK while acquiring it so init cannot hang before the host
        // has a chance to connect COM1, then restore blocking reads for the
        // framed protocol below.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
            .open(path)?;

        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(Error::last_os_error());
        }
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) } < 0 {
            return Err(Error::last_os_error());
        }

        let fd = file.as_fd();
        let mut tio = termios::tcgetattr(fd).map_err(|e| Error::new(io::ErrorKind::Other, e))?;
        termios::cfmakeraw(&mut tio);
        tio.control_flags
            .insert(termios::ControlFlags::CLOCAL | termios::ControlFlags::CREAD);
        termios::tcsetattr(fd, SetArg::TCSANOW, &tio)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let writer = file.try_clone()?;
        Ok(Self {
            reader: BufReader::new(file),
            writer,
        })
    }

    /// Send one bounded little-endian length-prefixed control-plane frame.
    pub fn send_frame(&mut self, payload: &[u8], maximum: usize) -> io::Result<()> {
        if maximum > MAX_COMMAND_FRAME {
            return Err(Error::new(
                io::ErrorKind::InvalidInput,
                "COM1 frame limit exceeds the library maximum",
            ));
        }
        let length = u32::try_from(payload.len()).map_err(|_| {
            Error::new(io::ErrorKind::InvalidInput, "COM1 frame exceeds u32 length")
        })?;
        if payload.len() > maximum {
            return Err(Error::new(
                io::ErrorKind::InvalidInput,
                "COM1 frame exceeds its protocol limit",
            ));
        }
        self.writer.write_all(&length.to_le_bytes())?;
        self.writer.write_all(payload)?;
        self.writer.flush()
    }

    /// Receive one bounded little-endian length-prefixed control-plane frame.
    /// The declared length is checked before any payload allocation.
    pub fn recv_frame(&mut self, maximum: usize) -> io::Result<Vec<u8>> {
        if maximum > MAX_COMMAND_FRAME {
            return Err(Error::new(
                io::ErrorKind::InvalidInput,
                "COM1 frame limit exceeds the library maximum",
            ));
        }
        let mut length_bytes = [0u8; 4];
        std::io::Read::read_exact(&mut self.reader, &mut length_bytes)?;
        let length = u32::from_le_bytes(length_bytes) as usize;
        if length > maximum {
            return Err(Error::new(
                io::ErrorKind::InvalidData,
                "COM1 frame exceeds its protocol limit",
            ));
        }
        let mut payload = Vec::new();
        payload.try_reserve_exact(length).map_err(|_| {
            Error::new(
                io::ErrorKind::OutOfMemory,
                "COM1 frame payload allocation failed",
            )
        })?;
        payload.resize(length, 0);
        std::io::Read::read_exact(&mut self.reader, &mut payload)?;
        Ok(payload)
    }

    /// Receive the bounded boot frame used by the init process.
    pub fn recv_boot_frame(&mut self) -> io::Result<Vec<u8>> {
        self.recv_frame(MAX_BOOT_CONFIG_FRAME)
    }
}
