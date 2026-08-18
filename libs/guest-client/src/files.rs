use protocol::{Command, Event};
use tokio::sync::mpsc;

use crate::client::Client;
use crate::error::GuestClientError;
use crate::transport::HostRequest;

/// Typed live file and directory operations over the guest command bus.
///
/// Every operation correlates its command with the expected reply event and
/// rejects a mismatched event as `GuestClientError::UnexpectedReply`.
pub struct GuestFiles {
    client: Client,
}

impl GuestFiles {
    /// Create a file/dir service over a dispatcher sender.
    pub fn new(cmd_tx: mpsc::Sender<HostRequest>) -> Self {
        Self {
            client: Client::new(cmd_tx),
        }
    }

    /// Read a file from the guest.
    pub async fn file_read(&self, path: &str) -> Result<Vec<u8>, GuestClientError> {
        match self
            .client
            .request_expect(Command::FileRead {
                path: path.to_string(),
            })
            .await?
        {
            Event::FileRead { data, .. } => Ok(data),
            _ => Err(GuestClientError::UnexpectedReply),
        }
    }

    /// Write bytes to a guest file, replacing its contents.
    pub async fn file_write(
        &self,
        path: &str,
        data: impl AsRef<[u8]>,
    ) -> Result<(), GuestClientError> {
        match self
            .client
            .request_expect(Command::FileWrite {
                path: path.to_string(),
                data: data.as_ref().to_vec(),
            })
            .await?
        {
            Event::FileWritten { .. } => Ok(()),
            _ => Err(GuestClientError::UnexpectedReply),
        }
    }

    /// Remove a guest file.
    pub async fn file_remove(&self, path: &str) -> Result<(), GuestClientError> {
        match self
            .client
            .request_expect(Command::FileRemove {
                path: path.to_string(),
            })
            .await?
        {
            Event::FileRemoved { .. } => Ok(()),
            _ => Err(GuestClientError::UnexpectedReply),
        }
    }

    /// Create a guest directory.
    pub async fn dir_create(&self, path: &str) -> Result<(), GuestClientError> {
        match self
            .client
            .request_expect(Command::DirCreate {
                path: path.to_string(),
            })
            .await?
        {
            Event::DirCreated { .. } => Ok(()),
            _ => Err(GuestClientError::UnexpectedReply),
        }
    }

    /// Remove a guest directory.
    pub async fn dir_remove(&self, path: &str) -> Result<(), GuestClientError> {
        match self
            .client
            .request_expect(Command::DirRemove {
                path: path.to_string(),
            })
            .await?
        {
            Event::DirRemoved { .. } => Ok(()),
            _ => Err(GuestClientError::UnexpectedReply),
        }
    }

    /// List entries in a guest directory.
    pub async fn dir_read(&self, path: &str) -> Result<DirListing, GuestClientError> {
        match self
            .client
            .request_expect(Command::DirRead {
                path: path.to_string(),
            })
            .await?
        {
            Event::DirRead { entries, .. } => Ok(DirListing { entries }),
            _ => Err(GuestClientError::UnexpectedReply),
        }
    }
}

/// Result of a guest `dir_read`: the list of entry names under a path.
pub struct DirListing {
    pub(crate) entries: Vec<String>,
}

impl DirListing {
    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the listing is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether `name` is present in the listing.
    pub fn contains(&self, name: &str) -> bool {
        self.entries.iter().any(|e| e == name)
    }

    /// Backwards-compatible alias for [`contains`](Self::contains).
    pub fn has(&self, name: &str) -> bool {
        self.contains(name)
    }

    /// Iterate the entry names by reference.
    pub fn iter(&self) -> impl Iterator<Item = &String> {
        self.entries.iter()
    }
}

impl std::ops::Index<usize> for DirListing {
    type Output = String;

    fn index(&self, index: usize) -> &Self::Output {
        &self.entries[index]
    }
}

impl IntoIterator for DirListing {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl<'a> IntoIterator for &'a DirListing {
    type Item = &'a String;
    type IntoIter = std::slice::Iter<'a, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::{ScriptedTransport, start_dispatcher};
    use std::sync::Arc;

    fn started_files(transport: ScriptedTransport) -> (GuestFiles, crate::support::TestDispatcher) {
        let dispatcher = start_dispatcher(Arc::new(transport));
        (GuestFiles::new(dispatcher.tx()), dispatcher)
    }

    #[tokio::test]
    async fn file_read_returns_matching_data() {
        let (files, dispatcher) = started_files(ScriptedTransport::new(vec![Event::FileRead {
            path: "/tmp/x".to_string(),
            data: b"payload".to_vec(),
        }]));

        assert_eq!(files.file_read("/tmp/x").await.unwrap(), b"payload");
        dispatcher.shutdown().await;
    }

    #[tokio::test]
    async fn file_read_rejects_unexpected_reply() {
        let (files, dispatcher) = started_files(ScriptedTransport::new(vec![Event::VMReady]));

        let error = files
            .file_read("/tmp/x")
            .await
            .expect_err("mismatched reply must fail");
        assert_eq!(error, GuestClientError::UnexpectedReply);
        dispatcher.shutdown().await;
    }

    #[tokio::test]
    async fn file_write_accepts_the_written_event() {
        let (files, dispatcher) = started_files(ScriptedTransport::new(vec![Event::FileWritten {
            path: "/tmp/x".to_string(),
        }]));

        files.file_write("/tmp/x", b"data").await.unwrap();
        dispatcher.shutdown().await;
    }

    #[tokio::test]
    async fn file_write_rejects_unexpected_reply() {
        let (files, dispatcher) = started_files(ScriptedTransport::new(vec![Event::VMReady]));

        let error = files
            .file_write("/tmp/x", b"data")
            .await
            .expect_err("mismatched reply must fail");
        assert_eq!(error, GuestClientError::UnexpectedReply);
        dispatcher.shutdown().await;
    }

    #[tokio::test]
    async fn file_remove_and_dir_operations_accept_matching_replies() {
        let (files, dispatcher) = started_files(ScriptedTransport::new(vec![
            Event::FileRemoved {
                path: "/tmp/x".to_string(),
            },
            Event::DirCreated {
                path: "/d".to_string(),
            },
            Event::DirRemoved {
                path: "/d".to_string(),
            },
        ]));

        files.file_remove("/tmp/x").await.unwrap();
        files.dir_create("/d").await.unwrap();
        files.dir_remove("/d").await.unwrap();
        dispatcher.shutdown().await;
    }

    #[tokio::test]
    async fn dir_read_returns_the_listing() {
        let (files, dispatcher) = started_files(ScriptedTransport::new(vec![Event::DirRead {
            path: "/d".to_string(),
            entries: vec!["a".to_string(), "b".to_string()],
        }]));

        let listing = files.dir_read("/d").await.unwrap();
        assert_eq!(listing.len(), 2);
        assert!(listing.contains("a"));
        assert_eq!(
            listing.iter().map(|e| e.as_str()).collect::<Vec<_>>(),
            ["a", "b"]
        );
        dispatcher.shutdown().await;
    }
}
