//! Write output to a file and rotate the files when limits have been exceeded.
//!
//! Defines a simple [tokio::io::Write] object that you can plug into your writers as middleware.
//!
//! # Rotating by Lines #
//!
//! We can rotate log files by using the amount of lines as a limit.
//!
//! ```
//! use file_rotate::{FileRotate, RotationMode};
//! use tokio::{fs, io::AsyncWriteExt};
//!
//! tokio_test::block_on(async {
//!   // Create a directory to store our logs, this is not strictly needed but shows how we can
//!   // arbitrary paths.
//!   fs::create_dir("target/async-my-log-directory-lines").await.unwrap();
//!
//!   // Create a new log writer. The first argument is anything resembling a path. The
//!   // basename is used for naming the log files.
//!   //
//!   // Here we choose to limit logs by 10 lines, and have at most 2 rotated log files. This
//!   // makes the total amount of log files 4, since the original file is present as well as
//!   // file 0.
//!   let mut log = FileRotate::new("target/async-my-log-directory-lines/my-log-file", RotationMode::Lines(3), 2).await.unwrap();
//!
//!   // Write a bunch of lines
//!   log.write("Line 1: Hello World!\n".as_bytes()).await;
//!   for idx in 2..11 {
//!     log.write(format!("Line {}\n", idx).as_bytes()).await;
//!   }
//!
//!   assert_eq!("Line 10\n", fs::read_to_string("target/async-my-log-directory-lines/my-log-file").await.unwrap());
//!
//!   assert_eq!("Line 1: Hello World!\nLine 2\nLine 3\n", fs::read_to_string("target/async-my-log-directory-lines/my-log-file.0").await.unwrap());
//!   assert_eq!("Line 4\nLine 5\nLine 6\n", fs::read_to_string("target/async-my-log-directory-lines/my-log-file.1").await.unwrap());
//!   //assert_eq!("Line 7\nLine 8\nLine 9\n", fs::read_to_string("target/async-my-log-directory-lines/my-log-file.2").await.unwrap());
//!
//!   fs::remove_dir_all("target/async-my-log-directory-lines").await;
//! });
//! ```
//!
//!
//! # Rotating by Bytes surpassing a threshold, but without splitting a buffer mid-way#
//!
//! We can rotate log files but never splitting a buffer half-way. This means a single buffer may
//! end up surpassing the number of expected bytes in a file, but that entire buffer will be
//! written. When the file surpasses the number of bytes to rotate, it'll be rotated for the
//! next buffer.
//!
//! When lines are written in a single buffer as demonstrated below, this ensures the logs
//! contain complete lines which do not split across files.
//!
//! ```
//! use file_rotate::{FileRotate, RotationMode};
//! use tokio::{fs, io::AsyncWriteExt};
//!
//! tokio_test::block_on(async {
//!
//!   // Create a directory to store our logs, this is not strictly needed but shows how we can
//!   // arbitrary paths.
//!   fs::create_dir("target/async-my-log-directory-lines").await.unwrap();
//!
//!   // Create a new log writer. The first argument is anything resembling a path. The
//!   // basename is used for naming the log files.
//!   //
//!   // Here we choose to limit logs by 10 lines, and have at most 2 rotated log files. This
//!   // makes the total amount of log files 4, since the original file is present as well as
//!   // file 0.
//!   let mut log = FileRotate::new("target/async-my-log-directory-lines/my-log-file", RotationMode::BytesSurpassed(2), 2).await.unwrap();
//!
//!   // Write a bunch of lines
//!   log.write("Line 1: Hello World!\n".as_bytes()).await;
//!   for idx in 2..11 {
//!     log.write(format!("Line {}", idx).as_bytes()).await;
//!   }
//!
//!   // the latest file is empty - since the previous file surpassed bytes and was rotated out
//!   assert_eq!("", fs::read_to_string("target/async-my-log-directory-lines/my-log-file").await.unwrap());
//!
//!   assert_eq!("Line 10", fs::read_to_string("target/async-my-log-directory-lines/my-log-file.0").await.unwrap());
//!   assert_eq!("Line 8", fs::read_to_string("target/async-my-log-directory-lines/my-log-file.1").await.unwrap());
//!   assert_eq!("Line 9", fs::read_to_string("target/async-my-log-directory-lines/my-log-file.2").await.unwrap());
//!
//!   fs::remove_dir_all("target/async-my-log-directory-lines").await;
//! });
//! ```
//!
//!
//! # Rotating by Bytes #
//!
//! Another method of rotation is by bytes instead of lines.
//!
//! ```
//! use file_rotate::{FileRotate, RotationMode};
//! use tokio::{fs, io::AsyncWriteExt};
//!
//! tokio_test::block_on(async {
//!   fs::create_dir("target/async-my-log-directory-bytes").await;
//!
//!   let mut log = FileRotate::new("target/async-my-log-directory-bytes/my-log-file", RotationMode::Bytes(5), 2).await.unwrap();
//!
//!   log.write("Test file\n".as_bytes()).await;
//!
//!   assert_eq!("Test ", fs::read_to_string("target/async-my-log-directory-bytes/my-log-file.0").await.unwrap());
//!   assert_eq!("file\n", fs::read_to_string("target/async-my-log-directory-bytes/my-log-file").await.unwrap());
//!
//!   fs::remove_dir_all("target/async-my-log-directory-bytes").await;
//! });
//! ```
//!
//! # Rotation Method #
//!
//! The rotation method used is to always write to the base path, and then move the file to a new
//! location when the limit is exceeded. The moving occurs in the sequence 0, 1, 2, n, 0, 1, 2...
//!
//! Here's an example with 1 byte limits:
//!
//! ```
//! use file_rotate::{FileRotate, RotationMode};
//! use tokio::{fs, io::AsyncWriteExt};
//!
//! tokio_test::block_on(async {
//!   fs::create_dir("target/async-my-log-directory-small").await;
//!
//!   let mut log = FileRotate::new("target/async-my-log-directory-small/my-log-file", RotationMode::Bytes(1), 3).await.unwrap();
//!
//!   log.write("A".as_bytes()).await;
//!   assert_eq!("A", fs::read_to_string("target/async-my-log-directory-small/my-log-file").await.unwrap());
//!
//!   log.write("B".as_bytes()).await;
//!   assert_eq!("A", fs::read_to_string("target/async-my-log-directory-small/my-log-file.0").await.unwrap());
//!   assert_eq!("B", fs::read_to_string("target/async-my-log-directory-small/my-log-file").await.unwrap());
//!
//!   log.write("C".as_bytes()).await;
//!   assert_eq!("A", fs::read_to_string("target/async-my-log-directory-small/my-log-file.0").await.unwrap());
//!   assert_eq!("B", fs::read_to_string("target/async-my-log-directory-small/my-log-file.1").await.unwrap());
//!   assert_eq!("C", fs::read_to_string("target/async-my-log-directory-small/my-log-file").await.unwrap());
//!
//!   log.write("D".as_bytes()).await;
//!   assert_eq!("A", fs::read_to_string("target/async-my-log-directory-small/my-log-file.0").await.unwrap());
//!   assert_eq!("B", fs::read_to_string("target/async-my-log-directory-small/my-log-file.1").await.unwrap());
//!   assert_eq!("C", fs::read_to_string("target/async-my-log-directory-small/my-log-file.2").await.unwrap());
//!   assert_eq!("D", fs::read_to_string("target/async-my-log-directory-small/my-log-file").await.unwrap());
//!
//!   log.write("E".as_bytes()).await;
//!   assert_eq!("A", fs::read_to_string("target/async-my-log-directory-small/my-log-file.0").await.unwrap());
//!   assert_eq!("B", fs::read_to_string("target/async-my-log-directory-small/my-log-file.1").await.unwrap());
//!   assert_eq!("C", fs::read_to_string("target/async-my-log-directory-small/my-log-file.2").await.unwrap());
//!   assert_eq!("D", fs::read_to_string("target/async-my-log-directory-small/my-log-file.3").await.unwrap());
//!   assert_eq!("E", fs::read_to_string("target/async-my-log-directory-small/my-log-file").await.unwrap());
//!
//!
//!   // Here we overwrite the 0 file since we're out of log files, restarting the sequencing
//!   log.write("F".as_bytes()).await;
//!   assert_eq!("E", fs::read_to_string("target/async-my-log-directory-small/my-log-file.0").await.unwrap());
//!   assert_eq!("B", fs::read_to_string("target/async-my-log-directory-small/my-log-file.1").await.unwrap());
//!   assert_eq!("C", fs::read_to_string("target/async-my-log-directory-small/my-log-file.2").await.unwrap());
//!   assert_eq!("D", fs::read_to_string("target/async-my-log-directory-small/my-log-file.3").await.unwrap());
//!   assert_eq!("F", fs::read_to_string("target/async-my-log-directory-small/my-log-file").await.unwrap());
//!
//!   fs::remove_dir_all("target/async-my-log-directory-small").await;
//! });
//! ```
//!
//! # Filesystem Errors #
//!
//! If the directory containing the logs is deleted or somehow made inaccessible then the rotator
//! will simply continue operating without fault. When a rotation occurs, it attempts to open a
//! file in the directory. If it can, it will just continue logging. If it can't then the written
//! date is sent to the void.
//!
//! This logger never panics.
use crate::error;
use core::future::Future;
use core::pin::Pin;
use futures::task::{Context, Poll};
use std::path::{Path, PathBuf};
use tokio::{
    fs::{self, File},
    io::{self, AsyncWrite},
};

// ---

type Result<T> = std::result::Result<T, error::Error>;

pub enum RotateState {
    PendingRename(Pin<Box<dyn Future<Output = io::Result<()>>>>),
    PendingCreate(Pin<Box<dyn Future<Output = io::Result<fs::File>>>>),
    Done,
}

/// Condition on which a file is rotated.
pub enum RotationMode {
    /// Cut the log at the exact size in bytes.
    Bytes(usize),
    /// Cut the log file at line breaks.
    Lines(usize),
    /// Cut the log file after surpassing size in bytes (but having written a complete buffer from a write call.)
    BytesSurpassed(usize),
}

/// The main writer used for rotating logs.
pub struct FileRotate {
    basename: PathBuf,
    count: usize,
    file: Pin<Box<File>>,
    file_number: usize,
    max_file_number: usize,
    mode: RotationMode,

    //transient stuff used by poll
    written: usize,
    buf_to_write: Option<Vec<u8>>,
    rotate_state: RotateState,
}

impl FileRotate {
    /// Create a new [FileRotate].
    ///
    /// The basename of the `path` is used to create new log files by appending an extension of the
    /// form `.N`, where N is `0..=max_file_number`.
    ///
    /// `rotation_mode` specifies the limits for rotating a file.
    ///
    /// # Panics
    ///
    /// Panics if `bytes == 0` or `lines == 0`.
    pub async fn new<P: AsRef<Path>>(
        path: P,
        rotation_mode: RotationMode,
        max_file_number: usize,
    ) -> Result<Self> {
        match rotation_mode {
            RotationMode::Bytes(bytes) if bytes == 0 => {
                return Err(error::Error::ZeroBytes);
            }
            RotationMode::Lines(lines) if lines == 0 => {
                return Err(error::Error::ZeroLines);
            }
            RotationMode::BytesSurpassed(bytes) if bytes == 0 => {
                return Err(error::Error::ZeroBytes);
            }
            _ => {}
        };

        Ok(Self {
            basename: path.as_ref().to_path_buf(),
            count: 0,
            file: Box::pin(File::create(&path).await?),
            file_number: 0,
            max_file_number,
            mode: rotation_mode,

            written: 0,
            buf_to_write: None,
            rotate_state: RotateState::Done,
        })
    }

    fn poll_rotate(self: &mut Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.rotate_state {
            RotateState::Done => {
                // if called when done, start rotation...
                let basename = self.basename.clone();
                let mut path = self.basename.clone();
                path.set_extension(self.file_number.to_string());
                self.rotate_state =
                    RotateState::PendingRename(Box::pin(fs::rename(basename, path)));
                self.poll_rotate(cx)
            }
            RotateState::PendingRename(ref mut rename_future) => {
                match rename_future.as_mut().poll(cx) {
                    Poll::Pending => Poll::Pending,

                    // Logic from synchronous side - ignore rename errors
                    // so long as create succeeds, logging continues...
                    Poll::Ready(Err(_)) | Poll::Ready(Ok(())) => {
                        let basename = self.basename.clone();
                        self.rotate_state =
                            RotateState::PendingCreate(Box::pin(File::create(basename)));
                        self.poll_rotate(cx)
                    }
                }
            }
            RotateState::PendingCreate(ref mut create_future) => {
                match create_future.as_mut().poll(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(e)) => {
                        self.rotate_state = RotateState::Done;
                        Poll::Ready(Err(e))
                    }
                    Poll::Ready(Ok(file)) => {
                        self.file = Box::pin(file);
                        self.file_number = (self.file_number + 1) % (self.max_file_number + 1);
                        self.count = 0;
                        self.rotate_state = RotateState::Done;
                        Poll::Ready(Ok(()))
                    }
                }
            }
        }
    }

    fn poll_write_bytes(
        self: &mut Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf_to_write: &mut Vec<u8>,
        bytes: usize,
    ) -> Poll<io::Result<bool>> {
        let (subbuf, used, should_rotate) = if self.count + buf_to_write.len() > bytes {
            // got more to write than allowed?
            let bytes_left = bytes - self.count;
            (&buf_to_write[..bytes_left], bytes_left, true)
        } else {
            (&buf_to_write[..], buf_to_write.len(), false)
        };

        match self.file.as_mut().poll_write(cx, subbuf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(w)) => {
                self.written += w;
                self.count += w;
                buf_to_write.drain(..used);
                Poll::Ready(Ok(should_rotate))
            }
        }
    }

    fn poll_write_bytes_surpassed(
        self: &mut Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf_to_write: &mut Vec<u8>,
        bytes: usize,
    ) -> Poll<io::Result<bool>> {
        match self.file.as_mut().poll_write(cx, buf_to_write) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(w)) => {
                self.written += w;
                self.count += w;
                buf_to_write.clear();
                let should_rotate = self.count > bytes;
                Poll::Ready(Ok(should_rotate))
            }
        }
    }

    fn poll_write_lines(
        self: &mut Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf_to_write: &mut Vec<u8>,
        lines: usize,
    ) -> Poll<io::Result<bool>> {
        let (subbuf, used) = if let Some((idx, _)) = buf_to_write
            .iter()
            .enumerate()
            .find(|(_, byte)| *byte == &b'\n')
        {
            (&buf_to_write[..idx + 1], idx + 1)
        } else {
            (&buf_to_write[..], buf_to_write.len())
        };

        match self.file.as_mut().poll_write(cx, subbuf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(w)) => {
                self.written += w;
                self.count += 1;
                buf_to_write.drain(..used);
                let should_rotate = self.count >= lines;
                Poll::Ready(Ok(should_rotate))
            }
        }
    }
}

impl AsyncWrite for FileRotate {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // are we waiting on a rotation future? Handle it
        match self.rotate_state {
            RotateState::Done => {
                // not rotating
            }
            _ => match self.poll_rotate(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    // rotation just completed
                }
            },
        }

        // Got a buffer to be written?
        if let Some(mut buf_to_write) = self.buf_to_write.take() {
            // Is it done? Finish everything up.
            if buf_to_write.is_empty() {
                self.buf_to_write = None;
                Poll::Ready(Ok(self.written))
            } else {
                let poll_write_result = match self.mode {
                    RotationMode::Bytes(bytes) => {
                        self.poll_write_bytes(cx, &mut buf_to_write, bytes)
                    }
                    RotationMode::Lines(lines) => {
                        self.poll_write_lines(cx, &mut buf_to_write, lines)
                    }
                    RotationMode::BytesSurpassed(bytes) => {
                        self.poll_write_bytes_surpassed(cx, &mut buf_to_write, bytes)
                    }
                };

                match poll_write_result {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Ready(Ok(should_rotate)) => {
                        // hold remaining for next round
                        self.buf_to_write = Some(buf_to_write);

                        if should_rotate {
                            match self.poll_rotate(cx) {
                                Poll::Pending => Poll::Pending,
                                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                                Poll::Ready(Ok(())) => self.poll_write(cx, buf),
                            }
                        } else {
                            self.poll_write(cx, buf)
                        }
                    }
                }
            }
        } else {
            // if no buffer-write in progress, set it up
            self.written = 0;
            // copy the entire buffer...
            self.buf_to_write = Some(Vec::from(buf));
            self.poll_write(cx, buf)
        }
    }

    // pass flush down to the current file
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.file.as_mut().poll_flush(cx)
    }

    // pass shutdown down to the current file
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.file.as_mut().poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn zero_bytes() {
        tokio_test::block_on(async {
            let zerobyteserr =
                FileRotate::new("target/async_zero_bytes", RotationMode::Bytes(0), 0).await;
            if let Err(error::Error::ZeroBytes) = zerobyteserr {
            } else {
                assert!(false, "Expected Error::ZeroBytes");
            };
        })
    }

    #[test]
    fn zero_bytes_surpassed() {
        tokio_test::block_on(async {
            let zerobyteserr = FileRotate::new(
                "target/async_zero_bytes",
                RotationMode::BytesSurpassed(0),
                0,
            )
            .await;
            if let Err(error::Error::ZeroBytes) = zerobyteserr {
            } else {
                assert!(false, "Expected Error::ZeroBytes");
            };
        });
    }

    #[test]
    fn zero_lines() {
        tokio_test::block_on(async {
            let zerolineserr =
                FileRotate::new("target/async_zero_lines", RotationMode::Lines(0), 0).await;
            if let Err(error::Error::ZeroLines) = zerolineserr {
            } else {
                assert!(false, "Expected Error::ZeroLines");
            };
        });
    }

    #[test]
    fn rotate_to_deleted_directory() {
        tokio_test::block_on(async {
            let _ = fs::remove_dir_all("target/async_rotate").await;
            fs::create_dir("target/async_rotate").await.unwrap();

            let mut rot = FileRotate::new("target/async_rotate/log", RotationMode::Lines(1), 0)
                .await
                .unwrap();
            rot.write("a\n".as_bytes()).await.unwrap();
            assert_eq!(
                "",
                fs::read_to_string("target/async_rotate/log").await.unwrap()
            );
            assert_eq!(
                "a\n",
                fs::read_to_string("target/async_rotate/log.0")
                    .await
                    .unwrap()
            );

            fs::remove_dir_all("target/async_rotate").await.unwrap();

            assert!(rot.write("b\n".as_bytes()).await.is_err());

            rot.flush().await.unwrap();
            assert!(fs::read_dir("target/async_rotate").await.is_err());
            fs::create_dir("target/async_rotate").await.unwrap();

            // async write may not have completed
            rot.write("c\n".as_bytes()).await.unwrap();

            // Give it one more character not have completed
            rot.write("d\n".as_bytes()).await.unwrap();
            assert_eq!(
                "",
                fs::read_to_string("target/async_rotate/log").await.unwrap()
            );

            rot.write("e\n".as_bytes()).await.unwrap();
            assert_eq!(
                "",
                fs::read_to_string("target/async_rotate/log").await.unwrap()
            );
            assert_eq!(
                "e\n",
                fs::read_to_string("target/async_rotate/log.0")
                    .await
                    .unwrap()
            );
        });
    }

    #[test]
    fn write_complete_record_until_bytes_surpassed() {
        tokio_test::block_on(async {
            let _ = fs::remove_dir_all("target/surpassed_bytes").await;
            fs::create_dir("target/surpassed_bytes").await.unwrap();

            let mut rot = FileRotate::new(
                "target/surpassed_bytes/log",
                RotationMode::BytesSurpassed(1),
                1,
            )
            .await
            .unwrap();

            rot.write("0123456789".as_bytes()).await.unwrap();
            rot.flush().await.unwrap();
            assert!(Path::new("target/surpassed_bytes/log.0").exists());
            // shouldn't exist yet - because entire record was written in one shot
            assert!(!Path::new("target/surpassed_bytes/log.1").exists());

            // This should create the second file
            rot.write("0123456789".as_bytes()).await.unwrap();
            rot.flush().await.unwrap();
            assert!(Path::new("target/surpassed_bytes/log.1").exists());

            fs::remove_dir_all("target/surpassed_bytes").await.unwrap();
        });
    }

    /*
    #[quickcheck_macros::quickcheck]
    fn arbitrary_lines(count: usize) {
        tokio_test::block_on(async {
            let _ = fs::remove_dir_all("target/arbitrary_lines").await;
            fs::create_dir("target/arbitrary_lines").await.unwrap();

            let count = count.max(1);
            let mut rot =
                FileRotate::new("target/arbitrary_lines/log", RotationMode::Lines(count), 0)
                    .await
                    .unwrap();

            for _ in 0..count - 1 {
                rot.write("\n".as_bytes()).await.unwrap();
            }

            rot.flush().await.unwrap();
            assert!(!Path::new("target/arbitrary_lines/log.0").exists());
            rot.write("\n".as_bytes()).await.unwrap();
            assert!(Path::new("target/arbitrary_lines/log.0").exists());

            fs::remove_dir_all("target/arbitrary_lines").await.unwrap();
        });
    }
    */

    #[quickcheck_macros::quickcheck]
    fn arbitrary_bytes() {
        tokio_test::block_on(async {
            let _ = fs::remove_dir_all("target/async_arbitrary_bytes").await;
            fs::create_dir("target/async_arbitrary_bytes")
                .await
                .unwrap();

            let count = 0.max(1);
            let mut rot = FileRotate::new(
                "target/async_arbitrary_bytes/log",
                RotationMode::Bytes(count),
                0,
            )
            .await
            .unwrap();

            for _ in 0..count {
                rot.write("0".as_bytes()).await.unwrap();
            }

            rot.flush().await.unwrap();
            assert!(!Path::new("target/async_arbitrary_bytes/log.0").exists());
            rot.write("1".as_bytes()).await.unwrap();
            assert!(Path::new("target/async_arbitrary_bytes/log.0").exists());

            fs::remove_dir_all("target/async_arbitrary_bytes")
                .await
                .unwrap();
        });
    }
}
