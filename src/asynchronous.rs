use core::pin::Pin;
use futures::task::{Context, Poll};
use std::path::{Path, PathBuf};
use tokio::{
    fs::{self, File},
    io::{self, AsyncWrite},
};

// ---

type Result<T> = std::result::Result<T, error::Error>;

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
    file: Option<File>,
    file_number: usize,
    max_file_number: usize,
    mode: RotationMode,
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
        };

        Self {
            basename: path.as_ref().to_path_buf(),
            count: 0,
            file: match File::create(&path) {
                Ok(file) => Some(file),
                Err(_) => None,
            }
            .await,
            file_number: 0,
            max_file_number,
            mode: rotation_mode,
        }
    }

    async fn rotate(&mut self) -> io::Result<()> {
        let mut path = self.basename.clone();
        path.set_extension(self.file_number.to_string());

        let _ = self.file.take();

        let _ = fs::rename(&self.basename, path);
        self.file = Some(File::create(&self.basename).await?);

        self.file_number = (self.file_number + 1) % (self.max_file_number + 1);
        self.count = 0;

        Ok(())
    }
}

impl AsyncWrite for FileRotate {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let written = buf.len();
        match self.mode {
            RotationMode::Bytes(bytes) => {
                while self.count + buf.len() > bytes {
                    let bytes_left = bytes - self.count;
                    if let Some(Err(err)) = self
                        .file
                        .as_mut()
                        .map(|file| file.write(&buf[..bytes_left]))
                    {
                        return Err(err);
                    }
                    self.rotate()?;
                    buf = &buf[bytes_left..];
                }
                self.count += buf.len();
                if let Some(Err(err)) = self.file.as_mut().map(|file| file.write(&buf[..])) {
                    return Err(err);
                }
            }
            RotationMode::Lines(lines) => {
                while let Some((idx, _)) = buf.iter().enumerate().find(|(_, byte)| *byte == &b'\n')
                {
                    if let Some(Err(err)) =
                        self.file.as_mut().map(|file| file.write(&buf[..idx + 1]))
                    {
                        return Err(err);
                    }
                    self.count += 1;
                    buf = &buf[idx + 1..];
                    if self.count >= lines {
                        self.rotate()?;
                    }
                }
                if let Some(Err(err)) = self.file.as_mut().map(|file| file.write(buf)) {
                    return Err(err);
                }
            }
            RotationMode::BytesSurpassed(bytes) => {
                if let Some(Err(err)) = self.file.as_mut().map(|file| file.write(&buf)) {
                    return Err(err);
                }
                self.count += buf.len();
                if self.count > bytes {
                    self.rotate()?
                }
            }
        }
        Ok(written)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(Err(err)) = self.file.as_mut().map(|file| file.flush()) {
            Err(err)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "assertion failed: bytes > 0")]
    fn zero_bytes() {
        let mut rot = FileRotate::new("target/zero_bytes", RotationMode::Bytes(0), 0);
        writeln!(rot, "Zero").unwrap();
        assert_eq!("\n", fs::read_to_string("target/zero_bytes").unwrap());
        assert_eq!("o", fs::read_to_string("target/zero_bytes.0").unwrap());
    }

    #[test]
    #[should_panic(expected = "assertion failed: lines > 0")]
    fn zero_lines() {
        let mut rot = FileRotate::new("target/zero_lines", RotationMode::Lines(0), 0);
        write!(rot, "a\nb\nc\nd\n").unwrap();
        assert_eq!("", fs::read_to_string("target/zero_lines").unwrap());
        assert_eq!("d\n", fs::read_to_string("target/zero_lines.0").unwrap());
    }

    #[test]
    fn rotate_to_deleted_directory() {
        let _ = fs::remove_dir_all("target/rotate");
        fs::create_dir("target/rotate").unwrap();

        let mut rot = FileRotate::new("target/rotate/log", RotationMode::Lines(1), 0);
        writeln!(rot, "a").unwrap();
        assert_eq!("", fs::read_to_string("target/rotate/log").unwrap());
        assert_eq!("a\n", fs::read_to_string("target/rotate/log.0").unwrap());

        fs::remove_dir_all("target/rotate").unwrap();

        assert!(writeln!(rot, "b").is_err());

        rot.flush().unwrap();
        assert!(fs::read_dir("target/rotate").is_err());
        fs::create_dir("target/rotate").unwrap();

        writeln!(rot, "c").unwrap();
        assert_eq!("", fs::read_to_string("target/rotate/log").unwrap());

        writeln!(rot, "d").unwrap();
        assert_eq!("", fs::read_to_string("target/rotate/log").unwrap());
        assert_eq!("d\n", fs::read_to_string("target/rotate/log.0").unwrap());
    }

    #[test]
    fn write_complete_record_until_bytes_surpassed() {
        let _ = fs::remove_dir_all("target/surpassed_bytes");
        fs::create_dir("target/surpassed_bytes").unwrap();

        let mut rot = FileRotate::new(
            "target/surpassed_bytes/log",
            RotationMode::BytesSurpassed(1),
            1,
        );

        write!(rot, "0123456789").unwrap();
        rot.flush().unwrap();
        assert!(Path::new("target/surpassed_bytes/log.0").exists());
        // shouldn't exist yet - because entire record was written in one shot
        assert!(!Path::new("target/surpassed_bytes/log.1").exists());

        // This should create the second file
        write!(rot, "0123456789").unwrap();
        rot.flush().unwrap();
        assert!(Path::new("target/surpassed_bytes/log.1").exists());

        fs::remove_dir_all("target/surpassed_bytes").unwrap();
    }

    #[quickcheck_macros::quickcheck]
    fn arbitrary_lines(count: usize) {
        let _ = fs::remove_dir_all("target/arbitrary_lines");
        fs::create_dir("target/arbitrary_lines").unwrap();

        let count = count.max(1);
        let mut rot = FileRotate::new("target/arbitrary_lines/log", RotationMode::Lines(count), 0);

        for _ in 0..count - 1 {
            writeln!(rot).unwrap();
        }

        rot.flush().unwrap();
        assert!(!Path::new("target/arbitrary_lines/log.0").exists());
        writeln!(rot).unwrap();
        assert!(Path::new("target/arbitrary_lines/log.0").exists());

        fs::remove_dir_all("target/arbitrary_lines").unwrap();
    }

    #[quickcheck_macros::quickcheck]
    fn arbitrary_bytes() {
        let _ = fs::remove_dir_all("target/arbitrary_bytes");
        fs::create_dir("target/arbitrary_bytes").unwrap();

        let count = 0.max(1);
        let mut rot = FileRotate::new("target/arbitrary_bytes/log", RotationMode::Bytes(count), 0);

        for _ in 0..count {
            write!(rot, "0").unwrap();
        }

        rot.flush().unwrap();
        assert!(!Path::new("target/arbitrary_bytes/log.0").exists());
        write!(rot, "1").unwrap();
        assert!(Path::new("target/arbitrary_bytes/log.0").exists());

        fs::remove_dir_all("target/arbitrary_bytes").unwrap();
    }
}
