//! Bounded, fail-closed reads for persistence inputs.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// Open `path` without following its final symlink and require a regular file.
#[cfg(unix)]
pub(crate) fn open_regular_nofollow(path: &Path) -> io::Result<File> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )?;
    require_regular(File::from(fd))
}

#[cfg(windows)]
pub(crate) fn open_regular_nofollow(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    // Open the reparse point itself so the metadata check below rejects it.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    require_regular(file)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn open_regular_nofollow(_path: &Path) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "secure no-follow persistence reads are unavailable on this platform",
    ))
}

fn require_regular(file: File) -> io::Result<File> {
    if !file.metadata()?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing non-regular persistence input",
        ));
    }
    Ok(file)
}

/// Read at most `limit + 1` bytes, rejecting oversize inputs before parsing.
pub(crate) fn read_regular_bounded(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let file = open_regular_nofollow(path)?;
    let metadata_len = file.metadata()?.len();
    if metadata_len > limit as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("persistence input exceeds {limit} byte limit"),
        ));
    }

    let read_limit = limit
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "persistence limit overflow"))?;
    let mut data = Vec::with_capacity((metadata_len as usize).min(limit));
    file.take(read_limit as u64).read_to_end(&mut data)?;
    if data.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("persistence input exceeds {limit} byte limit"),
        ));
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ccos_bounded_file_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn accepts_limit_and_rejects_limit_plus_one() {
        let path = temp_path("limit");
        File::create(&path).unwrap().write_all(b"12345678").unwrap();
        assert_eq!(read_regular_bounded(&path, 8).unwrap(), b"12345678");
        File::create(&path)
            .unwrap()
            .write_all(b"123456789")
            .unwrap();
        let error = read_regular_bounded(&path, 8).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        std::fs::remove_file(path).ok();
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn rejects_symlink_inputs() {
        let target = temp_path("target");
        let link = temp_path("link");
        File::create(&target).unwrap().write_all(b"{}").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&target, &link).unwrap();

        assert!(read_regular_bounded(&link, 8).is_err());
        std::fs::remove_file(link).ok();
        std::fs::remove_file(target).ok();
    }

    #[test]
    fn rejects_directories() {
        let path = temp_path("directory");
        std::fs::create_dir(&path).unwrap();
        assert!(read_regular_bounded(&path, 8).is_err());
        std::fs::remove_dir(path).ok();
    }
}
