use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    path::{Component, Path},
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) fn now() -> Result<u64, String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "The system clock is unavailable.")?
        .as_millis() as u64)
}
pub(crate) fn reparse(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}
pub(crate) fn directory(path: &Path, create: bool) -> Result<(), String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(
            "An absolute local storage directory without parent traversal is required.".into(),
        );
    }
    for part in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        match fs::symlink_metadata(part) {
            Ok(metadata) if metadata.is_dir() && !reparse(&metadata) => {}
            Ok(_) => {
                return Err(
                    "Storage directories must not be files, links or reparse points.".into(),
                )
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && create => {
                fs::create_dir(part).map_err(|e| format!("Cannot create local storage: {e}"))?;
                let metadata = fs::symlink_metadata(part).map_err(|e| e.to_string())?;
                if !metadata.is_dir() || reparse(&metadata) {
                    return Err("The storage directory changed while opening it.".into());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(format!("Cannot inspect local storage: {e}")),
        }
    }
    Ok(())
}
pub(crate) fn read_file(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    directory(path.parent().ok_or("Missing storage parent.")?, false)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000);
    }
    let file = options
        .open(path)
        .map_err(|e| format!("Cannot read local data: {e}"))?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() || reparse(&metadata) || metadata.len() > limit {
        return Err("The local data file is linked, unsupported or oversized.".into());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("The local data file exceeds its size limit.".into());
    }
    Ok(bytes)
}
pub(crate) fn create_file(path: &Path, exclusive: bool) -> Result<File, String> {
    directory(path.parent().ok_or("Missing storage parent.")?, true)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        if exclusive {
            options.share_mode(1);
        }
        options.custom_flags(0x00200000);
    }
    #[cfg(not(windows))]
    let _ = exclusive;
    options
        .open(path)
        .map_err(|e| format!("Cannot create local data: {e}"))
}
pub(crate) fn canonical_id(id: &str) -> Result<(), String> {
    if uuid::Uuid::parse_str(id)
        .map_err(|_| "Invalid local record identifier.")?
        .to_string()
        != id
    {
        return Err("A canonical local record identifier is required.".into());
    }
    Ok(())
}
