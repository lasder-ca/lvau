#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one anchor, found {count}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


# Apply owner-only Windows ACL to the empty temporary file before any secret
# bytes are written. The ACL then follows the file through the atomic rename.
replace_once(
    "crates/lvau-core/src/crypto/keys.rs",
    """    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if private { 0o600 } else { 0o644 };
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(mode))?;
    }

    temp.write_all(contents.as_bytes())?;""",
    """    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if private { 0o600 } else { 0o644 };
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(mode))?;
    }

    #[cfg(windows)]
    if private {
        set_windows_acl(temp.path())?;
    }

    temp.write_all(contents.as_bytes())?;""",
)
replace_once(
    "crates/lvau-core/src/crypto/keys.rs",
    """    #[cfg(windows)]
    if private {
        set_windows_acl(path)?;
    }

    #[cfg(unix)]""",
    """    #[cfg(unix)]""",
)

for path in ["crates/lvau-core/src/signing.rs", "crates/lvau-core/src/recovery.rs"]:
    replace_once(
        path,
        """    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o600))?;
    }

    temp.write_all(bytes)?;""",
        """    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o600))?;
    }

    #[cfg(windows)]
    crate::crypto::keys::set_windows_acl(temp.path())?;

    temp.write_all(bytes)?;""",
    )
    replace_once(
        path,
        """    #[cfg(windows)]
    crate::crypto::keys::set_windows_acl(path)?;

    #[cfg(unix)]""",
        """    #[cfg(unix)]""",
    )
