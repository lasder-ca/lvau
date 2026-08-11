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


for manifest in ["crates/lvau-gui/Cargo.toml", "crates/lvau-stub/Cargo.toml"]:
    replace_once(manifest, 'eframe = "0.29.1"', 'eframe = "0.33.3"')

replace_once("crates/lvau-gui/Cargo.toml", 'egui = "0.29.1"', 'egui = "0.33.3"')

# Remove the temporary RustSec exceptions only after moving the GUI dependency
# family to a release line that can resolve quick-xml >= 0.41.
audit = ROOT / ".cargo/audit.toml"
text = audit.read_text(encoding="utf-8")
old = '''[advisories]\n# quick-xml is present only through GUI platform/build dependencies\n# (zbus_xml/Wayland scanners); Lvau does not expose an XML parser to capsule\n# input. Upstream pins currently prevent quick-xml >=0.41.0. Review or remove\n# these exceptions by 2026-10-15, and immediately if an XML input path is added.\nignore = ["RUSTSEC-2026-0194", "RUSTSEC-2026-0195"]\n\n'''
if text.count(old) != 1:
    raise SystemExit(".cargo/audit.toml: expected quick-xml exception block exactly once")
audit.write_text(text.replace(old, "[advisories]\n\n", 1), encoding="utf-8")
