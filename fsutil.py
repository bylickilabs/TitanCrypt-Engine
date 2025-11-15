from pathlib import Path
from dataclasses import dataclass
from typing import List

@dataclass
class FileEntry:
    rel_path: str
    abs_path: Path
    size: int
    mtime: float

def collect_entries(root: Path) -> List[FileEntry]:
    root = root.resolve()
    entries: List[FileEntry] = []

    if not root.exists():
        return entries

    if root.is_file():
        stat = root.stat()
        entries.append(
            FileEntry(
                rel_path=root.name,
                abs_path=root,
                size=stat.st_size,
                mtime=stat.st_mtime,
            )
        )
        return entries

    for p in root.rglob("*"):
        if p.is_file():
            stat = p.stat()
            entries.append(
                FileEntry(
                    rel_path=str(p.relative_to(root)),
                    abs_path=p,
                    size=stat.st_size,
                    mtime=stat.st_mtime,
                )
            )
    return entries