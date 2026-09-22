"""Bounded, symlink-safe filesystem discovery."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pathspec


def iter_files(root: Path, ignores: pathspec.PathSpec, *, follow_symlinks: bool) -> Iterator[Path]:
    if root.is_file():
        if follow_symlinks or not root.is_symlink():
            yield root
        return
    for current, directories, files in os.walk(root, followlinks=follow_symlinks):
        current_path = Path(current)
        directories[:] = [
            name
            for name in sorted(directories)
            if (follow_symlinks or not (current_path / name).is_symlink())
            and not ignores.match_file((current_path / name).relative_to(root).as_posix() + "/")
        ]
        for name in sorted(files):
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            if ignores.match_file(relative):
                continue
            if path.is_symlink() and not follow_symlinks:
                continue
            yield path
