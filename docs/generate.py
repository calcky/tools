"""Publish tool documentation at its repository-relative path, preserving links."""
from pathlib import Path

import mkdocs_gen_files

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ("irqtop", "netping", "flowgen", "cttop", "netlens")

sources = [ROOT / tool / "README.md" for tool in TOOLS]
sources.extend(ROOT / tool / "RELEASE.md" for tool in TOOLS if (ROOT / tool / "RELEASE.md").is_file())
# netlens has linked reference pages, ADRs and schemas in addition to its README.
sources.extend(path for path in sorted((ROOT / "netlens/docs").rglob("*"))
               if path.is_file() and path.suffix in {".md", ".json"})

for source in sources:
    destination = source.relative_to(ROOT)
    with mkdocs_gen_files.open(destination, "w") as page:
        page.write(source.read_text(encoding="utf-8"))
    if source.suffix == ".md":
        mkdocs_gen_files.set_edit_path(destination, Path("..") / destination)
