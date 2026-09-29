"""Keep relative language links and shared screenshots available in every locale."""

from pathlib import Path

from mkdocs.plugins import event_priority
from mkdocs.structure.files import File


@event_priority(-110)
def on_files(files, *, config):
    # i18n's disabled text fallback also excludes unlocalized assets in English.
    docs = Path(config.docs_dir)
    for path in sorted((docs / "assets/screenshots").glob("*.png")):
        source = path.relative_to(docs).as_posix()
        if source not in files.src_uris:
            files.append(File(source, config.docs_dir, config.site_dir, config.use_directory_urls))
    return files


@event_priority(-100)
def on_page_context(context, *, page, config, nav):
    # i18n leaves homepage links absolute; counterparts retain RTD version paths.
    for alternate in config.extra.alternate:
        counterpart = page.file.alternates.get(alternate["lang"])
        if counterpart is not None:
            alternate["link"] = counterpart.url or "."
    return context
