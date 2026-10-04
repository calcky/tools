# Repository Instructions

## Tool Documentation

- Keep each overview page to one tool catalog table with columns for tool,
  purpose, and installation source/Release. Each tool appears once; put its
  documentation link and Release link in the same row instead of maintaining
  a separate installation table.
- Sort overview rows and the sidebar's Tools entries by tool name, A-Z,
  case-insensitively. For combined names such as `irqtop / irqstat`, sort by
  the first tool name. Keep the same order in Chinese and English.
- Apply these rules to the current layout when adding or changing a tool.
  Keep each tool's nested pages together and retain their reading order;
  alphabetical sorting applies to the tool entries, not their subpages.
- In usage examples, invoke the installed executable by its tool name (for
  example `netping ...`), without `sudo`, `./`, `bin/`, an absolute path, or an
  architecture suffix. Keep privilege requirements in prose, separate from
  the copyable command.
- Call the setup section "安装" (English: "Installation"), not "下载". Show
  an x86_64 asset URL from the tool's canonical GitHub Release, install it as
  the unsuffixed tool name in a directory on `PATH`, then use only that name
  in subsequent examples. Note other supported architectures in prose.
- Read the Docs tool pages should lead with a brief purpose, then a real
  screenshot when one is available, installation, common usage, option
  reference, and interpretation/limitations as appropriate. Do not include
  build-from-source instructions or build dependencies on Read the Docs;
  development instructions belong in repository developer documentation.
- Keep Chinese and English pages consistent. Do not invent screenshots,
  release assets, supported options, or privilege guarantees.

## Release Policy

- Each tool has one current official release, represented by one canonical tag
  and one GitHub Release.
- Use the tool name in the canonical tag, for example `flowgen-release` or
  `netping-release`; do not create a growing series of tool-specific release
  tags such as `flowgen-v0.1.1`, `flowgen-v0.1.3`, and `flowgen-v0.1.4`.
- A tool's release contains all supported architecture binaries as assets in
  that single GitHub Release. Do not create one Release per architecture.
- Before publishing, update the existing canonical tag and Release to point to
  the new commit and replace their assets. Keep the canonical tag unchanged;
  set the Release title to `<tool> v<version>`, for example `flowgen v0.1.4`.
- Read the program version from the tool's `Cargo.toml` or `VERSION` file.
  Updating a tag does not increment the version; bump the program version
  explicitly before publishing a new version.
- Push canonical tags individually, using an explicit force-with-lease when
  updating an existing tag. GitHub does not trigger Actions when more than
  three tags are pushed together. Verify the tag-triggered publishing run,
  not only the branch build.
- If a second Release was mistakenly created for the same tool, first publish
  and verify the canonical Release, then delete the duplicate Release and its
  noncanonical tag. Do not leave two visible Releases for one tool.
- Otherwise, preserve historical tags and Releases unless the user explicitly
  requests cleanup.
- Verify the release workflow, asset checksums, static linkage, and executable
  version before reporting the release as complete.
