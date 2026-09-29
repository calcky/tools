# Repository Instructions

## Release Policy

- Each tool has one current official release, represented by one canonical tag
  and one GitHub Release.
- Use the tool name in the canonical tag, for example `flowgen-release` or
  `netping-release`; do not create a growing series of tool-specific release
  tags such as `flowgen-v0.1.1`, `flowgen-v0.1.3`, and `flowgen-v0.1.4`.
- A tool's release contains all supported architecture binaries as assets in
  that single GitHub Release. Do not create one Release per architecture.
- Before publishing, update the existing canonical tag and Release to point to
  the new commit and replace their assets. Keep the tag and Release names
  identical for the tool.
- Existing historical tags and Releases are preserved unless the user
  explicitly requests cleanup; this policy applies to future releases.
- Verify the release workflow, asset checksums, static linkage, and executable
  version before reporting the release as complete.
