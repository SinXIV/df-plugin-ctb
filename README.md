# df-plugin-ctb

DragonFruit Plugin for the CTB Encoder

## Current status

- Plugin role: **encoder-only** (no network/runtime protocol surface).
- Output target: `.ctb`
- Encoder path: raw raster mask layers from `dragonfruit-slicer-v3` (PNG path disabled).
- Implementation stage: concrete CTB binary serialization enabled (real CTB magic/header, print/slicer tables, layer definitions, CTB RLE packets).

## Clean-room policy

This plugin is implemented using clean-room methods. External tools/spec references may inform behavior, but no GPL code is copied.
