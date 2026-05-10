# df-plugin-ctb

DragonFruit Plugin for the CTB Encoder

## Current status

- Plugin role: **encoder-only** (no network/runtime protocol surface).
- Output target: `.ctb`
- Encoder path: raw raster mask layers from `dragonfruit-slicer-v3` (PNG path disabled).
- Implementation stage: concrete CTB binary serialization enabled (real CTB magic/header, print/slicer tables, layer definitions, CTB RLE packets).

## Legal notice (interoperability)

This plugin includes format-compatibility work for CTB-family resin files to enable interoperability between software ecosystems.

The project is developed in good faith for compatibility use cases, with attention to applicable legal frameworks such as:

- EU Directive 2009/24/EC (interoperability-related reverse engineering allowances)
- DMCA Section 1201(f) (United States interoperability exemption)
- Fair Use / Fair Dealing doctrines where applicable

The implementation follows clean-room style engineering practices for independent behavior verification and format compatibility.

Users are responsible for ensuring their use complies with applicable law in their jurisdiction.

**Disclaimer:** This section is general information only and does not constitute legal advice. For jurisdiction-specific guidance, consult qualified legal counsel.
