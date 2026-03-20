import type { SlicingFormatDefinition } from '@/features/slicing/formats/types';

export const CTB_FORMAT_DEFINITION: SlicingFormatDefinition = {
  id: 'ctb.ctb.v1',
  outputFormat: '.ctb',
  displayName: 'CTB',
  ownership: 'plugin',
  layerDataKind: 'raw-mask',
  pluginId: 'ctb',
  formatVersions: [
    { value: 'v2v3', label: 'V2/V3' },
    { value: 'v4v5', label: 'V4/V5', isDefault: true },
    { value: 'v5enc', label: 'V5 ENC' },
  ],
  rustModulePath: 'formats::ctb',
  wasmExportName: 'encode_ctb_container',
  notes: 'CTB binary encoder using raw raster mask layers in dragonfruit-slicer-v3.',
};
