import type { SlicingFormatDefinition } from '@/features/slicing/formats/types';

export const CTB_FORMAT_DEFINITION: SlicingFormatDefinition = {
  id: 'ctb.ctb.v1',
  outputFormat: '.ctb',
  displayName: 'CTB',
  ownership: 'plugin',
  pluginId: 'ctb',
  rustModulePath: 'formats::ctb',
  wasmExportName: 'encode_ctb_container',
  notes: 'CTB encoder using raw raster mask layers in dragonfruit-slicer-v3.',
};
