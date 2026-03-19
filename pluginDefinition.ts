import type { ComplexPluginDefinition } from '@/features/plugins/complexPluginContracts';
import { CTB_PLUGIN_MANIFEST } from './pluginManifest';
import { CTB_FORMAT_DEFINITION } from './slicing/ctbFormatDefinition';

export const CTB_COMPLEX_PLUGIN_DEFINITION: ComplexPluginDefinition = {
  id: 'ctb',
  manifest: CTB_PLUGIN_MANIFEST,
  capabilities: {
    networkOperations: false,
    uploadWithProgress: false,
    slicerEncoder: true,
    tauriRuntimePlugin: false,
  },
  slicingFormatsByOutput: {
    [CTB_FORMAT_DEFINITION.outputFormat]: CTB_FORMAT_DEFINITION,
  },
};

export default CTB_COMPLEX_PLUGIN_DEFINITION;
