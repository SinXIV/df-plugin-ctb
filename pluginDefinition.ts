import type {
  ComplexPluginDefinition,
  PluginLocalMaterialSettingsAdapterContract,
} from '@/features/plugins/complexPluginContracts';
import { CTB_PLUGIN_MANIFEST } from './pluginManifest';
import { CTB_FORMAT_DEFINITION } from './slicing/ctbFormatDefinition';
import ctbSimpleMaterialSettings from './materialSettings/settings_simple.json';
import ctbTwostageMaterialSettings from './materialSettings/settings_twostage.json';

type CtbModeSettingsSchema = Omit<PluginLocalMaterialSettingsAdapterContract, 'outputFormat'>;

function createCtbModeSettingsAdapter(schema: CtbModeSettingsSchema): PluginLocalMaterialSettingsAdapterContract {
  return {
    outputFormat: CTB_FORMAT_DEFINITION.outputFormat,
    ...schema,
  };
}

const CTB_LOCAL_MATERIAL_SETTINGS_SIMPLE_ADAPTER = createCtbModeSettingsAdapter(
  ctbSimpleMaterialSettings as CtbModeSettingsSchema,
);

const CTB_LOCAL_MATERIAL_SETTINGS_TWOSTAGE_ADAPTER = createCtbModeSettingsAdapter(
  ctbTwostageMaterialSettings as CtbModeSettingsSchema,
);

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
  localMaterialSettingsByOutput: {
    [CTB_FORMAT_DEFINITION.outputFormat]: CTB_LOCAL_MATERIAL_SETTINGS_SIMPLE_ADAPTER,
  },
  localMaterialSettingsByOutputAndMode: {
    [CTB_FORMAT_DEFINITION.outputFormat]: {
      simple: CTB_LOCAL_MATERIAL_SETTINGS_SIMPLE_ADAPTER,
      twostage: CTB_LOCAL_MATERIAL_SETTINGS_TWOSTAGE_ADAPTER,
    },
  },
};

export default CTB_COMPLEX_PLUGIN_DEFINITION;
