import type {
  ComplexPluginDefinition,
  PluginMonitoringSnapshotContract,
  PluginMonitoringWebcamInfoContract,
  PluginMonitoringUiAdapterContract,
  PluginNetworkUiAdapterContract,
} from '@/features/plugins/complexPluginContracts';
import { CTB_PLUGIN_MANIFEST } from './pluginManifest';
import { CTB_FORMAT_DEFINITION } from './slicing/ctbFormatDefinition';

const passthroughMetaDraft = (meta: Record<string, unknown>): Record<string, string> => {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(meta)) {
    if (value == null) continue;
    out[key] = String(value);
  }
  return out;
};

const passthroughDraftForBackend = (draft: Record<string, string>): Record<string, string> => ({ ...draft });

const CTB_NETWORK_ADAPTER: PluginNetworkUiAdapterContract = {
  mode: 'ctb',
  pluginId: 'ctb',
  displayName: 'CTB Network',
  operationNamespace: 'ctb',
  operations: {
    connect: 'ctb/connect',
    discover: 'ctb/discover',
    materials: 'ctb/materials',
    materialsEdit: 'ctb/materials/edit',
  },
  defaultLocalHostnames: ['ctb.local', 'printer.local'],
  primaryEditFields: [],
  basicSections: [],
  advancedSections: [],
  resolveEditDraftFromMeta: passthroughMetaDraft,
  resolveMaterialProcessValues: () => ({}),
  denormalizeEditDraftForBackend: passthroughDraftForBackend,
  resolveAdvancedSectionId: () => 'ctb-default',
  getFieldHelpText: () => 'No additional help available yet for CTB network fields.',
  isDynamicWaitEnabled: () => false,
};

const CTB_MONITORING_ADAPTER: PluginMonitoringUiAdapterContract = {
  mode: 'ctb',
  pluginId: 'ctb',
  displayName: 'CTB Monitoring',
  available: true,
  operations: {
    status: 'ctb/printer/status',
    webcamInfo: 'ctb/printer/webcam/info',
    platesList: 'ctb/plates/list',
    start: 'ctb/printer/start',
    deletePlate: 'ctb/plate/delete',
    pause: 'ctb/printer/pause',
    resume: 'ctb/printer/resume',
    cancel: 'ctb/printer/cancel',
    emergencyStop: 'ctb/printer/emergency-stop',
  },
  parseStatusPayload: (payload: unknown): PluginMonitoringSnapshotContract => {
    const body = (payload ?? {}) as Record<string, unknown>;
    return {
      connected: Boolean(body.connected ?? false),
      stateText: typeof body.stateText === 'string' ? body.stateText : 'unknown',
      isPrinting: Boolean(body.isPrinting ?? false),
      isPaused: Boolean(body.isPaused ?? false),
      cancelLatched: Boolean(body.cancelLatched ?? false),
      pauseLatched: Boolean(body.pauseLatched ?? false),
      finished: Boolean(body.finished ?? false),
      progressPct: typeof body.progressPct === 'number' ? body.progressPct : null,
      currentLayer: typeof body.currentLayer === 'number' ? body.currentLayer : null,
      totalLayers: typeof body.totalLayers === 'number' ? body.totalLayers : null,
      plateId: typeof body.plateId === 'number' ? body.plateId : null,
      jobName: typeof body.jobName === 'string' ? body.jobName : null,
      etaSec: typeof body.etaSec === 'number' ? body.etaSec : null,
    };
  },
  parseWebcamInfoPayload: (payload: unknown): PluginMonitoringWebcamInfoContract => {
    const body = (payload ?? {}) as Record<string, unknown>;
    return {
      available: Boolean(body.available ?? false),
      streamUrl: typeof body.streamUrl === 'string' ? body.streamUrl : null,
      snapshotUrl: typeof body.snapshotUrl === 'string' ? body.snapshotUrl : null,
      message: typeof body.message === 'string' ? body.message : 'No webcam data available',
    };
  },
};

export const CTB_COMPLEX_PLUGIN_DEFINITION: ComplexPluginDefinition = {
  id: 'ctb',
  manifest: CTB_PLUGIN_MANIFEST,
  capabilities: {
    networkOperations: true,
    uploadWithProgress: true,
    slicerEncoder: true,
    tauriRuntimePlugin: true,
  },
  networkAdaptersByMode: {
    [CTB_NETWORK_ADAPTER.mode]: CTB_NETWORK_ADAPTER,
  },
  monitoringAdaptersByMode: {
    [CTB_MONITORING_ADAPTER.mode]: CTB_MONITORING_ADAPTER,
  },
  slicingFormatsByOutput: {
    [CTB_FORMAT_DEFINITION.outputFormat]: CTB_FORMAT_DEFINITION,
  },
};

export default CTB_COMPLEX_PLUGIN_DEFINITION;
