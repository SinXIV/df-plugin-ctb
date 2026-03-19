import type { PluginUploadHandler } from '@/features/plugins/pluginUploadBridge';

export const uploadPrintJobWithProgress: PluginUploadHandler = async ({ callbacks }) => {
  const message = 'CTB upload bridge is not implemented yet.';
  callbacks.onStatusUpdate({
    stage: 'error',
    message,
    error: message,
  });
  callbacks.onError?.(message);

  return {
    ok: false,
    plateId: null,
  };
};
