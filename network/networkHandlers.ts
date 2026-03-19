import type { PluginNetworkOperationHandlerContract } from '@/features/plugins/complexPluginContracts';

export const handleCtbNetworkOperation: PluginNetworkOperationHandlerContract = async (operationPath) => {
  const operation = operationPath.join('/');
  return {
    status: 501,
    body: {
      ok: false,
      error: `CTB network operation not implemented yet: ${operation || '(empty operation)'}`,
    },
  };
};

export const handlePluginNetworkOperation = handleCtbNetworkOperation;
