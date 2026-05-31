import { defineStore } from 'pinia';

import {
  ConfigService,
  type GetDnsConfigResponse,
  type UpdateDnsConfigRequest,
  type UpdateDnsConfigResponse,
} from '../api/services';

export const useDnsConfigStore = defineStore('dns-config', () => {
  async function getConfig(): Promise<GetDnsConfigResponse> {
    return await ConfigService.get();
  }

  async function updateConfig(
    data: UpdateDnsConfigRequest,
  ): Promise<UpdateDnsConfigResponse> {
    return await ConfigService.update(data);
  }

  function $reset() {}

  return {
    $reset,
    getConfig,
    updateConfig,
  };
});
