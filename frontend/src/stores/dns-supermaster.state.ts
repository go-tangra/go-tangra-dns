import { defineStore } from 'pinia';

import {
  SupermasterService,
  type ListSupermastersResponse,
  type GetSupermasterResponse,
  type CreateSupermasterResponse,
} from '../api/services';

type Paging = { page?: number; pageSize?: number } | undefined;

export const useDnsSupermasterStore = defineStore('dns-supermaster', () => {
  async function listSupermasters(paging?: Paging): Promise<ListSupermastersResponse> {
    return await SupermasterService.list({
      page: paging?.page,
      pageSize: paging?.pageSize,
    });
  }

  async function getSupermaster(id: string): Promise<GetSupermasterResponse> {
    return await SupermasterService.get(id);
  }

  async function createSupermaster(data: {
    ip: string;
    nameserver: string;
    account?: string;
  }): Promise<CreateSupermasterResponse> {
    return await SupermasterService.create(data);
  }

  async function deleteSupermaster(id: string): Promise<void> {
    return await SupermasterService.delete(id);
  }

  function $reset() {}

  return {
    $reset,
    listSupermasters,
    getSupermaster,
    createSupermaster,
    deleteSupermaster,
  };
});
