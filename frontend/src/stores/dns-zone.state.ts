import { defineStore } from 'pinia';

import {
  ZoneService,
  type Zone,
  type ZoneKind,
  type ListZonesResponse,
  type GetZoneResponse,
  type CreateZoneResponse,
  type UpdateZoneResponse,
  type ExportZoneResponse,
} from '../api/services';

type Paging = { page?: number; pageSize?: number } | undefined;

export const useDnsZoneStore = defineStore('dns-zone', () => {
  async function listZones(
    paging?: Paging,
    formValues?: {
      search?: string;
      kind?: ZoneKind;
    } | null,
  ): Promise<ListZonesResponse> {
    return await ZoneService.list({
      search: formValues?.search,
      kind: formValues?.kind,
      page: paging?.page,
      pageSize: paging?.pageSize,
    });
  }

  async function getZone(id: string): Promise<GetZoneResponse> {
    return await ZoneService.get(id);
  }

  async function createZone(data: {
    name: string;
    kind: ZoneKind;
    nameservers?: string[];
    masters?: string;
    description?: string;
    templateId?: string;
    dnssecEnabled?: boolean;
  }): Promise<CreateZoneResponse> {
    return await ZoneService.create(data);
  }

  async function updateZone(
    id: string,
    data: Partial<Zone>,
  ): Promise<UpdateZoneResponse> {
    return await ZoneService.update(id, {
      id,
      kind: data.kind,
      masters: data.masters,
      description: data.description,
      dnssecEnabled: data.dnssecEnabled,
    });
  }

  async function deleteZone(id: string): Promise<void> {
    return await ZoneService.delete(id);
  }

  async function exportZone(id: string): Promise<ExportZoneResponse> {
    return await ZoneService.export(id);
  }

  async function notifyZone(id: string): Promise<void> {
    return await ZoneService.notify(id);
  }

  function $reset() {}

  return {
    $reset,
    listZones,
    getZone,
    createZone,
    updateZone,
    deleteZone,
    exportZone,
    notifyZone,
  };
});
