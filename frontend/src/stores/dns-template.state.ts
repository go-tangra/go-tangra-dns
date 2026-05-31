import { defineStore } from 'pinia';

import {
  ZoneTemplateService,
  type TemplateRecord,
  type ListZoneTemplatesResponse,
  type GetZoneTemplateResponse,
  type CreateZoneTemplateResponse,
  type UpdateZoneTemplateResponse,
} from '../api/services';

type Paging = { page?: number; pageSize?: number } | undefined;

export const useDnsTemplateStore = defineStore('dns-template', () => {
  async function listTemplates(paging?: Paging): Promise<ListZoneTemplatesResponse> {
    return await ZoneTemplateService.list({
      page: paging?.page,
      pageSize: paging?.pageSize,
    });
  }

  async function getTemplate(id: string): Promise<GetZoneTemplateResponse> {
    return await ZoneTemplateService.get(id);
  }

  async function createTemplate(data: {
    name: string;
    description?: string;
    records?: TemplateRecord[];
  }): Promise<CreateZoneTemplateResponse> {
    return await ZoneTemplateService.create(data);
  }

  async function updateTemplate(
    id: string,
    data: {
      name?: string;
      description?: string;
      records?: TemplateRecord[];
    },
  ): Promise<UpdateZoneTemplateResponse> {
    return await ZoneTemplateService.update(id, { id, ...data });
  }

  async function deleteTemplate(id: string): Promise<void> {
    return await ZoneTemplateService.delete(id);
  }

  function $reset() {}

  return {
    $reset,
    listTemplates,
    getTemplate,
    createTemplate,
    updateTemplate,
    deleteTemplate,
  };
});
