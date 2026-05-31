import { defineStore } from 'pinia';

import {
  RecordService,
  type RecordType,
  type RecordContent,
  type ListRecordsResponse,
  type CreateRecordResponse,
  type UpdateRecordResponse,
} from '../api/services';

export const useDnsRecordStore = defineStore('dns-record', () => {
  async function listRecords(
    zoneId: string,
    formValues?: {
      type?: RecordType;
      search?: string;
    } | null,
  ): Promise<ListRecordsResponse> {
    return await RecordService.list(zoneId, {
      type: formValues?.type,
      search: formValues?.search,
    });
  }

  async function createRecord(
    zoneId: string,
    data: {
      name: string;
      type: RecordType;
      ttl?: number;
      contents?: RecordContent[];
      comment?: string;
    },
  ): Promise<CreateRecordResponse> {
    return await RecordService.create(zoneId, data);
  }

  async function updateRecord(
    zoneId: string,
    name: string,
    type: string,
    data: {
      ttl?: number;
      contents?: RecordContent[];
      comment?: string;
    },
  ): Promise<UpdateRecordResponse> {
    return await RecordService.update(zoneId, name, type, data);
  }

  async function deleteRecord(
    zoneId: string,
    name: string,
    type: string,
  ): Promise<void> {
    return await RecordService.delete(zoneId, name, type);
  }

  function $reset() {}

  return {
    $reset,
    listRecords,
    createRecord,
    updateRecord,
    deleteRecord,
  };
});
