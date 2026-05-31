/**
 * API client for dns module
 *
 * This client uses the dynamic module routing:
 *   /admin/v1/modules/dns/v1/...
 */

import { useAccessStore } from 'shell/vben/stores';

const MODULE_BASE_URL = '/admin/v1/modules/dns/v1';

export interface RequestOptions {
  headers?: Record<string, string>;
  signal?: AbortSignal;
}

function getAuthHeaders(): Record<string, string> {
  const accessStore = useAccessStore();
  const token = accessStore.accessToken;
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  options?: RequestOptions
): Promise<T> {
  const url = `${MODULE_BASE_URL}${path}`;

  const response = await fetch(url, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...getAuthHeaders(),
      ...options?.headers,
    },
    body: body ? JSON.stringify(body) : undefined,
    signal: options?.signal,
  });

  if (!response.ok) {
    let message = `HTTP error! status: ${response.status}`;
    try {
      const errorBody = await response.json();
      if (errorBody?.message) {
        message = errorBody.message;
      }
    } catch { /* response body not JSON, use default message */ }
    throw new Error(message);
  }

  // Some endpoints (DELETE, NOTIFY) return an empty body.
  const text = await response.text();
  return (text ? JSON.parse(text) : ({} as T)) as T;
}

export const dnsApi = {
  get: <T>(path: string, options?: RequestOptions) =>
    request<T>('GET', path, undefined, options),

  post: <T>(path: string, body?: unknown, options?: RequestOptions) =>
    request<T>('POST', path, body, options),

  put: <T>(path: string, body?: unknown, options?: RequestOptions) =>
    request<T>('PUT', path, body, options),

  patch: <T>(path: string, body?: unknown, options?: RequestOptions) =>
    request<T>('PATCH', path, body, options),

  delete: <T>(path: string, options?: RequestOptions) =>
    request<T>('DELETE', path, undefined, options),
};

export default dnsApi;
