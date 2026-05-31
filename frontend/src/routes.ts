import type { RouteRecordRaw } from 'vue-router';

const routes: RouteRecordRaw[] = [
  {
    path: '/dns',
    name: 'DNS',
    component: () => import('shell/app-layout'),
    redirect: '/dns/dashboard',
    meta: {
      order: 2030,
      icon: 'lucide:globe',
      title: 'dns.menu.moduleName',
      keepAlive: true,
      authority: ['platform:admin', 'tenant:manager'],
    },
    children: [
      {
        path: 'dashboard',
        name: 'DnsDashboard',
        meta: {
          icon: 'lucide:layout-dashboard',
          title: 'dns.menu.dashboard',
          authority: ['platform:admin', 'tenant:manager'],
        },
        component: () => import('./views/dashboard/index.vue'),
      },
      {
        path: 'zones',
        name: 'DnsZones',
        meta: {
          icon: 'lucide:globe',
          title: 'dns.menu.zones',
          authority: ['platform:admin', 'tenant:manager'],
        },
        component: () => import('./views/zones/index.vue'),
      },
      {
        path: 'zones/:zoneId',
        name: 'DnsZoneRecords',
        meta: {
          hideInMenu: true,
          title: 'dns.menu.records',
          authority: ['platform:admin', 'tenant:manager'],
        },
        component: () => import('./views/zones/zone-records.vue'),
      },
      {
        path: 'templates',
        name: 'DnsTemplates',
        meta: {
          icon: 'lucide:file-text',
          title: 'dns.menu.templates',
          authority: ['platform:admin', 'tenant:manager'],
        },
        component: () => import('./views/templates/index.vue'),
      },
      {
        path: 'supermasters',
        name: 'DnsSupermasters',
        meta: {
          icon: 'lucide:server',
          title: 'dns.menu.supermasters',
          authority: ['platform:admin', 'tenant:manager'],
        },
        component: () => import('./views/supermasters/index.vue'),
      },
      {
        path: 'configuration',
        name: 'DnsConfiguration',
        meta: {
          icon: 'lucide:settings',
          title: 'dns.menu.configuration',
          authority: ['platform:admin'],
        },
        component: () => import('./views/configuration/index.vue'),
      },
    ],
  },
];

export default routes;
