import type { RouteRecordRaw } from 'vue-router'
import '@/main.css'

// Routes mounted by the platform shell under their own error boundary.
export const routes: RouteRecordRaw[] = [
  { path: '/dns', name: 'dns-zones', component: () => import('@/views/zones/index.vue'), meta: { module: 'dns' } },
  { path: '/dns/zones/:id', name: 'dns-zone-records', component: () => import('@/views/zones/records.vue'), meta: { module: 'dns' } },
  { path: '/dns/templates', name: 'dns-templates', component: () => import('@/views/templates/index.vue'), meta: { module: 'dns' } },
  { path: '/dns/supermasters', name: 'dns-supermasters', component: () => import('@/views/supermasters/index.vue'), meta: { module: 'dns' } },
  { path: '/dns/dashboard', name: 'dns-dashboard', component: () => import('@/views/dashboard/index.vue'), meta: { module: 'dns' } },
  { path: '/dns/configuration', name: 'dns-configuration', component: () => import('@/views/configuration/index.vue'), meta: { module: 'dns' } },
]
export default routes
