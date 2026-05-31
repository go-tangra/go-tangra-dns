import './styles/tailwind.css';
import type { TangraModule } from './sdk';
import routes from './routes';
import { useDnsZoneStore } from './stores/dns-zone.state';
import { useDnsRecordStore } from './stores/dns-record.state';
import { useDnsTemplateStore } from './stores/dns-template.state';
import { useDnsSupermasterStore } from './stores/dns-supermaster.state';
import { useDnsConfigStore } from './stores/dns-config.state';
import enUS from './locales/en-US.json';
import zhCN from './locales/zh-CN.json';

const dnsModule: TangraModule = {
  id: 'dns',
  version: '1.0.0',
  routes,
  stores: {
    'dns-zone': useDnsZoneStore,
    'dns-record': useDnsRecordStore,
    'dns-template': useDnsTemplateStore,
    'dns-supermaster': useDnsSupermasterStore,
    'dns-config': useDnsConfigStore,
  },
  locales: {
    'en-US': enUS,
    'zh-CN': zhCN,
  },
};

export default dnsModule;
