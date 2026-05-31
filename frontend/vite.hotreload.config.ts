import originalConfig from './vite.config';
import { mergeConfig, type UserConfig, type Plugin } from 'vite';

const resolved = typeof originalConfig === 'function'
  ? originalConfig({ command: 'build', mode: 'development' })
  : originalConfig;

// Plugin that runs last to ensure HMR is disabled after all other plugins
const disableHmr: Plugin = {
  name: 'disable-hmr',
  enforce: 'post',
  config() {
    return { server: { hmr: false } };
  },
  configureServer(server) {
    // Close the WebSocket server if module-federation created one
    if (server.ws && typeof server.ws.close === 'function') {
      server.ws.close();
    }
  },
};

const merged = mergeConfig(resolved as UserConfig, {
  base: '/modules/dns/',
  server: { allowedHosts: true, hmr: false },
});

// Append our plugin last so its config hook wins
merged.plugins = [...(Array.isArray(merged.plugins) ? merged.plugins : []), disableHmr];

export default merged;
