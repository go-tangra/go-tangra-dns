import type { ShellContext, TangraModule } from './types';

export function registerModule(ctx: ShellContext, module: TangraModule) {
  for (const route of module.routes) {
    const pathsToRemove = new Set<string>();
    pathsToRemove.add(route.path);
    if (route.children) {
      for (const child of route.children) {
        const childPath = child.path.startsWith('/')
          ? child.path
          : `${route.path}/${child.path}`;
        pathsToRemove.add(childPath);
      }
    }

    for (const existing of ctx.router.getRoutes()) {
      if (pathsToRemove.has(existing.path) && existing.name) {
        ctx.router.removeRoute(existing.name);
      }
    }

    ctx.router.addRoute(route);
  }

  for (const [lang, messages] of Object.entries(module.locales)) {
    ctx.i18n.global.mergeLocaleMessage(lang, { [module.id]: messages });
  }
}
