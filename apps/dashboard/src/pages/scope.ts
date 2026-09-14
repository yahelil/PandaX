import type { Scope } from "../data/types";

export function scopeFromParams(params: URLSearchParams): Scope {
  return { productId: params.get("product") || undefined, releaseId: params.get("release") || undefined };
}

export function matchesScope(item: { productId?: string; releaseId?: string }, scope: Scope): boolean {
  if (scope.productId && item.productId !== scope.productId) return false;
  return !scope.releaseId || item.releaseId === scope.releaseId;
}

export function scopedPath(path: string, scope: Scope, extras?: Record<string, string>): string {
  const params = new URLSearchParams(extras);
  if (scope.productId) params.set("product", scope.productId);
  if (scope.releaseId) params.set("release", scope.releaseId);
  const query = params.toString();
  return query ? `${path}?${query}` : path;
}
