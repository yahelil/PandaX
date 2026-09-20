export type HomeSetupMode = "replace" | "hidden";

export function homeSetupMode({
  isScoped,
  hasProduct,
}: {
  isScoped: boolean;
  hasProduct: boolean;
}): HomeSetupMode {
  return isScoped || hasProduct ? "hidden" : "replace";
}
