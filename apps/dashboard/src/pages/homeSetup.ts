export type HomeSetupMode = "replace" | "supplemental" | "hidden";

export function homeSetupMode({
  isScoped,
  hasProduct,
  setupComplete,
}: {
  isScoped: boolean;
  hasProduct: boolean;
  setupComplete: boolean;
}): HomeSetupMode {
  if (isScoped || setupComplete) return "hidden";
  return hasProduct ? "supplemental" : "replace";
}
