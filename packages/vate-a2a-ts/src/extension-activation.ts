import { VATE_A2A_EXTENSION_URI } from "./types.js";

export function isVateExtensionActivated(headerValue: string | undefined): boolean {
  if (!headerValue) {
    return false;
  }
  return headerValue
    .split(",")
    .map((part) => part.trim())
    .includes(VATE_A2A_EXTENSION_URI);
}
