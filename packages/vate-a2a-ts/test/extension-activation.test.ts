import { describe, expect, it } from "vitest";
import {
  isVateExtensionActivated,
  VATE_A2A_EXTENSION_URI,
} from "../src/index.js";

describe("extension activation", () => {
  it("detects VATE activation in an A2A-Extensions header", () => {
    expect(isVateExtensionActivated(VATE_A2A_EXTENSION_URI)).toBe(true);
    expect(isVateExtensionActivated(`other, ${VATE_A2A_EXTENSION_URI}`)).toBe(true);
    expect(isVateExtensionActivated("other")).toBe(false);
  });
});
