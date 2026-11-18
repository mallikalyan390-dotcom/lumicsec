import { describe, expect, it } from "vitest";
import { importOfflineDocument } from "../src/index.js";

describe("API specification import limits", () => {
  it("rejects an oversized specification", async () => {
    const content = " ".repeat(1_048_577);
    await expect(importOfflineDocument(content)).rejects.toThrow("DOCUMENT_SIZE_LIMIT");
  });

  it("rejects unsupported external document formats", async () => {
    await expect(importOfflineDocument("<?xml version='1.0'?><root/>")).rejects.toThrow();
  });
});
