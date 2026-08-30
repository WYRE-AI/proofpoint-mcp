/**
 * Handler-invocation tests for the URL Defense domain — see dlp.test.ts for
 * the rationale.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { urlDefenseHandler } from "../url-defense.js";

vi.mock("../../utils/client.js", () => ({
  apiRequest: vi.fn(),
}));

import { apiRequest } from "../../utils/client.js";
const mockApiRequest = vi.mocked(apiRequest);

describe("urlDefenseHandler", () => {
  beforeEach(() => {
    mockApiRequest.mockReset();
  });

  describe("proofpoint_url_decode", () => {
    it("requires a non-empty urls array", async () => {
      const empty = await urlDefenseHandler.handleCall("proofpoint_url_decode", {
        urls: [],
      });
      expect(empty.isError).toBe(true);

      const missing = await urlDefenseHandler.handleCall("proofpoint_url_decode", {});
      expect(missing.isError).toBe(true);
      expect(mockApiRequest).not.toHaveBeenCalled();
    });

    it("POSTs the urls array as the body", async () => {
      mockApiRequest.mockResolvedValue({
        decodedUrls: [{ url: "https://urldefense.proofpoint.com/x", decodedUrl: "https://real.example.com" }],
      });

      const result = await urlDefenseHandler.handleCall("proofpoint_url_decode", {
        urls: ["https://urldefense.proofpoint.com/x"],
      });

      expect(mockApiRequest).toHaveBeenCalledWith("/v2/url/decode", {
        method: "POST",
        body: { urls: ["https://urldefense.proofpoint.com/x"] },
      });
      expect(JSON.parse(result.content[0].text)).toEqual({
        decodedUrls: [{ url: "https://urldefense.proofpoint.com/x", decodedUrl: "https://real.example.com" }],
      });
    });
  });

  describe("proofpoint_url_analyze", () => {
    it("requires url", async () => {
      const result = await urlDefenseHandler.handleCall("proofpoint_url_analyze", {});
      expect(result.isError).toBe(true);
      expect(mockApiRequest).not.toHaveBeenCalled();
    });

    it("POSTs the url as the body", async () => {
      mockApiRequest.mockResolvedValue({ riskScore: 10, classification: "clean" });

      const result = await urlDefenseHandler.handleCall("proofpoint_url_analyze", {
        url: "https://example.com",
      });

      expect(mockApiRequest).toHaveBeenCalledWith("/v2/url/analyze", {
        method: "POST",
        body: { url: "https://example.com" },
      });
      expect(JSON.parse(result.content[0].text)).toEqual({
        riskScore: 10,
        classification: "clean",
      });
    });
  });

  it("unknown tool returns isError without calling the API", async () => {
    const result = await urlDefenseHandler.handleCall("proofpoint_url_bogus", {});
    expect(result.isError).toBe(true);
    expect(mockApiRequest).not.toHaveBeenCalled();
  });
});
