/**
 * Handler-invocation tests for the threat-intel domain — see dlp.test.ts for
 * the rationale.
 *
 * buildThreatCard() itself is already thoroughly unit-tested in
 * mcp-apps.test.ts; what's untested is the *wiring* in
 * proofpoint_threat_get_by_id — that the handler calls apiRequest, attaches
 * the card's output as `_card` on the JSON payload, and degrades gracefully
 * when the response isn't a valid threat summary.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { threatIntelHandler } from "../threat-intel.js";

vi.mock("../../utils/client.js", () => ({
  apiRequest: vi.fn(),
}));

import { apiRequest } from "../../utils/client.js";
const mockApiRequest = vi.mocked(apiRequest);

describe("threatIntelHandler", () => {
  beforeEach(() => {
    mockApiRequest.mockReset();
  });

  describe("proofpoint_threat_get_campaign", () => {
    it("URL-encodes campaign_id into the path", async () => {
      mockApiRequest.mockResolvedValue({ id: "camp/1", name: "Q3 lures" });

      const result = await threatIntelHandler.handleCall("proofpoint_threat_get_campaign", {
        campaign_id: "camp/1",
      });

      expect(mockApiRequest).toHaveBeenCalledWith("/v2/campaign/camp%2F1");
      expect(JSON.parse(result.content[0].text)).toEqual({ id: "camp/1", name: "Q3 lures" });
    });

    it("requires campaign_id", async () => {
      const result = await threatIntelHandler.handleCall("proofpoint_threat_get_campaign", {});
      expect(result.isError).toBe(true);
      expect(mockApiRequest).not.toHaveBeenCalled();
    });
  });

  describe("proofpoint_threat_get_by_id", () => {
    it("requests the threat summary and attaches a normalized _card for a valid payload", async () => {
      mockApiRequest.mockResolvedValue({
        id: "b31a3b45cf12a4e8",
        name: "hxxps://malicious.example.com/invoice.pdf",
        type: "url",
        severityScore: 90,
      });

      const result = await threatIntelHandler.handleCall("proofpoint_threat_get_by_id", {
        threat_id: "b31a3b45cf12a4e8",
      });

      expect(mockApiRequest).toHaveBeenCalledWith(
        "/v2/threat/summary/b31a3b45cf12a4e8"
      );
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.id).toBe("b31a3b45cf12a4e8");
      expect(parsed._card).toEqual({
        id: "b31a3b45cf12a4e8",
        name: "hxxps://malicious.example.com/invoice.pdf",
        type: "url",
        severityScore: 90,
      });
    });

    it("omits _card (but still returns the raw payload) when the response isn't a threat summary", async () => {
      mockApiRequest.mockResolvedValue("An unexpected error occurred");

      const result = await threatIntelHandler.handleCall("proofpoint_threat_get_by_id", {
        threat_id: "bad-id",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed).toBe("An unexpected error occurred");
      expect(result.isError).toBeUndefined();
    });

    it("URL-encodes threat_id and requires it", async () => {
      mockApiRequest.mockResolvedValue({ id: "x", name: "x" });
      await threatIntelHandler.handleCall("proofpoint_threat_get_by_id", {
        threat_id: "abc def",
      });
      expect(mockApiRequest).toHaveBeenCalledWith("/v2/threat/summary/abc%20def");

      const missing = await threatIntelHandler.handleCall("proofpoint_threat_get_by_id", {});
      expect(missing.isError).toBe(true);
    });
  });

  describe("proofpoint_threat_list_families", () => {
    it("defaults to interval=PT1H with no time filter", async () => {
      mockApiRequest.mockResolvedValue({ families: [] });
      await threatIntelHandler.handleCall("proofpoint_threat_list_families", {});
      expect(mockApiRequest).toHaveBeenCalledWith("/v2/threat/families", {
        params: { interval: "PT1H" },
      });
    });

    it("passes through sinceTime instead of defaulting", async () => {
      mockApiRequest.mockResolvedValue({ families: [] });
      await threatIntelHandler.handleCall("proofpoint_threat_list_families", {
        sinceTime: "2026-01-01T00:00:00Z",
      });
      expect(mockApiRequest).toHaveBeenCalledWith("/v2/threat/families", {
        params: { sinceTime: "2026-01-01T00:00:00Z" },
      });
    });
  });

  describe("proofpoint_threat_get_iocs", () => {
    it("without campaign_id or time filter, defaults to interval=PT1H against the base IOC endpoint", async () => {
      mockApiRequest.mockResolvedValue({ iocs: [] });
      await threatIntelHandler.handleCall("proofpoint_threat_get_iocs", {});
      expect(mockApiRequest).toHaveBeenCalledWith("/v2/threat/iocs", {
        params: { interval: "PT1H" },
      });
    });

    it("routes to the campaign-scoped IOC path when campaign_id is given", async () => {
      mockApiRequest.mockResolvedValue({ iocs: [] });
      await threatIntelHandler.handleCall("proofpoint_threat_get_iocs", {
        campaign_id: "camp-1",
        threat_type: "url",
      });
      expect(mockApiRequest).toHaveBeenCalledWith("/v2/campaign/camp-1/iocs", {
        params: { threatType: "url" },
      });
    });
  });

  it("unknown tool returns isError without calling the API", async () => {
    const result = await threatIntelHandler.handleCall("proofpoint_threat_bogus", {});
    expect(result.isError).toBe(true);
    expect(mockApiRequest).not.toHaveBeenCalled();
  });
});
