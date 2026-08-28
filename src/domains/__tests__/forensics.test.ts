/**
 * Handler-invocation tests for the forensics domain — see dlp.test.ts for
 * the rationale.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { forensicsHandler } from "../forensics.js";

vi.mock("../../utils/client.js", () => ({
  apiRequest: vi.fn(),
}));

import { apiRequest } from "../../utils/client.js";
const mockApiRequest = vi.mocked(apiRequest);

describe("forensicsHandler", () => {
  beforeEach(() => {
    mockApiRequest.mockReset();
  });

  describe("proofpoint_forensics_get_threat", () => {
    it("requires threat_id", async () => {
      const result = await forensicsHandler.handleCall("proofpoint_forensics_get_threat", {});
      expect(result.isError).toBe(true);
      expect(mockApiRequest).not.toHaveBeenCalled();
    });

    it("URL-encodes threat_id and omits includeCampaignForensics when falsy", async () => {
      mockApiRequest.mockResolvedValue({ threatId: "t1" });
      await forensicsHandler.handleCall("proofpoint_forensics_get_threat", {
        threat_id: "t/1",
      });
      expect(mockApiRequest).toHaveBeenCalledWith("/v2/forensics/threat/t%2F1", {
        params: {},
      });
    });

    it("includes includeCampaignForensics when true", async () => {
      mockApiRequest.mockResolvedValue({ threatId: "t1" });
      await forensicsHandler.handleCall("proofpoint_forensics_get_threat", {
        threat_id: "t1",
        includeCampaignForensics: true,
      });
      expect(mockApiRequest).toHaveBeenCalledWith("/v2/forensics/threat/t1", {
        params: { includeCampaignForensics: true },
      });
    });
  });

  describe("proofpoint_forensics_get_campaign", () => {
    it("requires campaign_id", async () => {
      const result = await forensicsHandler.handleCall("proofpoint_forensics_get_campaign", {});
      expect(result.isError).toBe(true);
      expect(mockApiRequest).not.toHaveBeenCalled();
    });

    it("URL-encodes campaign_id into the path", async () => {
      mockApiRequest.mockResolvedValue({ campaignId: "c1" });
      await forensicsHandler.handleCall("proofpoint_forensics_get_campaign", {
        campaign_id: "c/1",
      });
      expect(mockApiRequest).toHaveBeenCalledWith("/v2/forensics/campaign/c%2F1");
    });
  });

  describe("proofpoint_forensics_search_messages", () => {
    it("with no filters and no elicitation server, sends an empty params object", async () => {
      mockApiRequest.mockResolvedValue({ messages: [] });
      await forensicsHandler.handleCall("proofpoint_forensics_search_messages", {});
      expect(mockApiRequest).toHaveBeenCalledWith("/v1/trap/search", { params: {} });
    });

    it("maps message_id/threat_id args to messageID/threatID params", async () => {
      mockApiRequest.mockResolvedValue({ messages: [] });
      await forensicsHandler.handleCall("proofpoint_forensics_search_messages", {
        message_id: "mid-1",
        threat_id: "tid-1",
      });
      expect(mockApiRequest).toHaveBeenCalledWith("/v1/trap/search", {
        params: { messageID: "mid-1", threatID: "tid-1" },
      });
    });
  });

  describe("proofpoint_forensics_pull_messages", () => {
    it("requires a non-empty message_ids array", async () => {
      const empty = await forensicsHandler.handleCall("proofpoint_forensics_pull_messages", {
        message_ids: [],
      });
      expect(empty.isError).toBe(true);

      const missing = await forensicsHandler.handleCall("proofpoint_forensics_pull_messages", {});
      expect(missing.isError).toBe(true);
      expect(mockApiRequest).not.toHaveBeenCalled();
    });

    it("POSTs message_ids with a default reason and wraps a success envelope (no elicitation server, so confirmation !== false and it proceeds)", async () => {
      mockApiRequest.mockResolvedValue({ pullId: "p1" });

      const result = await forensicsHandler.handleCall("proofpoint_forensics_pull_messages", {
        message_ids: ["m1", "m2"],
      });

      expect(mockApiRequest).toHaveBeenCalledWith("/v1/trap/pull", {
        method: "POST",
        body: { messageIds: ["m1", "m2"], reason: "Threat remediation via MCP" },
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.success).toBe(true);
      expect(parsed.message).toContain("2 message(s)");
    });

    it("passes through a custom reason", async () => {
      mockApiRequest.mockResolvedValue({ pullId: "p1" });
      await forensicsHandler.handleCall("proofpoint_forensics_pull_messages", {
        message_ids: ["m1"],
        reason: "Confirmed phishing campaign",
      });
      expect(mockApiRequest).toHaveBeenCalledWith("/v1/trap/pull", {
        method: "POST",
        body: { messageIds: ["m1"], reason: "Confirmed phishing campaign" },
      });
    });
  });

  it("unknown tool returns isError without calling the API", async () => {
    const result = await forensicsHandler.handleCall("proofpoint_forensics_bogus", {});
    expect(result.isError).toBe(true);
    expect(mockApiRequest).not.toHaveBeenCalled();
  });
});
