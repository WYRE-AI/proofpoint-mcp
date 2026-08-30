/**
 * Handler-invocation tests for the DLP domain.
 *
 * The tool surface (proofpoint_dlp_*) is registered via getTools() and wired
 * through index.ts's CallTool handler, but the request-shaping and
 * response-mapping logic inside handleCall was never exercised by a test.
 * These mock the underlying apiRequest client and invoke handleCall
 * directly, asserting outbound call shape (path, params, method) and the
 * shape of what's returned to the MCP caller.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { dlpHandler } from "../dlp.js";

vi.mock("../../utils/client.js", () => ({
  apiRequest: vi.fn(),
}));

import { apiRequest } from "../../utils/client.js";
const mockApiRequest = vi.mocked(apiRequest);

describe("dlpHandler", () => {
  beforeEach(() => {
    mockApiRequest.mockReset();
  });

  describe("proofpoint_dlp_list_incidents", () => {
    it("passes through filters and applies page/per_page defaults", async () => {
      mockApiRequest.mockResolvedValue({ incidents: [] });

      const result = await dlpHandler.handleCall("proofpoint_dlp_list_incidents", {
        severity: "high",
        status: "open",
      });

      expect(mockApiRequest).toHaveBeenCalledWith("/v1/dlp/incidents", {
        params: { page: 1, per_page: 50, severity: "high", status: "open" },
      });
      expect(JSON.parse(result.content[0].text)).toEqual({ incidents: [] });
      expect(result.isError).toBeUndefined();
    });

    it("honors explicit paging and date range params", async () => {
      mockApiRequest.mockResolvedValue({ incidents: [] });

      await dlpHandler.handleCall("proofpoint_dlp_list_incidents", {
        startDate: "2026-01-01",
        endDate: "2026-01-31",
        page: 3,
        per_page: 10,
      });

      expect(mockApiRequest).toHaveBeenCalledWith("/v1/dlp/incidents", {
        params: {
          page: 3,
          per_page: 10,
          startDate: "2026-01-01",
          endDate: "2026-01-31",
        },
      });
    });

    it("has no elicitation server attached in tests, so no filters means no filter params are added", async () => {
      mockApiRequest.mockResolvedValue({ incidents: [] });

      await dlpHandler.handleCall("proofpoint_dlp_list_incidents", {});

      expect(mockApiRequest).toHaveBeenCalledWith("/v1/dlp/incidents", {
        params: { page: 1, per_page: 50 },
      });
    });
  });

  describe("proofpoint_dlp_get_incident", () => {
    it("URL-encodes the incident id into the path", async () => {
      mockApiRequest.mockResolvedValue({ id: "abc/def", status: "open" });

      const result = await dlpHandler.handleCall("proofpoint_dlp_get_incident", {
        incident_id: "abc/def",
      });

      expect(mockApiRequest).toHaveBeenCalledWith("/v1/dlp/incidents/abc%2Fdef");
      expect(JSON.parse(result.content[0].text)).toEqual({
        id: "abc/def",
        status: "open",
      });
    });

    it("returns an error and never calls the API when incident_id is missing", async () => {
      const result = await dlpHandler.handleCall("proofpoint_dlp_get_incident", {});

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("incident_id is required");
      expect(mockApiRequest).not.toHaveBeenCalled();
    });
  });

  describe("proofpoint_dlp_list_encrypted", () => {
    it("shapes sender/recipient filters into query params", async () => {
      mockApiRequest.mockResolvedValue({ messages: [] });

      await dlpHandler.handleCall("proofpoint_dlp_list_encrypted", {
        sender: "a@example.com",
        recipient: "b@example.com",
      });

      expect(mockApiRequest).toHaveBeenCalledWith("/v1/encryption/messages", {
        params: {
          page: 1,
          per_page: 50,
          sender: "a@example.com",
          recipient: "b@example.com",
        },
      });
    });
  });

  describe("unknown tool", () => {
    it("returns an isError result without calling the API", async () => {
      const result = await dlpHandler.handleCall("proofpoint_dlp_nonexistent", {});
      expect(result.isError).toBe(true);
      expect(mockApiRequest).not.toHaveBeenCalled();
    });
  });
});
