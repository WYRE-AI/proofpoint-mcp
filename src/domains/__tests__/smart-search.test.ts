/**
 * Handler-invocation tests for the smart-search domain — see dlp.test.ts for
 * the rationale.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { smartSearchHandler } from "../smart-search.js";

vi.mock("../../utils/client.js", () => ({
  apiRequest: vi.fn(),
}));

import { apiRequest } from "../../utils/client.js";
const mockApiRequest = vi.mocked(apiRequest);

describe("smartSearchHandler", () => {
  beforeEach(() => {
    mockApiRequest.mockReset();
  });

  describe("proofpoint_smart_search_trace", () => {
    it("with no filters and no elicitation server, sends only paging defaults", async () => {
      mockApiRequest.mockResolvedValue({ messages: [] });
      await smartSearchHandler.handleCall("proofpoint_smart_search_trace", {});
      expect(mockApiRequest).toHaveBeenCalledWith("/v1/smart-search", {
        params: { page: 1, per_page: 50 },
      });
    });

    it("maps message_id to messageID and drops status when it's 'all'", async () => {
      mockApiRequest.mockResolvedValue({ messages: [] });
      await smartSearchHandler.handleCall("proofpoint_smart_search_trace", {
        message_id: "mid-1",
        status: "all",
      });
      expect(mockApiRequest).toHaveBeenCalledWith("/v1/smart-search", {
        params: { page: 1, per_page: 50, messageID: "mid-1" },
      });
    });

    it("includes status when it's a specific value", async () => {
      mockApiRequest.mockResolvedValue({ messages: [] });
      await smartSearchHandler.handleCall("proofpoint_smart_search_trace", {
        sender: "a@example.com",
        status: "bounced",
      });
      expect(mockApiRequest).toHaveBeenCalledWith("/v1/smart-search", {
        params: { page: 1, per_page: 50, sender: "a@example.com", status: "bounced" },
      });
    });
  });

  describe("proofpoint_smart_search_get_message", () => {
    it("requires message_id", async () => {
      const result = await smartSearchHandler.handleCall(
        "proofpoint_smart_search_get_message",
        {}
      );
      expect(result.isError).toBe(true);
      expect(mockApiRequest).not.toHaveBeenCalled();
    });

    it("URL-encodes message_id into the path", async () => {
      mockApiRequest.mockResolvedValue({ id: "m/1" });
      const result = await smartSearchHandler.handleCall(
        "proofpoint_smart_search_get_message",
        { message_id: "m/1" }
      );
      expect(mockApiRequest).toHaveBeenCalledWith("/v1/smart-search/messages/m%2F1");
      expect(JSON.parse(result.content[0].text)).toEqual({ id: "m/1" });
    });
  });

  describe("proofpoint_smart_search_get_headers", () => {
    it("requires message_id and hits the /headers subpath", async () => {
      const missing = await smartSearchHandler.handleCall(
        "proofpoint_smart_search_get_headers",
        {}
      );
      expect(missing.isError).toBe(true);

      mockApiRequest.mockResolvedValue({ headers: {} });
      await smartSearchHandler.handleCall("proofpoint_smart_search_get_headers", {
        message_id: "m1",
      });
      expect(mockApiRequest).toHaveBeenCalledWith(
        "/v1/smart-search/messages/m1/headers"
      );
    });
  });

  it("unknown tool returns isError without calling the API", async () => {
    const result = await smartSearchHandler.handleCall("proofpoint_smart_search_bogus", {});
    expect(result.isError).toBe(true);
    expect(mockApiRequest).not.toHaveBeenCalled();
  });
});
