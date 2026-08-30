/**
 * Handler-invocation tests for the quarantine domain — see dlp.test.ts for
 * the rationale (tool surface was wired but handleCall itself untested).
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { quarantineHandler } from "../quarantine.js";

vi.mock("../../utils/client.js", () => ({
  apiRequest: vi.fn(),
}));

import { apiRequest } from "../../utils/client.js";
const mockApiRequest = vi.mocked(apiRequest);

describe("quarantineHandler", () => {
  beforeEach(() => {
    mockApiRequest.mockReset();
  });

  describe("proofpoint_quarantine_list", () => {
    it("shapes filters into query params and applies defaults", async () => {
      mockApiRequest.mockResolvedValue({ messages: [{ id: "m1" }] });

      const result = await quarantineHandler.handleCall("proofpoint_quarantine_list", {
        sender: "a@example.com",
        folder: "SPAM",
      });

      expect(mockApiRequest).toHaveBeenCalledWith("/v1/quarantine", {
        params: { page: 1, per_page: 50, sender: "a@example.com", folder: "SPAM" },
      });
      expect(JSON.parse(result.content[0].text)).toEqual({
        messages: [{ id: "m1" }],
        page: 1,
        per_page: 50,
      });
    });

    it("unwraps a `messages` envelope from the API response", async () => {
      mockApiRequest.mockResolvedValue({ messages: [{ id: "m1" }], total: 1 });

      const result = await quarantineHandler.handleCall("proofpoint_quarantine_list", {
        sender: "a@example.com",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.messages).toEqual([{ id: "m1" }]);
    });

    it("passes a bare array response through unwrapped", async () => {
      mockApiRequest.mockResolvedValue([{ id: "m1" }]);

      const result = await quarantineHandler.handleCall("proofpoint_quarantine_list", {
        sender: "a@example.com",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.messages).toEqual([{ id: "m1" }]);
    });
  });

  describe("proofpoint_quarantine_search", () => {
    it("requires query and errors without calling the API", async () => {
      const result = await quarantineHandler.handleCall("proofpoint_quarantine_search", {});
      expect(result.isError).toBe(true);
      expect(mockApiRequest).not.toHaveBeenCalled();
    });

    it("sends the query as `q` plus paging params", async () => {
      mockApiRequest.mockResolvedValue({ results: [] });

      await quarantineHandler.handleCall("proofpoint_quarantine_search", {
        query: "invoice",
        page: 2,
      });

      expect(mockApiRequest).toHaveBeenCalledWith("/v1/quarantine/search", {
        params: { q: "invoice", page: 2, per_page: 50 },
      });
    });
  });

  describe("proofpoint_quarantine_release", () => {
    it("POSTs to the release endpoint and wraps a success envelope", async () => {
      mockApiRequest.mockResolvedValue({ status: "released" });

      const result = await quarantineHandler.handleCall("proofpoint_quarantine_release", {
        message_id: "msg-123",
      });

      expect(mockApiRequest).toHaveBeenCalledWith("/v1/quarantine/msg-123/release", {
        method: "POST",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.success).toBe(true);
      expect(parsed.message).toContain("msg-123");
      expect(parsed.result).toEqual({ status: "released" });
    });

    it("requires message_id and errors without calling the API", async () => {
      const result = await quarantineHandler.handleCall("proofpoint_quarantine_release", {});
      expect(result.isError).toBe(true);
      expect(mockApiRequest).not.toHaveBeenCalled();
    });
  });

  describe("proofpoint_quarantine_delete", () => {
    it("DELETEs the message and wraps a success envelope (no elicitation server in tests, so it proceeds)", async () => {
      mockApiRequest.mockResolvedValue({ status: "deleted" });

      const result = await quarantineHandler.handleCall("proofpoint_quarantine_delete", {
        message_id: "msg-456",
      });

      expect(mockApiRequest).toHaveBeenCalledWith("/v1/quarantine/msg-456", {
        method: "DELETE",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.success).toBe(true);
      expect(parsed.message).toContain("msg-456");
    });

    it("requires message_id and errors without calling the API", async () => {
      const result = await quarantineHandler.handleCall("proofpoint_quarantine_delete", {});
      expect(result.isError).toBe(true);
      expect(mockApiRequest).not.toHaveBeenCalled();
    });
  });
});
