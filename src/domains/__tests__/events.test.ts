/**
 * Handler-invocation tests for the events domain — see dlp.test.ts for the
 * rationale.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { eventsHandler } from "../events.js";

vi.mock("../../utils/client.js", () => ({
  apiRequest: vi.fn(),
}));

import { apiRequest } from "../../utils/client.js";
const mockApiRequest = vi.mocked(apiRequest);

describe("eventsHandler", () => {
  beforeEach(() => {
    mockApiRequest.mockReset();
  });

  describe("proofpoint_events_list", () => {
    it("defaults to interval=PT1H when no time filter is given (no elicitation server in tests)", async () => {
      mockApiRequest.mockResolvedValue({ events: [] });
      await eventsHandler.handleCall("proofpoint_events_list", {});
      expect(mockApiRequest).toHaveBeenCalledWith("/v2/siem/all", {
        params: { interval: "PT1H" },
      });
    });

    it("passes through threatType and disposition filters", async () => {
      mockApiRequest.mockResolvedValue({ events: [] });
      await eventsHandler.handleCall("proofpoint_events_list", {
        sinceSeconds: 900,
        threatType: "phish",
        disposition: "blocked",
      });
      expect(mockApiRequest).toHaveBeenCalledWith("/v2/siem/all", {
        params: { sinceSeconds: 900, threatType: "phish", disposition: "blocked" },
      });
    });
  });

  describe("proofpoint_events_get_details", () => {
    it("requires event_id", async () => {
      const result = await eventsHandler.handleCall("proofpoint_events_get_details", {});
      expect(result.isError).toBe(true);
      expect(mockApiRequest).not.toHaveBeenCalled();
    });

    it("URL-encodes event_id into the path", async () => {
      mockApiRequest.mockResolvedValue({ id: "e/1" });
      const result = await eventsHandler.handleCall("proofpoint_events_get_details", {
        event_id: "e/1",
      });
      expect(mockApiRequest).toHaveBeenCalledWith("/v2/events/e%2F1");
      expect(JSON.parse(result.content[0].text)).toEqual({ id: "e/1" });
    });
  });

  describe("proofpoint_events_get_stats", () => {
    it("defaults to interval=PT1H", async () => {
      mockApiRequest.mockResolvedValue({ counts: {} });
      await eventsHandler.handleCall("proofpoint_events_get_stats", {});
      expect(mockApiRequest).toHaveBeenCalledWith("/v2/events/stats", {
        params: { interval: "PT1H" },
      });
    });

    it("passes through sinceSeconds instead of defaulting", async () => {
      mockApiRequest.mockResolvedValue({ counts: {} });
      await eventsHandler.handleCall("proofpoint_events_get_stats", { sinceSeconds: 60 });
      expect(mockApiRequest).toHaveBeenCalledWith("/v2/events/stats", {
        params: { sinceSeconds: 60 },
      });
    });
  });

  it("unknown tool returns isError without calling the API", async () => {
    const result = await eventsHandler.handleCall("proofpoint_events_bogus", {});
    expect(result.isError).toBe(true);
    expect(mockApiRequest).not.toHaveBeenCalled();
  });
});
