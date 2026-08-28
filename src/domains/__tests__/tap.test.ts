/**
 * Handler-invocation tests for the TAP (Targeted Attack Protection) domain —
 * see dlp.test.ts for the rationale.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { tapHandler } from "../tap.js";

vi.mock("../../utils/client.js", () => ({
  apiRequest: vi.fn(),
}));

import { apiRequest } from "../../utils/client.js";
const mockApiRequest = vi.mocked(apiRequest);

describe("tapHandler", () => {
  beforeEach(() => {
    mockApiRequest.mockReset();
    mockApiRequest.mockResolvedValue({ threatsInfoMap: [] });
  });

  describe("proofpoint_tap_get_all_threats", () => {
    it("defaults to a PT1H interval when no time filter is given (no elicitation server in tests)", async () => {
      await tapHandler.handleCall("proofpoint_tap_get_all_threats", {});

      expect(mockApiRequest).toHaveBeenCalledWith("/v2/siem/all", {
        params: { interval: "PT1H" },
      });
    });

    it("passes through an explicit sinceSeconds/threatStatus/format without overriding", async () => {
      await tapHandler.handleCall("proofpoint_tap_get_all_threats", {
        sinceSeconds: 1800,
        threatStatus: "cleared",
        format: "json",
      });

      expect(mockApiRequest).toHaveBeenCalledWith("/v2/siem/all", {
        params: { sinceSeconds: 1800, threatStatus: "cleared", format: "json" },
      });
    });
  });

  it.each([
    ["proofpoint_tap_get_messages_delivered", "/v2/siem/messages/delivered"],
    ["proofpoint_tap_get_messages_blocked", "/v2/siem/messages/blocked"],
    ["proofpoint_tap_get_clicks_permitted", "/v2/siem/clicks/permitted"],
    ["proofpoint_tap_get_clicks_blocked", "/v2/siem/clicks/blocked"],
  ])("%s hits %s and defaults to PT1H with no time filter", async (toolName, path) => {
    await tapHandler.handleCall(toolName, {});
    expect(mockApiRequest).toHaveBeenCalledWith(path, {
      params: { interval: "PT1H" },
    });
  });

  it("proofpoint_tap_get_clicks_blocked forwards sinceTime instead of defaulting", async () => {
    await tapHandler.handleCall("proofpoint_tap_get_clicks_blocked", {
      sinceTime: "2026-01-01T00:00:00Z",
    });
    expect(mockApiRequest).toHaveBeenCalledWith("/v2/siem/clicks/blocked", {
      params: { sinceTime: "2026-01-01T00:00:00Z" },
    });
  });

  it("returns the raw SIEM response as the tool result text", async () => {
    mockApiRequest.mockResolvedValue({
      threatsInfoMap: [{ threatId: "t1" }],
    });

    const result = await tapHandler.handleCall("proofpoint_tap_get_all_threats", {
      interval: "PT30M",
    });

    expect(JSON.parse(result.content[0].text)).toEqual({
      threatsInfoMap: [{ threatId: "t1" }],
    });
  });

  it("unknown tool returns isError without calling the API", async () => {
    const result = await tapHandler.handleCall("proofpoint_tap_bogus", {});
    expect(result.isError).toBe(true);
    expect(mockApiRequest).not.toHaveBeenCalled();
  });
});
