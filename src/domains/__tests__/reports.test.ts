/**
 * Handler-invocation tests for the reports domain — see dlp.test.ts for the
 * rationale.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { reportsHandler } from "../reports.js";

vi.mock("../../utils/client.js", () => ({
  apiRequest: vi.fn(),
}));

import { apiRequest } from "../../utils/client.js";
const mockApiRequest = vi.mocked(apiRequest);

describe("reportsHandler", () => {
  beforeEach(() => {
    mockApiRequest.mockReset();
  });

  describe("proofpoint_reports_org_summary", () => {
    it("defaults window to 30 when unset (no elicitation server in tests)", async () => {
      mockApiRequest.mockResolvedValue({ totals: {} });
      await reportsHandler.handleCall("proofpoint_reports_org_summary", {});
      expect(mockApiRequest).toHaveBeenCalledWith("/v1/reports/summary", {
        params: { window: 30 },
      });
    });

    it("passes through an explicit window", async () => {
      mockApiRequest.mockResolvedValue({ totals: {} });
      await reportsHandler.handleCall("proofpoint_reports_org_summary", { window: 7 });
      expect(mockApiRequest).toHaveBeenCalledWith("/v1/reports/summary", {
        params: { window: 7 },
      });
    });
  });

  describe("proofpoint_reports_threat_summary", () => {
    it("defaults window to 30 and drops threatType when it's 'all'", async () => {
      mockApiRequest.mockResolvedValue({ breakdown: {} });
      await reportsHandler.handleCall("proofpoint_reports_threat_summary", {
        threatType: "all",
      });
      expect(mockApiRequest).toHaveBeenCalledWith("/v1/reports/threats", {
        params: { window: 30 },
      });
    });

    it("includes threatType when it's a specific value", async () => {
      mockApiRequest.mockResolvedValue({ breakdown: {} });
      await reportsHandler.handleCall("proofpoint_reports_threat_summary", {
        threatType: "malware",
        window: 14,
      });
      expect(mockApiRequest).toHaveBeenCalledWith("/v1/reports/threats", {
        params: { window: 14, threatType: "malware" },
      });
    });
  });

  describe("proofpoint_reports_mail_flow", () => {
    it("defaults window to 7 (not 30) and omits granularity when unset", async () => {
      mockApiRequest.mockResolvedValue({ series: [] });
      await reportsHandler.handleCall("proofpoint_reports_mail_flow", {});
      expect(mockApiRequest).toHaveBeenCalledWith("/v1/reports/mail-flow", {
        params: { window: 7 },
      });
    });

    it("passes through granularity", async () => {
      mockApiRequest.mockResolvedValue({ series: [] });
      await reportsHandler.handleCall("proofpoint_reports_mail_flow", {
        granularity: "hourly",
      });
      expect(mockApiRequest).toHaveBeenCalledWith("/v1/reports/mail-flow", {
        params: { window: 7, granularity: "hourly" },
      });
    });
  });

  describe("proofpoint_reports_executive_summary", () => {
    it("defaults window to 30", async () => {
      mockApiRequest.mockResolvedValue({ summary: "..." });
      const result = await reportsHandler.handleCall(
        "proofpoint_reports_executive_summary",
        {}
      );
      expect(mockApiRequest).toHaveBeenCalledWith("/v1/reports/executive", {
        params: { window: 30 },
      });
      expect(JSON.parse(result.content[0].text)).toEqual({ summary: "..." });
    });
  });

  it("unknown tool returns isError without calling the API", async () => {
    const result = await reportsHandler.handleCall("proofpoint_reports_bogus", {});
    expect(result.isError).toBe(true);
    expect(mockApiRequest).not.toHaveBeenCalled();
  });
});
