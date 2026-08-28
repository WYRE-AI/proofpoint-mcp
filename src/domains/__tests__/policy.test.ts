/**
 * Handler-invocation tests for the policy domain — see dlp.test.ts for the
 * rationale.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { policyHandler } from "../policy.js";

vi.mock("../../utils/client.js", () => ({
  apiRequest: vi.fn(),
}));

import { apiRequest } from "../../utils/client.js";
const mockApiRequest = vi.mocked(apiRequest);

describe("policyHandler", () => {
  beforeEach(() => {
    mockApiRequest.mockReset();
  });

  describe("proofpoint_policy_list", () => {
    it("sends an empty params object when type is unset", async () => {
      mockApiRequest.mockResolvedValue({ policies: [] });
      await policyHandler.handleCall("proofpoint_policy_list", {});
      expect(mockApiRequest).toHaveBeenCalledWith("/v1/policies", { params: {} });
    });

    it("passes through the type filter", async () => {
      mockApiRequest.mockResolvedValue({ policies: [] });
      await policyHandler.handleCall("proofpoint_policy_list", { type: "inbound" });
      expect(mockApiRequest).toHaveBeenCalledWith("/v1/policies", {
        params: { type: "inbound" },
      });
    });
  });

  describe("proofpoint_policy_get", () => {
    it("requires policy_id", async () => {
      const result = await policyHandler.handleCall("proofpoint_policy_get", {});
      expect(result.isError).toBe(true);
      expect(mockApiRequest).not.toHaveBeenCalled();
    });

    it("URL-encodes policy_id into the path", async () => {
      mockApiRequest.mockResolvedValue({ id: "p/1", rules: [] });
      const result = await policyHandler.handleCall("proofpoint_policy_get", {
        policy_id: "p/1",
      });
      expect(mockApiRequest).toHaveBeenCalledWith("/v1/policies/p%2F1");
      expect(JSON.parse(result.content[0].text)).toEqual({ id: "p/1", rules: [] });
    });
  });

  describe("proofpoint_policy_list_routes", () => {
    it("applies page/per_page defaults", async () => {
      mockApiRequest.mockResolvedValue({ routes: [] });
      await policyHandler.handleCall("proofpoint_policy_list_routes", {});
      expect(mockApiRequest).toHaveBeenCalledWith("/v1/policy/routes", {
        params: { page: 1, per_page: 50 },
      });
    });

    it("honors explicit paging", async () => {
      mockApiRequest.mockResolvedValue({ routes: [] });
      await policyHandler.handleCall("proofpoint_policy_list_routes", {
        page: 4,
        per_page: 25,
      });
      expect(mockApiRequest).toHaveBeenCalledWith("/v1/policy/routes", {
        params: { page: 4, per_page: 25 },
      });
    });
  });

  it("unknown tool returns isError without calling the API", async () => {
    const result = await policyHandler.handleCall("proofpoint_policy_bogus", {});
    expect(result.isError).toBe(true);
    expect(mockApiRequest).not.toHaveBeenCalled();
  });
});
