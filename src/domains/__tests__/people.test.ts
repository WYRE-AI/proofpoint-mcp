/**
 * Handler-invocation tests for the people domain — see dlp.test.ts for the
 * rationale.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { peopleHandler } from "../people.js";

vi.mock("../../utils/client.js", () => ({
  apiRequest: vi.fn(),
}));

import { apiRequest } from "../../utils/client.js";
const mockApiRequest = vi.mocked(apiRequest);

describe("peopleHandler", () => {
  beforeEach(() => {
    mockApiRequest.mockReset();
  });

  describe("proofpoint_people_get_vap", () => {
    it("defaults window to 30 and page/size when unset (no elicitation server in tests)", async () => {
      mockApiRequest.mockResolvedValue({ users: [] });

      await peopleHandler.handleCall("proofpoint_people_get_vap", {});

      expect(mockApiRequest).toHaveBeenCalledWith("/v2/people/vap", {
        params: { window: 30, page: 1, size: 1000 },
      });
    });

    it("passes through an explicit window/page/size", async () => {
      mockApiRequest.mockResolvedValue({ users: [] });

      await peopleHandler.handleCall("proofpoint_people_get_vap", {
        window: 90,
        page: 2,
        size: 50,
      });

      expect(mockApiRequest).toHaveBeenCalledWith("/v2/people/vap", {
        params: { window: 90, page: 2, size: 50 },
      });
    });
  });

  describe("proofpoint_people_get_top_clickers", () => {
    it("defaults window to 30", async () => {
      mockApiRequest.mockResolvedValue({ users: [] });
      await peopleHandler.handleCall("proofpoint_people_get_top_clickers", {});
      expect(mockApiRequest).toHaveBeenCalledWith("/v2/people/top-clickers", {
        params: { window: 30, page: 1, size: 1000 },
      });
    });
  });

  describe("proofpoint_people_get_user_risk", () => {
    it("requires email and errors without calling the API", async () => {
      const result = await peopleHandler.handleCall("proofpoint_people_get_user_risk", {});
      expect(result.isError).toBe(true);
      expect(mockApiRequest).not.toHaveBeenCalled();
    });

    it("URL-encodes the email into the path and sends window as a param", async () => {
      mockApiRequest.mockResolvedValue({ riskScore: 42 });

      const result = await peopleHandler.handleCall("proofpoint_people_get_user_risk", {
        email: "user+test@example.com",
        window: 14,
      });

      expect(mockApiRequest).toHaveBeenCalledWith(
        "/v2/people/user%2Btest%40example.com",
        { params: { window: 14 } }
      );
      expect(JSON.parse(result.content[0].text)).toEqual({ riskScore: 42 });
    });
  });

  it("unknown tool returns isError without calling the API", async () => {
    const result = await peopleHandler.handleCall("proofpoint_people_bogus", {});
    expect(result.isError).toBe(true);
    expect(mockApiRequest).not.toHaveBeenCalled();
  });
});
