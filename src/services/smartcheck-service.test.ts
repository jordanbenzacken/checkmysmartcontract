import { analyzeContract } from "./smartcheck-service";
import { vi } from "vitest";

// Mock Supabase
vi.mock("../lib/supabase", () => ({
  supabase: {
    auth: {
      getUser: vi.fn().mockResolvedValue({ data: { user: null } }),
    },
    from: vi.fn().mockReturnValue({
      insert: vi.fn().mockResolvedValue({ data: null, error: null }),
      select: vi.fn().mockReturnValue({
        order: vi.fn().mockResolvedValue({ data: [], error: null }),
      }),
    }),
  },
}));

describe("SmartCheck Service", () => {
  describe("analyzeContract", () => {
    it("should handle empty input", async () => {
      const results = await analyzeContract("");
      expect(results).toHaveLength(1);
      expect(results[0].severity).toBe("error");
      expect(results[0].message).toBe("Invalid source code provided");
    });

    it("should handle invalid input type", async () => {
      // @ts-expect-error - Testing invalid input
      const results = await analyzeContract(null);
      expect(results).toHaveLength(1);
      expect(results[0].severity).toBe("error");
      expect(results[0].message).toBe("Invalid source code provided");
    });

    it("should detect missing contract declaration", async () => {
      const code = `
        pragma solidity ^0.8.0;
        uint public value;
      `;
      const results = await analyzeContract(code);
      expect(results).toHaveLength(1);
      expect(results[0].severity).toBe("error");
      expect(results[0].message).toBe("No contract declaration found");
    });

    it("should detect public state variable without getter", async () => {
      const code = `
        pragma solidity ^0.8.0;
        contract Test {
          uint public value;
        }
      `;
      const results = await analyzeContract(code);
      expect(results).toHaveLength(1);
      expect(results[0].severity).toBe("low");
      expect(results[0].message).toBe("Public state variable without getter");
    });

    it("should not flag constant public state variables", async () => {
      const code = `
        pragma solidity ^0.8.0;
        contract Test {
          uint public constant value = 100;
        }
      `;
      const results = await analyzeContract(code);
      expect(results).toHaveLength(1);
      expect(results[0].severity).toBe("info");
      expect(results[0].message).toBe("No issues found");
    });

    it("should detect public function without state mutability", async () => {
      const code = `
        pragma solidity ^0.8.0;
        contract Test {
          function test() public {
            // some code
          }
        }
      `;
      const results = await analyzeContract(code);
      expect(results).toHaveLength(1);
      expect(results[0].severity).toBe("medium");
      expect(results[0].message).toBe(
        "Public function without state mutability specifier"
      );
    });
  });
});
