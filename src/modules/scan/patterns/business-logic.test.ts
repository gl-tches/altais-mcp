import { describe, expect, it } from "vitest";
import { runPatterns } from "../engine.js";
import type { Language } from "../languages.js";
import { BUSINESS_LOGIC_PATTERNS } from "./business-logic.js";

function scan(source: string, language: Language): readonly string[] {
  return runPatterns(BUSINESS_LOGIC_PATTERNS, { source, language }).map((f) => f.rule);
}

describe("business-logic patterns - pattern ids", () => {
  it("has unique rule ids", () => {
    const ids = BUSINESS_LOGIC_PATTERNS.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("every pattern carries a real CWE", () => {
    for (const p of BUSINESS_LOGIC_PATTERNS) {
      expect(p.cwe.length).toBeGreaterThan(0);
      expect(p.references.length).toBeGreaterThan(0);
    }
  });
});

describe("business-logic patterns - price trust", () => {
  describe("positives", () => {
    it("flags a price read from req.body", () => {
      const rules = scan(`const total = req.body.price * qty;`, "javascript");
      expect(rules).toContain("business-logic-price-from-request-js");
    });

    it("flags an amount read via bracket access", () => {
      const rules = scan(`const a = req.query["amount"];`, "javascript");
      expect(rules).toContain("business-logic-price-from-request-js");
    });

    it("flags a Python amount from request.json", () => {
      const rules = scan(`amount = request.json["amount"]`, "python");
      expect(rules).toContain("business-logic-price-from-request-py");
    });

    it("flags a Python total via request.form.get", () => {
      const rules = scan(`total = request.form.get("total")`, "python");
      expect(rules).toContain("business-logic-price-from-request-py");
    });
  });

  describe("negatives", () => {
    it("does not flag a server-derived price", () => {
      const rules = scan(`const total = product.price * qty;`, "javascript");
      expect(rules.filter((r) => r.startsWith("business-logic-price"))).toEqual([]);
    });

    it("does not flag a non-monetary request field", () => {
      const rules = scan(`const name = req.body.name;`, "javascript");
      expect(rules.filter((r) => r.startsWith("business-logic-price"))).toEqual([]);
    });
  });
});

describe("business-logic patterns - mass assignment", () => {
  describe("positives", () => {
    it("flags req.body.role assignment", () => {
      const rules = scan(`user.role = req.body.role;`, "javascript");
      expect(rules).toContain("business-logic-mass-assignment-privileged-field-js");
    });

    it("flags req.body.isAdmin", () => {
      const rules = scan(`const admin = req.body.isAdmin;`, "javascript");
      expect(rules).toContain("business-logic-mass-assignment-privileged-field-js");
    });

    it("flags spreading req.body into create()", () => {
      const rules = scan(`User.create({ ...req.body });`, "javascript");
      expect(rules).toContain("business-logic-mass-assignment-spread-js");
    });

    it("flags req.body passed straight to update()", () => {
      const rules = scan(`User.update(req.body, { where: { id } });`, "javascript");
      expect(rules).toContain("business-logic-mass-assignment-spread-js");
    });
  });

  describe("negatives", () => {
    it("does not flag an allowlisted create", () => {
      const rules = scan(
        `User.create({ name: req.body.name, email: req.body.email });`,
        "javascript",
      );
      expect(rules).not.toContain("business-logic-mass-assignment-spread-js");
    });

    it("does not flag a non-privileged field", () => {
      const rules = scan(`user.nickname = req.body.nickname;`, "javascript");
      expect(rules).not.toContain("business-logic-mass-assignment-privileged-field-js");
    });
  });
});

describe("business-logic patterns - IDOR", () => {
  describe("positives", () => {
    it("flags findById(req.params.id)", () => {
      const rules = scan(`const doc = await Order.findById(req.params.id);`, "javascript");
      expect(rules).toContain("business-logic-idor-find-by-request-id-js");
    });

    it("flags findOne with id from req.params", () => {
      const rules = scan(`const u = await User.findOne({ id: req.params.id });`, "javascript");
      expect(rules).toContain("business-logic-idor-find-by-request-id-js");
    });

    it("flags Django objects.get(id=request...)", () => {
      const rules = scan(`obj = Invoice.objects.get(id=request.GET["id"])`, "python");
      expect(rules).toContain("business-logic-idor-orm-get-by-request-id-py");
    });
  });

  describe("negatives", () => {
    it("does not flag an ownership-scoped findOne", () => {
      const rules = scan(
        `const u = await User.findOne({ id: id, ownerId: currentUser });`,
        "javascript",
      );
      expect(rules).not.toContain("business-logic-idor-find-by-request-id-js");
    });

    it("does not flag an ownership-scoped Django query", () => {
      const rules = scan(`obj = Invoice.objects.get(id=pk, owner=request.user)`, "python");
      // matches because request. appears, but only the broad rule; the safe
      // case here uses pk not request — confirm no false positive:
      expect(rules).not.toContain("business-logic-idor-orm-get-by-request-id-py");
    });
  });
});

describe("business-logic patterns - discount", () => {
  it("flags a client-supplied discount", () => {
    const rules = scan(`const off = req.body.discount;`, "javascript");
    expect(rules).toContain("business-logic-unvalidated-discount-js");
  });

  it("flags a coupon code from request", () => {
    const rules = scan(`applyCoupon(req.query["couponCode"]);`, "javascript");
    expect(rules).toContain("business-logic-unvalidated-discount-js");
  });

  it("does not flag a server-resolved coupon", () => {
    const rules = scan(`const off = coupon.discount;`, "javascript");
    expect(rules).not.toContain("business-logic-unvalidated-discount-js");
  });
});
