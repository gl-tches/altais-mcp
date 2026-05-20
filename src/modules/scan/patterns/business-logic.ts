// Business-logic flaw patterns: trusting request-supplied values for prices,
// privileged fields (mass assignment), object access (IDOR), and discounts.
//
// These are heuristic detectors. A business-logic flaw cannot be proven by
// pattern matching alone, so findings are medium severity and flag code that
// warrants a manual review.

import type { Pattern } from "./types.js";

const REFS_BUSINESS_LOGIC = [
  "https://cwe.mitre.org/data/definitions/840.html",
  "https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability",
];
const REFS_IDOR = ["https://cwe.mitre.org/data/definitions/639.html", "OWASP Top 10 2025 A01"];
const REFS_MASS_ASSIGNMENT = [
  "https://cwe.mitre.org/data/definitions/915.html",
  "https://cwe.mitre.org/data/definitions/799.html",
  "OWASP Top 10 2025 A04",
];
const REFS_TRUST_BOUNDARY = [
  "https://cwe.mitre.org/data/definitions/602.html",
  "https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability",
];

export const BUSINESS_LOGIC_PATTERNS: readonly Pattern[] = [
  {
    id: "business-logic-price-from-request-js",
    category: "business-logic",
    title: "Price or amount taken directly from request input",
    description:
      "A monetary or quantity field (price, amount, total, cost, quantity, subtotal) is read straight from `req.body`/`req.query`/`req.params` and used without re-deriving it server-side. An attacker can submit an arbitrary value and pay any price they choose.",
    severity: "medium",
    cwe: ["CWE-602", "CWE-840"],
    remediation:
      "Never trust client-supplied prices or totals. Look up the authoritative price from the product catalog server-side and recompute the total from quantities you validate.",
    references: REFS_TRUST_BOUNDARY,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex:
        /\breq\.(?:body|query|params)\s*(?:\.\s*(?:price|amount|total|subtotal|cost|quantity|qty|balance)\b|\[\s*["'](?:price|amount|total|subtotal|cost|quantity|qty|balance)["']\s*\])/i,
    },
  },
  {
    id: "business-logic-price-from-request-py",
    category: "business-logic",
    title: "Price or amount taken directly from request input (Python)",
    description:
      "A monetary or quantity value is read straight from `request.json`, `request.form`, `request.data`, or `request.args` and used as-is. Client-supplied prices and totals must be treated as untrusted.",
    severity: "medium",
    cwe: ["CWE-602", "CWE-840"],
    remediation:
      "Recompute prices and totals from server-side catalog data. Only accept item identifiers and quantities from the client, then validate the quantities.",
    references: REFS_TRUST_BOUNDARY,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex:
        /\brequest\.(?:json|form|data|args|values|POST|GET)\b(?:\.get\s*\(\s*["']|\s*\[\s*["'])(?:price|amount|total|subtotal|cost|quantity|qty|balance)["']/i,
    },
  },
  {
    id: "business-logic-mass-assignment-privileged-field-js",
    category: "business-logic",
    title: "Mass assignment of a privileged field from request input",
    description:
      "A privileged field such as `role`, `isAdmin`, `is_admin`, `permissions`, or `verified` is assigned directly from `req.body`. An attacker can escalate privileges by adding that key to the request payload.",
    severity: "high",
    cwe: ["CWE-915", "CWE-799"],
    remediation:
      "Never copy privileged attributes from request input. Allowlist the exact fields a client may set, and manage role/permission changes through a separate authorized code path.",
    references: REFS_MASS_ASSIGNMENT,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex:
        /\breq\.(?:body|query|params)\s*(?:\.\s*(?:role|roles|isAdmin|is_admin|admin|isSuperuser|is_superuser|permissions|privileges|verified|isVerified|accountType|account_type)\b|\[\s*["'](?:role|roles|isAdmin|is_admin|admin|isSuperuser|is_superuser|permissions|privileges|verified|isVerified|accountType|account_type)["']\s*\])/,
    },
  },
  {
    id: "business-logic-mass-assignment-spread-js",
    category: "business-logic",
    title: "Whole request body spread into a database create/update",
    description:
      "The entire `req.body` is spread or passed into a database `create`/`update`/`save` call. Any field the attacker adds to the payload — including privileged ones — is persisted (mass assignment / over-posting).",
    severity: "high",
    cwe: ["CWE-915", "CWE-799"],
    remediation:
      "Construct the persisted object from an explicit allowlist of fields. Use `pick`/`select` helpers or a validated DTO instead of spreading `req.body`.",
    references: REFS_MASS_ASSIGNMENT,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex:
        /\.(?:create|update|updateOne|updateMany|findOneAndUpdate|insert|insertOne|save|bulkCreate|set)\s*\(\s*(?:\{\s*\.\.\.\s*req\.body\b|req\.body\s*[,)])/,
    },
  },
  {
    id: "business-logic-idor-find-by-request-id-js",
    category: "business-logic",
    title: "Record fetched by a request-supplied id with no ownership check",
    description:
      "A record is loaded with `findById`/`findOne` using an id taken straight from `req.params`/`req.query`/`req.body`. Without a scoping condition tied to the authenticated user, this is an Insecure Direct Object Reference (IDOR).",
    severity: "medium",
    cwe: ["CWE-639"],
    remediation:
      "Scope the lookup to the current principal — e.g. `findOne({ _id: id, ownerId: req.user.id })` — or perform an explicit authorization check after loading the record.",
    references: REFS_IDOR,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex:
        /\.(?:findById|findByPk|findByIdAndUpdate|findByIdAndDelete)\s*\(\s*req\.(?:params|query|body)\b|\.findOne\s*\(\s*\{\s*(?:_?id)\s*:\s*req\.(?:params|query|body)\b/,
    },
  },
  {
    id: "business-logic-idor-orm-get-by-request-id-py",
    category: "business-logic",
    title: "ORM record fetched by request-supplied id with no ownership check (Python)",
    description:
      "A Django/SQLAlchemy record is loaded via `objects.get(id=request...)` or `query.get(request...)` using a request-supplied id. Without filtering by the authenticated owner this is an IDOR.",
    severity: "medium",
    cwe: ["CWE-639"],
    remediation:
      "Filter the queryset by the current user — e.g. `Model.objects.get(id=pk, owner=request.user)` — or use `get_object_or_404` with an ownership-scoped queryset.",
    references: REFS_IDOR,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex:
        /\.objects\.(?:get|filter)\s*\(\s*(?:pk|id)\s*=\s*request\.|\.query\.get\s*\(\s*request\./,
    },
  },
  {
    id: "business-logic-unvalidated-discount-js",
    category: "business-logic",
    title: "Client-controlled discount or coupon applied without validation",
    description:
      "A discount, coupon, or promo value comes from request input and is applied directly to a price or total. If the coupon code or discount percentage is not validated server-side, an attacker can grant themselves arbitrary discounts.",
    severity: "medium",
    cwe: ["CWE-840", "CWE-602"],
    remediation:
      "Resolve coupon codes against a server-side store, verify they are active and applicable, and compute the discount server-side. Never accept a discount amount or percentage straight from the client.",
    references: REFS_BUSINESS_LOGIC,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex:
        /\breq\.(?:body|query|params)\s*(?:\.\s*(?:discount|discountPercent|discountPercentage|coupon|couponCode|promo|promoCode|voucher)\b|\[\s*["'](?:discount|discountPercent|discountPercentage|coupon|couponCode|promo|promoCode|voucher)["']\s*\])/i,
    },
  },
];
