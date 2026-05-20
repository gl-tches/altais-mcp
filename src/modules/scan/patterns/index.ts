// Aggregate every scan pattern in declaration order so the engine can
// iterate them deterministically.

import { BUSINESS_LOGIC_PATTERNS } from "./business-logic.js";
import { CACHE_POISONING_PATTERNS } from "./cache-poisoning.js";
import { CRLF_INJECTION_PATTERNS } from "./crlf-injection.js";
import { DESERIALIZATION_PATTERNS } from "./deserialization.js";
import { EXCEPTIONAL_CONDITIONS_PATTERNS } from "./exceptional-conditions.js";
import { HOST_HEADER_INJECTION_PATTERNS } from "./host-header-injection.js";
import { INJECTION_PATTERNS } from "./injection.js";
import { PATH_TRAVERSAL_PATTERNS } from "./path-traversal.js";
import { PROTOTYPE_POLLUTION_PATTERNS } from "./prototype-pollution.js";
import { RACE_CONDITION_PATTERNS } from "./race-condition.js";
import { REDOS_PATTERNS } from "./redos.js";
import { REQUEST_SMUGGLING_PATTERNS } from "./request-smuggling.js";
import { SSRF_PATTERNS } from "./ssrf.js";
import { SSTI_PATTERNS } from "./ssti.js";
import { XSS_PATTERNS } from "./xss.js";
import type { Pattern } from "./types.js";

export const ALL_PATTERNS: readonly Pattern[] = [
  ...INJECTION_PATTERNS,
  ...XSS_PATTERNS,
  ...SSRF_PATTERNS,
  ...PATH_TRAVERSAL_PATTERNS,
  ...EXCEPTIONAL_CONDITIONS_PATTERNS,
  ...PROTOTYPE_POLLUTION_PATTERNS,
  ...SSTI_PATTERNS,
  ...REDOS_PATTERNS,
  ...RACE_CONDITION_PATTERNS,
  ...DESERIALIZATION_PATTERNS,
  ...BUSINESS_LOGIC_PATTERNS,
  ...REQUEST_SMUGGLING_PATTERNS,
  ...CACHE_POISONING_PATTERNS,
  ...CRLF_INJECTION_PATTERNS,
  ...HOST_HEADER_INJECTION_PATTERNS,
];

export {
  BUSINESS_LOGIC_PATTERNS,
  CACHE_POISONING_PATTERNS,
  CRLF_INJECTION_PATTERNS,
  DESERIALIZATION_PATTERNS,
  EXCEPTIONAL_CONDITIONS_PATTERNS,
  HOST_HEADER_INJECTION_PATTERNS,
  INJECTION_PATTERNS,
  PATH_TRAVERSAL_PATTERNS,
  PROTOTYPE_POLLUTION_PATTERNS,
  RACE_CONDITION_PATTERNS,
  REDOS_PATTERNS,
  REQUEST_SMUGGLING_PATTERNS,
  SSRF_PATTERNS,
  SSTI_PATTERNS,
  XSS_PATTERNS,
};
