// Shared types for the threat-model module.

export type ComponentType =
  | "user"
  | "browser"
  | "api"
  | "service"
  | "database"
  | "queue"
  | "cache"
  | "storage"
  | "external"
  | "auth"
  | "function"
  | "other";

export const COMPONENT_TYPES: readonly ComponentType[] = [
  "user",
  "browser",
  "api",
  "service",
  "database",
  "queue",
  "cache",
  "storage",
  "external",
  "auth",
  "function",
  "other",
];

export interface Component {
  readonly name: string;
  readonly type: ComponentType;
  readonly description?: string;
  readonly trust_zone?: string;
  readonly handles_pii?: boolean;
  readonly authenticates_clients?: boolean;
}

export interface DataFlow {
  readonly from: string;
  readonly to: string;
  readonly data: string;
  readonly protocol?: string;
  readonly auth?: string;
  readonly encrypted?: boolean;
}

export interface TrustBoundary {
  readonly name: string;
  readonly description?: string;
}

export interface Architecture {
  readonly components: readonly Component[];
  readonly data_flows?: readonly DataFlow[];
  readonly trust_boundaries?: readonly TrustBoundary[];
}

export type StrideCategory =
  | "spoofing"
  | "tampering"
  | "repudiation"
  | "information_disclosure"
  | "denial_of_service"
  | "elevation_of_privilege";

export const STRIDE_CATEGORIES: readonly StrideCategory[] = [
  "spoofing",
  "tampering",
  "repudiation",
  "information_disclosure",
  "denial_of_service",
  "elevation_of_privilege",
];

export interface ThreatTemplate {
  readonly category: StrideCategory;
  readonly description: string;
  readonly mitigation: string;
  readonly cwe: readonly string[];
}
