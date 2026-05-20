// Typosquat detector.
//
// For each declared dependency, compare its name to a curated list of
// popular packages (by ecosystem). If the edit distance is small (1-2)
// but the name does not match exactly, flag.

import type { Finding, FindingLocation } from "../../core/types.js";
import { findingId } from "../../core/utils.js";
import { levenshtein } from "./semver.js";
import type { DependencyPackage, EcosystemId } from "./types.js";

const POPULAR: Readonly<Record<EcosystemId, readonly string[]>> = {
  npm: [
    "react",
    "vue",
    "angular",
    "lodash",
    "axios",
    "express",
    "next",
    "typescript",
    "tslib",
    "ts-node",
    "vite",
    "webpack",
    "eslint",
    "prettier",
    "moment",
    "dayjs",
    "luxon",
    "chalk",
    "commander",
    "yargs",
    "zod",
    "jest",
    "vitest",
    "mocha",
    "chai",
    "fastify",
    "koa",
    "nestjs",
    "rxjs",
    "redux",
    "graphql",
    "apollo-server",
    "mongoose",
    "sequelize",
    "knex",
    "prisma",
    "ioredis",
    "winston",
    "pino",
    "bcrypt",
    "jsonwebtoken",
    "uuid",
    "nanoid",
    "node-fetch",
    "undici",
    "ws",
  ],
  cargo: [
    "serde",
    "serde_json",
    "tokio",
    "anyhow",
    "thiserror",
    "clap",
    "regex",
    "log",
    "tracing",
    "rand",
    "chrono",
    "reqwest",
    "hyper",
    "axum",
    "tower",
    "diesel",
    "sqlx",
    "rusoto_core",
    "ring",
    "rustls",
    "uuid",
    "syn",
    "quote",
    "proc-macro2",
    "futures",
    "actix-web",
    "rocket",
  ],
  pypi: [
    "requests",
    "urllib3",
    "boto3",
    "botocore",
    "numpy",
    "pandas",
    "scipy",
    "matplotlib",
    "django",
    "flask",
    "fastapi",
    "starlette",
    "sqlalchemy",
    "psycopg2",
    "pymysql",
    "redis",
    "celery",
    "pytest",
    "pyyaml",
    "cryptography",
    "click",
    "jinja2",
    "werkzeug",
    "pydantic",
    "httpx",
    "aiohttp",
    "pillow",
    "scikit-learn",
    "torch",
    "tensorflow",
    "transformers",
    "openai",
    "anthropic",
  ],
  go: [
    "github.com/gin-gonic/gin",
    "github.com/labstack/echo",
    "github.com/spf13/cobra",
    "github.com/spf13/viper",
    "github.com/sirupsen/logrus",
    "go.uber.org/zap",
    "github.com/stretchr/testify",
    "github.com/golang/protobuf",
    "google.golang.org/grpc",
    "golang.org/x/crypto",
    "golang.org/x/net",
    "golang.org/x/sys",
    "github.com/aws/aws-sdk-go",
    "gopkg.in/yaml.v3",
    "github.com/google/uuid",
    "github.com/lib/pq",
    "gorm.io/gorm",
    "github.com/redis/go-redis",
  ],
};

export interface TyposquatHit {
  readonly suspect: string;
  readonly suspect_version: string;
  readonly nearest: string;
  readonly distance: number;
}

export interface TyposquatReport {
  readonly hits: readonly TyposquatHit[];
  readonly findings: readonly Finding[];
}

export function detectTyposquat(
  packages: readonly DependencyPackage[],
  source: string | undefined,
  customPopular?: Readonly<Record<EcosystemId, readonly string[]>>,
): TyposquatReport {
  const hits: TyposquatHit[] = [];
  const findings: Finding[] = [];
  for (const pkg of packages) {
    const candidates = customPopular?.[pkg.ecosystem] ?? POPULAR[pkg.ecosystem];
    if (candidates.includes(pkg.name)) continue; // exact match — popular package
    let best: { name: string; distance: number } | null = null;
    for (const c of candidates) {
      const d = levenshtein(pkg.name, c, 2);
      if (d === null) continue;
      if (d === 0) {
        best = null;
        break;
      }
      if (!best || d < best.distance) best = { name: c, distance: d };
    }
    if (best && best.distance <= 2) {
      hits.push({
        suspect: pkg.name,
        suspect_version: pkg.version,
        nearest: best.name,
        distance: best.distance,
      });
      findings.push(buildFinding(pkg, best.name, best.distance, source));
    }
  }
  return { hits, findings };
}

function buildFinding(
  pkg: DependencyPackage,
  nearest: string,
  distance: number,
  source: string | undefined,
): Finding {
  const location: FindingLocation | undefined =
    source !== undefined ? { file: source, line_start: 1 } : undefined;
  const evidence = `${pkg.name} vs popular package "${nearest}" (distance=${distance})`;
  return {
    id: findingId("supply_chain", "typosquat", location, evidence),
    module: "supply_chain",
    rule: "typosquat-candidate",
    severity: distance === 1 ? "high" : "medium",
    cwe: ["CWE-1357"],
    title: `Possible typosquat: \`${pkg.name}\` close to popular \`${nearest}\``,
    description: `\`${pkg.name}@${pkg.version}\` (${pkg.ecosystem}) is ${distance} character${distance === 1 ? "" : "s"} away from a well-known package. Typosquatted dependencies commonly ship credential exfiltration or backdoors.`,
    ...(location !== undefined ? { location } : {}),
    evidence,
    remediation: `Confirm \`${pkg.name}\` is the dependency you intended. If you meant \`${nearest}\`, replace it and remove the typosquatted package from the lockfile.`,
    references: ["https://cwe.mitre.org/data/definitions/1357.html"],
    tags: ["supply-chain", "typosquat", `ecosystem:${pkg.ecosystem}`],
    status: "open",
  };
}
