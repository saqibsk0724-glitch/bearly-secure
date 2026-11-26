
import { join } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { openDatabase } from "./db/index.ts";
import { loadKeyring, type Keyring } from "./storage/keyring.ts";

export type Dependencies = {
  appOrigin: string;
  port: number;
  databasePath: string;
  acornFulfillmentDelayMs: number;
  maxRequestBodyBytes: number;
  maxUploadBytes: number;
  maxPublicProductResults: number;
  downloadSigningKey: Buffer;
  keyring: Keyring ;
  pawPalApiKey : string;
  db: DatabaseSync;
  trustedProxyHops : number;
};

function requireEnv(
  name: string,
  env: NodeJS.ProcessEnv = process.env,
): string {
  const value = env[name];

  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }

  return value;
}

function parseNonNegativeInteger(value: string, name: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${name} must be a non-negative integer`);
  }
  return parsed;
}

export function initDependencies(
  env: NodeJS.ProcessEnv = process.env,
  cwd: string = process.cwd(),
): Dependencies {
  const port = parseNonNegativeInteger(env.PORT ?? "3000", "PORT");
  if (port > 65_535) {
    throw new Error("PORT must be no greater than 65535");
  }

  const acornFulfillmentDelayMs = Number(env.ACORN_FULFILLMENT_DELAY_MS ?? "0");
  if (
    !Number.isFinite(acornFulfillmentDelayMs) ||
    acornFulfillmentDelayMs < 0
  ) {
    throw new Error("ACORN_FULFILLMENT_DELAY_MS must be a non-negative number");
  }

  const downloadSigningKey = requireEnv("DOWNLOAD_SIGNING_KEY", env);

if (
  downloadSigningKey.length !== 64 ||
  !/^[0-9a-fA-F]{64}$/.test(downloadSigningKey)
) {
  throw new Error(
    "DOWNLOAD_SIGNING_KEY must be exactly 64 hexadecimal characters",
  );
}

  const values = {
    appOrigin: new URL(env.APP_ORIGIN ?? "http://localhost:3000").origin,
    port,
    trustedProxyHops: parseNonNegativeInteger(
      env.TRUST_PROXY_HOPS ?? "0",
      "TRUST_PROXY_HOPS",
    ),
    databasePath: env.DATABASE_URL ?? join(cwd, "data", "bearly-secure.sqlite"),
    acornFulfillmentDelayMs,
    maxRequestBodyBytes: 32 * 1024,
    maxUploadBytes: 1024 * 1024,
    maxPublicProductResults: 50,
    downloadSigningKey: Buffer.from(downloadSigningKey, "hex"),
    pawPalApiKey : requireEnv("PAWPAL_API_KEY" , env),
    keyring: loadKeyring(env),
  };

  return { ...values, db: openDatabase(values.databasePath) };
}
