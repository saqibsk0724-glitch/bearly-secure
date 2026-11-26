
import { hash, timingSafeEqual } from "node:crypto";
import argon2 from "argon2";

const PASSWORD_HASH_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19 * 1024,
  timeCost: 2,
  parallelism: 1,
} as const;

export const MAX_PASSWORD_LENGTH = 128;

const LEGACY_SHA256_PATTERN = /^[a-f0-9]{64}$/i;

export async function hashPassword(
  password: string,
): Promise<string> {
  if (password.length > MAX_PASSWORD_LENGTH) {
    throw new RangeError(
      `Password must not exceed ${MAX_PASSWORD_LENGTH} characters`,
    );
  }

  return argon2.hash(password , PASSWORD_HASH_OPTIONS);
}

export async function verifyPassword(
  password: string,
  passwordHash: string,
): Promise<boolean> {
  if (password.length > MAX_PASSWORD_LENGTH) {
    return false;
  }

  // Support existing SHA-256 password hashes.
  if (LEGACY_SHA256_PATTERN.test(passwordHash)) {
    const candidateHash = Buffer.from(
      hash("sha256", password, "hex"),
      "hex",
    );

    const storedHash = Buffer.from(passwordHash, "hex");

    return timingSafeEqual(candidateHash, storedHash);
  }

  // Verify modern Argon2id password hashes.
  if (passwordHash.startsWith("$argon2id$")) {
    try {
      return await argon2.verify(passwordHash, password);
    } catch {
      return false;
    }
  }

  // Reject unsupported or malformed hashes.
  return false;
}

export function passwordNeedsRehash(
  passwordHash: string,
): boolean {
  if (/^[a-f0-9]{64}$/i.test(passwordHash)) {
    return true;
  }

  if (!passwordHash.startsWith("$argon2id$")) {
    return false;
  }

  try {
    return argon2.needsRehash(
      passwordHash,
      PASSWORD_HASH_OPTIONS,
    );
  } catch {
    return false;
  }
}
