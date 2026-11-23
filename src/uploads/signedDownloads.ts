
import { createHmac, timingSafeEqual } from "node:crypto";

const SIGNED_DOWNLOAD_TTL_SECONDS = 5 * 60;

export function createSignedDownloadPath(
  signingKey: Buffer,
  fileId: number,
  nowSeconds: number = currentUnixTime(),
): string {
  const expires = nowSeconds + SIGNED_DOWNLOAD_TTL_SECONDS;
  const signature = signDownload(signingKey, fileId, expires);

  return `/files/${fileId}/signed-download?expires=${expires}&signature=${signature}`;
}

export function verifySignedDownload(
  signingKey: Buffer,
  fileId: number,
  expiresValue: string,
  signature: string,
  nowSeconds: number = currentUnixTime(),
): boolean {
  // Validate expiration and signature format
  if (!/^\d+$/.test(expiresValue) || !/^[a-f0-9]{64}$/.test(signature)) {
    return false;
  }

  // Check whether the URL has expired
  const expires = Number(expiresValue);

  if (!Number.isSafeInteger(expires) || expires <= nowSeconds) {
    return false;
  }

  // Convert the provided signature to a buffer
  const providedBuffer = Buffer.from(signature, "hex");

  // Generate the expected signature
  const expectedSignature = signDownload(signingKey, fileId, expires);
  const expectedBuffer = Buffer.from(expectedSignature, "hex");

  // Ensure buffer lengths match
  if (providedBuffer.length !== expectedBuffer.length) {
    return false;
  }

  // Compare signatures securely
  return timingSafeEqual(providedBuffer, expectedBuffer);
}

function signDownload(
  signingKey: Buffer,
  fileId: number,
  expires: number,
): string {
  const payload = `GET\n/files/${fileId}/signed-download\n${expires}`;

  return createHmac("sha256", signingKey)
    .update(payload)
    .digest("hex");
}

function currentUnixTime(): number {
  return Math.floor(Date.now() / 1000);
}
