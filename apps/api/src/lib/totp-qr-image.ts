import QRCode from "qrcode";

// Local-only QR encoding. No requests leave the API process. The provisioning
// URI is ephemeral, contains the TOTP secret, and must never reach logs.
const MAX_DATA_URL_CHARS = 120_000;
const MIN_SECRET_LENGTH = 16;
const MAX_SECRET_LENGTH = 128;

export function createTotpProvisioningUri(secret: unknown, accountLabel?: string): string | null {
  if (typeof secret !== "string" || secret.length > MAX_SECRET_LENGTH + 8) return null;

  const normalizedSecret = secret.replace(/[ \t\r\n]/g, "").replace(/=+$/, "").toUpperCase();
  if (normalizedSecret.length < MIN_SECRET_LENGTH || normalizedSecret.length > MAX_SECRET_LENGTH
    || !/^[A-Z2-7]+$/.test(normalizedSecret)) return null;

  const normalizedLabel = typeof accountLabel === "string" && accountLabel.length <= 120
    && /^[A-Za-z0-9+_.@-]+$/.test(accountLabel)
    ? accountLabel
    : "Authenticator";
  const label = `LumicSec:${normalizedLabel}`;
  const uri = new URL(`otpauth://totp/${encodeURIComponent(label)}`);
  uri.searchParams.set("secret", normalizedSecret);
  uri.searchParams.set("issuer", "LumicSec");
  uri.searchParams.set("algorithm", "SHA1");
  uri.searchParams.set("digits", "6");
  uri.searchParams.set("period", "30");
  const result = uri.toString();
  return result.length <= 512 ? result : null;
}

export async function createTotpQrPngDataUrl(secret: unknown, accountLabel?: string): Promise<string | null> {
  const uri = createTotpProvisioningUri(secret, accountLabel);
  if (!uri) return null;

  try {
    const imageUrl = await QRCode.toDataURL(uri, {
      type: "image/png",
      errorCorrectionLevel: "M",
      width: 256,
      margin: 4,
      color: { dark: "#000000FF", light: "#FFFFFFFF" },
    });
    return imageUrl.length <= MAX_DATA_URL_CHARS && imageUrl.startsWith("data:image/png;base64,")
      ? imageUrl
      : null;
  } catch {
    // Do not expose the URI or library exception in logs or API responses.
    return null;
  }
}
