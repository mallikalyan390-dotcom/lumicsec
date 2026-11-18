import { z } from "zod";

export const MAX_SPEC_BYTES = 1_048_576;

export const mfaCodeSchema = z.string().regex(/^[0-9]{6}$/, "Enter the six-digit authenticator code.");

// Supabase Auth JS already returns a complete SVG image data URL.
// Never concatenate another prefix or URI-encode the returned QR string.
export function isTrustedTotpQrImageDataUrl(value: unknown): value is string {
  if (typeof value !== "string" || value.length < 40 || value.length > 100_000 || /[\r\n\0]/.test(value)) {
    return false;
  }

  const match = /^data:image\/svg\+xml;(utf-8|charset=utf-8|base64),/i.exec(value);
  if (!match) {
    return false;
  }

  const payload = value.slice(match[0].length);
  return match[1]?.toLowerCase() === "base64"
    ? /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(payload)
    : (payload.startsWith("<svg") || payload.startsWith("<?xml") || /^%3c(?:svg|%3fxml)/i.test(payload));
}


export const apiSpecAssessmentRequestSchema = z.object({
  content: z.string().min(1, "Specification content is required."),
  filename: z.string().max(255).optional(),
}).strict();

export type ApiSpecAssessmentRequest = z.infer<typeof apiSpecAssessmentRequestSchema>;

export const organizationCreateSchema = z.object({
  displayName: z.string().trim().min(2).max(160),
}).strict();

export const organizationIdQuerySchema = z.object({
  organizationId: z.uuid(),
}).strict();

export const assetCreateSchema = z.object({
  organizationId: z.uuid(),
  kind: z.enum(["website", "api"]),
  displayName: z.string().trim().min(2).max(160),
  origin: z.string().trim().min(10).max(253),
}).strict();

export type OrganizationCreateRequest = z.infer<typeof organizationCreateSchema>;
export type AssetCreateRequest = z.infer<typeof assetCreateSchema>;
