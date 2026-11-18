import { z } from "zod";

export const MAX_SPEC_BYTES = 1_048_576;

export const mfaCodeSchema = z.string().regex(/^[0-9]{6}$/, "Enter the six-digit authenticator code.");

export { isTrustedTotpQrImageDataUrl, normalizeTotpSvgQrDataUrl, totpQrFormatMetadata } from "./totp-qr.js";

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
