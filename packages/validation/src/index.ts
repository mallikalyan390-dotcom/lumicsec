import { z } from "zod";

export const MAX_SPEC_BYTES = 1_048_576;

export const mfaCodeSchema = z.string().regex(/^[0-9]{6}$/, "Enter the six-digit authenticator code.");

export {
  isTrustedTotpQrImageDataUrl, isTrustedTotpPngDataUrl,
  normalizeTotpSvgQrDataUrl, totpQrFormatMetadata,
} from "./totp-qr.js";

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


// Organization RBAC and asset-proof inputs. Unknown fields are rejected.
export const organizationPathSchema = z.object({ organizationId: z.uuid() }).strict();
export const invitationPathSchema = organizationPathSchema.extend({ invitationId: z.uuid() }).strict();
export const memberPathSchema = organizationPathSchema.extend({ userId: z.uuid() }).strict();
export const organizationInviteSchema = z.object({
  email: z.email().max(254).transform((email) => email.trim().toLowerCase()),
  role: z.enum(["admin", "member"]),
}).strict();
export const invitationAcceptSchema = z.object({
  token: z.string().regex(/^[a-f0-9]{64}$/),
}).strict();
export const memberRoleSchema = z.object({
  role: z.enum(["owner", "admin", "member"]),
}).strict();
export const assetVerificationIssueSchema = z.object({
  organizationId: z.uuid(), assetId: z.uuid(),
  method: z.enum(["dns_txt", "https_file"]),
}).strict();
export const assetVerificationCheckSchema = z.object({
  organizationId: z.uuid(), assetId: z.uuid(), challengeId: z.uuid(),
}).strict();
export const assetVerificationRevokeSchema = z.object({
  organizationId: z.uuid(), assetId: z.uuid(),
}).strict();
export const assetVerificationListSchema = assetVerificationRevokeSchema;
