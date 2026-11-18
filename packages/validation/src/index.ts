import { z } from "zod";

export const MAX_SPEC_BYTES = 1_048_576;

export const mfaCodeSchema = z.string().regex(/^[0-9]{6}$/, "Enter the six-digit authenticator code.");

export const apiSpecAssessmentRequestSchema = z.object({
  content: z.string().min(1, "Specification content is required."),
  filename: z.string().max(255).optional(),
}).strict();

export type ApiSpecAssessmentRequest = z.infer<typeof apiSpecAssessmentRequestSchema>;
