export type AuthSessionState =
  | "unconfigured"
  | "anonymous"
  | "needs_enrollment"
  | "needs_challenge"
  | "authenticated";

export interface AuthSessionResponse {
  state: AuthSessionState;
  configured: boolean;
  csrfToken: string;
  user?: {
    id: string;
    email: string | null;
  };
  message?: string;
}

export interface ApiSpecObservation {
  ruleId: string;
  operationKey: string | null;
  pointer: string;
  category: string;
  impact: string;
  confidence: string;
  validationLevel: "SPEC_OBSERVATION";
  reviewRequired: true;
  explanation: string;
  remediation: string;
}

export interface ApiSpecCoverage {
  ruleId: string;
  revision: string;
  status: string;
  applicableOperations: number;
  matches: number;
  reason: string | null;
}

export interface ApiSpecAssessmentResponse {
  runId: string;
  classification: "SPEC_ONLY" | "INVENTORY_ONLY";
  source: {
    filename: string | null;
    format: string;
    fingerprint: string;
  };
  operationCount: number;
  findings: ApiSpecObservation[];
  coverage: ApiSpecCoverage[];
  warnings: string[];
  limitations: string[];
  reviewRequired: true;
}

export interface ApiHealthResponse {
  status: "ok";
  service: "lumicsec-api";
  version: string;
}
