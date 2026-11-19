-- Offline API-spec observations legitimately have NULL remediation.
-- Preserve NULL rather than inventing scanner guidance or altering source evidence.
-- This corrects the immediately previous new findings-only table; no old data changed.
ALTER TABLE public.security_findings ALTER COLUMN remediation DROP NOT NULL;