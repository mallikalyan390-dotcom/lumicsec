/* Authorized, bounded report projection and actual PDF generator.
 * Never include raw HTTP requests, cookie values, bearer headers, imported
 * spec bodies, unverifiable CVE/CVSS, or fabricated risk claims.
 */
import { PDFDocument, StandardFonts, rgb } from "pdf-lib";

export type ReportAsset = Readonly<{
  id: string; display_name: string; canonical_origin: string; asset_kind: string;
}>;
export type ReportFinding = Readonly<{
  id: string; asset_id: string; assessment_kind: string; rule_id: string;
  title: string; summary: string; remediation: string | null;
  source_classification: string; severity_estimate: string;
  reviewer_conclusion: string; review_reason: string | null;
  workflow_status: string; first_seen_at: string; last_seen_at: string;
  source_locator: string; assigned_to: string | null;
}>;
export type ReportEvidence = Readonly<{
  finding_id: string; job_id: string; observation_id: string;
  scope_hash: string | null; source_fingerprint: string | null;
  evidence_source: { fingerprints?: string[]; paths?: string[] } | null;
}>;
export type ReportEvent = Readonly<{
  finding_id: string; actor_id: string; event_type: string;
  occurred_at: string; details: Record<string,unknown>;
}>;
export type ReportRetest = Readonly<{
  finding_id: string; requested_at: string; compared_at: string | null;
  comparison_state: string; comparison_job_id: string | null;
}>;
export type ReportJob = Readonly<{
  id: string; asset_id: string; assessment_kind: string; job_state: string;
  requested_at: string; scope_hash: string | null;
  result_coverage: Record<string,unknown> | null;
  web_report: Record<string,unknown> | null;
}>;
export type SecurityReport = Readonly<{
  classification: "TENANT_AUTHORIZED_REVIEW_REPORT";
  generatedAt: string;
  organization: { id: string; displayName: string };
  scope: { assetId: string | null; scopeDescription: string };
  disclaimer: string;
  counts: Record<string,number>;
  assets: ReportAsset[];
  findings: ReportFinding[];
  evidence: ReportEvidence[];
  history: ReportEvent[];
  retests: ReportRetest[];
  assessments: ReportJob[];
  limitations: string[];
}>;

const MAX_FINDINGS = 100;
const MAX_PAGES = 60;
const MAX_PDF_BYTES = 1_500_000;
const SECRET_PATTERNS = [
  /\bBearer\s+[A-Za-z0-9._~+/-]{8,}/gi,
  /\b(?:token|password|secret|api[_ -]?key|authorization|cookie)\s*[:=]\s*[^\s,;]{6,}/gi,
  /\b(?:sb_secret_|sk_live_)[A-Za-z0-9_-]{8,}/gi,
  /\beyJ[A-Za-z0-9_-]{40,}(?:\.[A-Za-z0-9_-]{10,}){1,2}/g,
];
export function printableReportText(value: unknown, max = 600): string {
  let output = String(value ?? "").normalize("NFKD");
  for (const pattern of SECRET_PATTERNS) output = output.replace(pattern,"[REDACTED]");
  return [...output].map(char => {
    const code=char.charCodeAt(0);
    return code<32||code===127||code>=128?" ":char;
  }).join("").slice(0,max);
}
export function safeReportProjection(raw: SecurityReport): SecurityReport {
  if (raw.findings.length > MAX_FINDINGS || raw.evidence.length > 300 ||
    raw.history.length > 400 || raw.retests.length > 200 ||
    raw.assessments.length > 60 || raw.assets.length > 30)
    throw Error("REPORT_RESOURCE_LIMIT_EXCEEDED");
  const scrub = (value: unknown): unknown => {
    if (typeof value === "string") return printableReportText(value, 1_000);
    if (Array.isArray(value)) return value.map(scrub);
    if (value !== null && typeof value === "object")
      return Object.fromEntries(Object.entries(value).map(([k,v]) => [k,scrub(v)]));
    return value;
  };
  return scrub(raw) as SecurityReport;
}

export async function generateSecurityReportPdf(report: SecurityReport): Promise<Uint8Array> {
  const r = safeReportProjection(report);
  const doc = await PDFDocument.create();
  doc.setTitle("LumicSec | Evidence-backed Security Findings");
  doc.setAuthor("LumicSec");
  doc.setSubject("Tenant-scoped assessment evidence and remediation review");
  const regular = await doc.embedFont(StandardFonts.Helvetica);
  const bold = await doc.embedFont(StandardFonts.HelveticaBold);
  const width = 595, height = 842, margin = 45;
  let page = doc.addPage([width,height]);
  let y=height-54;
  let printedPages=1;
  const ink = rgb(0.09,0.17,0.28), blue=rgb(0.02,0.40,0.61);
  const gray=rgb(0.32,0.39,0.49);
  function nextPage() {
    if (printedPages >= MAX_PAGES) throw Error("REPORT_PAGE_LIMIT_EXCEEDED");
    page=doc.addPage([width,height]); printedPages++; y=height-52;
    page.drawText("LumicSec  |  Security review report (continued)",{
      x:margin,y:y,size:10,font:bold,color:blue,
    }); y-=32;
  }
  function line(value: unknown, opts: { size?: number; strong?: boolean; color?: typeof ink; indent?: number }={}) {
    const size=opts.size??10;
    const font=opts.strong?bold:regular;
    const x=margin+(opts.indent??0);
    const maxWidth=width-x-margin;
    const words=printableReportText(value,1100).split(/\s+/);
    let segment="";
    const segments:string[]=[];
    for(const word of words) {
      if(!word)continue;
      if(font.widthOfTextAtSize(word,size)>maxWidth) {
        if(segment){segments.push(segment);segment="";}
        let part="";
        for(const char of word) {
          if(font.widthOfTextAtSize(part+char,size)>maxWidth) {
            if(part)segments.push(part);
            part=char;
          } else part+=char;
        }
        segment=part;
      } else if(font.widthOfTextAtSize(segment?segment+" "+word:word,size)>maxWidth) {
        segments.push(segment);segment=word;
      }else segment=segment?segment+" "+word:word;
    }
    if(segment)segments.push(segment);
    if(!segments.length)segments.push(" ");
    for(const chunk of segments) {
      if(y<margin+35)nextPage();
      page.drawText(chunk,{x,y,size,font,color:opts.color??ink});
      y-=size+5;
    }
  }
  function heading(title:string) {
    if(y<margin+85)nextPage();
    y-=12;line(title,{size:14,strong:true,color:blue});y-=5;
  }
  // Cover / report assurance.
  page.drawRectangle({ x:0,y:height-135,width,height:135,color:ink });
  page.drawText("LUMICSEC", {x:margin,y:height-76,size:30,font:bold,color:rgb(0.75,0.94,0.99)});
  page.drawText("Evidence-backed security findings",{
    x:margin,y:height-108,size:13,font:regular,color:rgb(0.90,0.94,0.98),
  });
  y=height-164;
  line("Organization: "+r.organization.displayName,{size:14,strong:true});
  line("Scope: "+r.scope.scopeDescription);
  line("Generated UTC: "+r.generatedAt);
  line("Review classification: "+r.classification,{size:9,color:gray});
  heading("Executive summary");
  line("Retained findings: "+r.findings.length
    +" | Open: "+(r.counts["open"]??0)
    +" | Review required: "+(r.counts["unreviewed"]??0)
    +" | In remediation: "+(r.counts["in_progress"]??0));
  for(const severity of ["high","medium","low","info"]) {
    line("Severity estimate "+severity.toUpperCase()+": "+(r.counts[severity]??0));
  }
  line("All severity labels are estimates. Human review is required; no saved passive or offline specification signal proves exploitability.",{size:9,color:gray});
  heading("Asset and assessment scope");
  if(!r.assets.length)line("No saved authorized assets in this scope.");
  for(const asset of r.assets) {
    line(asset.display_name+" ["+asset.asset_kind+"]",{strong:true});
    line(asset.canonical_origin+" | Asset "+asset.id,{size:9});
  }
  if(!r.assessments.length)line("No saved assessment jobs available.");
  for(const job of r.assessments) {
    line(job.assessment_kind+" | "+job.job_state+" | "+job.requested_at,{size:9});
    line("Assessment "+job.id+" | Scope SHA256 "+(job.scope_hash??"not saved"),{size:8,color:gray});
    const limitations=job.assessment_kind==="web_passive"
      ? job.web_report?.["limitations"] : job.result_coverage?.["limitations"];
    if(Array.isArray(limitations)) {
      for(const item of limitations.slice(0,4))line("Coverage limitation: "+String(item),{size:8,color:gray});
    }
  }
  heading("Findings by estimated severity and workflow");
  if(!r.findings.length)line("No imported findings exist. Import saved authorized observations to begin review. This is not proof of a secure asset.");
  const byRank={high:0,medium:1,low:2,info:3};
  const ordered=[...r.findings].sort((a,b)=>
    (byRank[a.severity_estimate as keyof typeof byRank]??4) -
    (byRank[b.severity_estimate as keyof typeof byRank]??4) ||
    a.workflow_status.localeCompare(b.workflow_status));
  let groupKey="";
  for(const finding of ordered) {
    const key=finding.severity_estimate.toUpperCase()+" / "+finding.workflow_status;
    if(groupKey!==key){heading("Estimated "+key+" findings");groupKey=key;}
    heading(finding.rule_id+" | "+finding.title);
    line("Estimated severity: "+finding.severity_estimate+" | Reviewer decision: "+
      finding.reviewer_conclusion+" | Remediation status: "+finding.workflow_status,
      {size:9,strong:true});
    line("Evidence type: "+finding.source_classification+" | Asset "+finding.asset_id,{size:8});
    line("Observed: "+finding.summary);
    line("Remediation guidance: "+(finding.remediation??"Review the source evidence and system configuration."));
    line("Observed locator: "+finding.source_locator,{size:9});
    if(finding.review_reason) line("Reviewer rationale: "+finding.review_reason,{size:9});
    for(const link of r.evidence.filter(e=>e.finding_id===finding.id).slice(0,8)) {
      line("Source observation: "+link.observation_id+" | Assessment "+link.job_id,{size:8});
      line("Scope SHA256: "+(link.scope_hash??"not recorded")
        +" | Source fingerprint: "+(link.source_fingerprint??"not recorded"),{size:8});
      for(const hash of (link.evidence_source?.fingerprints??[]).slice(0,3))
        line("Captured evidence SHA256: "+hash,{size:8,color:gray});
    }
    for(const event of r.history.filter(e=>e.finding_id===finding.id).slice(0,12)) {
      line("Audit "+event.occurred_at+" | "+event.event_type+" | Reviewer "+event.actor_id,
        {size:8,color:gray});
      if(event.event_type==="commented")
        line("Comment: "+String((event.details["input"] as Record<string,unknown> | undefined)?.["message"]??""),{size:8});
    }
    for(const retest of r.retests.filter(t=>t.finding_id===finding.id).slice(0,6))
      line("Retest "+retest.requested_at+" | "+retest.comparison_state
        +" | Assessment "+(retest.comparison_job_id??"awaiting authorized evidence"),{size:8});
  }
  heading("Coverage, assurance and disclosure limitations");
  for(const limit of r.limitations)line("- "+limit,{size:9});
  line(r.disclaimer,{size:9,strong:true});
  // Print page numbers into safe footer area on all pages.
  doc.getPages().forEach((p,index)=>{
    p.drawLine({start:{x:margin,y:38},end:{x:width-margin,y:38},
      thickness:0.5,color:gray});
    p.drawText("LumicSec  |  Confidential tenant review  |  Page "+(index+1)+"/"+printedPages,
      {x:margin,y:23,size:8,font:regular,color:gray});
  });
  const bytes=await doc.save({useObjectStreams:false});
  if(bytes.length>MAX_PDF_BYTES)throw Error("REPORT_RESOURCE_LIMIT_EXCEEDED");
  return bytes;
}
