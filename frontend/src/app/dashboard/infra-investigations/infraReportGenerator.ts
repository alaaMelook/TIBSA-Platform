/**
 * Premium SOC-Style PDF report generator for Threat Infrastructure Intelligence investigations.
 * Uses jsPDF to compile complex threat intelligence data into an elegant, high-impact PDF layout.
 * Optimized with high-contrast Slate-900 typography and conditional section rendering (hiding empty sections).
 */
import jsPDF from "jspdf";
import { InfraInvestigation, InfraInvestigationResults, ThreatIndicatorCheck } from "@/types/infra_investigation";

function getSeverityColor(score: number): [number, number, number] {
  if (score >= 75) return [220, 38, 38];     // Red (Critical/High)
  if (score >= 40) return [217, 119, 6];     // Amber (Medium)
  return [22, 163, 74];                      // Emerald (Low/Clean)
}

function getIndicatorColor(severity: string): [number, number, number] {
  switch (severity.toLowerCase()) {
    case "critical":
    case "high":
      return [220, 38, 38];
    case "medium":
      return [217, 119, 6];
    case "low":
      return [37, 99, 235]; // Blue
    default:
      return [15, 23, 42]; // Slate 900
  }
}

/**
 * Clean and sanitize string to prevent jsPDF built-in fonts encoding errors
 */
function sanitize(text: string | null | undefined): string {
  if (!text) return "N/A";
  return String(text)
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201C\u201D]/g, '"')
    .replace(/\u2013/g, "-")
    .replace(/\u2014/g, "--")
    .replace(/\u2026/g, "...")
    .replace(/\u2022/g, "-")
    .replace(/\u00b7/g, "-")
    .replace(/[^\x00-\xFF]/g, "")
    .trim();
}

export function generateInfraPDFReport(
  investigation: InfraInvestigation
) {
  const results = investigation.results;
  if (!results) return;

  const doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
  const pageW = doc.internal.pageSize.getWidth();
  const pageH = doc.internal.pageSize.getHeight();
  const margin = 20;
  const contentW = pageW - margin * 2;
  let y = 20;
  let currentSectionIndex = 1;

  const addPage = () => {
    doc.addPage();
    y = 20;
  };

  const checkPage = (need: number) => {
    if (y + need > 265) {
      addPage();
    }
  };

  const riskLabel = results.risk?.risk_label || "Clean";
  const riskColor = getSeverityColor(investigation.risk_score);

  // ───────────────────────────────────────────────────────────────────────────
  // SECTION 1: COVER PAGE
  // ───────────────────────────────────────────────────────────────────────────
  
  // Upper slate branding banner
  doc.setFillColor(15, 23, 42); // Slate 900
  doc.rect(0, 0, pageW, 95, "F");

  // Cyan brand accent bar
  doc.setFillColor(6, 182, 212); // Cyan 500
  doc.rect(0, 95, pageW, 4, "F");

  // Logo / Branding text (High-contrast white)
  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(32);
  doc.text("TIBSA", margin, 38);
  
  doc.setFontSize(11);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(103, 114, 229); // Cyber Indigo
  doc.text("THREAT INTELLIGENCE PORTAL", margin, 46);

  // Document Title (High-contrast bold white)
  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(23);
  const titleLines = doc.splitTextToSize("THREAT INFRASTRUCTURE INVESTIGATION REPORT", contentW - 20);
  doc.text(titleLines, margin, 62);

  // Target Information Highlight Card
  y = 110;
  doc.setFillColor(248, 250, 252); // Slate 50
  doc.setDrawColor(226, 232, 240); // Slate 200
  doc.setLineWidth(0.6);
  doc.roundedRect(margin, y, contentW, 48, 2, 2, "FD");

  // Risk Rating badge inside metadata card
  doc.setFillColor(riskColor[0], riskColor[1], riskColor[2]);
  doc.roundedRect(pageW - margin - 44, y + 10, 36, 12, 1.5, 1.5, "F");
  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.text(riskLabel.toUpperCase(), pageW - margin - 26, y + 18, { align: "center" });

  doc.setFontSize(8.5);
  doc.setTextColor(100, 116, 139); // Slate 500 for low importance labels
  doc.text("SECURITY CLASSIFICATION", pageW - margin - 26, y + 28, { align: "center" });
  doc.setFont("helvetica", "bold");
  doc.setTextColor(15, 23, 42); // Slate 900
  doc.text("TLP:AMBER", pageW - margin - 26, y + 33, { align: "center" });

  // Metadata items (High-contrast Slate-900)
  doc.setTextColor(15, 23, 42);
  doc.setFontSize(11.5);
  
  doc.setFont("helvetica", "bold");
  doc.text("Target IOC:", margin + 8, y + 11);
  doc.setFont("courier", "bold");
  doc.setFontSize(12);
  doc.text(sanitize(investigation.target), margin + 38, y + 11);

  doc.setFont("helvetica", "bold");
  doc.setFontSize(11.5);
  doc.text("IOC Type:", margin + 8, y + 20);
  doc.setFont("helvetica", "normal");
  doc.text(investigation.target_type.toUpperCase(), margin + 38, y + 20);

  doc.setFont("helvetica", "bold");
  doc.text("Record ID:", margin + 8, y + 29);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10.5);
  doc.text(sanitize(investigation.id), margin + 38, y + 29);

  doc.setFont("helvetica", "bold");
  doc.setFontSize(11.5);
  doc.text("Generated:", margin + 8, y + 38);
  doc.setFont("helvetica", "normal");
  doc.text(new Date().toUTCString(), margin + 38, y + 38);

  // Section divider line
  y = 175;
  doc.setDrawColor(203, 213, 225); // Slate 300
  doc.setLineWidth(0.4);
  doc.line(margin, y, pageW - margin, y);

  // Subtitle / Abstract (High-contrast text)
  y = 188;
  doc.setTextColor(15, 23, 42); // Slate 900
  doc.setFont("helvetica", "bold");
  doc.setFontSize(13.5);
  doc.text("REPORT ABSTRACT & OBJECTIVE", margin, y);
  
  y += 7;
  doc.setFont("helvetica", "normal");
  doc.setFontSize(11.5);
  doc.setTextColor(30, 41, 59); // Slate 800 for high-contrast paragraph
  const abstractText = 
    "This automated forensic dossier compiles domain, IP, WHOIS, reputation metrics, SSL credentials, DNS layouts, " +
    "and correlation matrices for the requested indicator. The findings represent a composite security posture built from live " +
    "global threat databases and heuristic risk engines. Action items and indicators contained herein are restricted to authorised SOC personnel.";
  const abstractLines = doc.splitTextToSize(abstractText, contentW);
  doc.text(abstractLines, margin, y);

  // Forensic stamps / Bottom visual blocks
  y = 240;
  doc.setFillColor(241, 245, 249);
  doc.rect(margin, y, contentW, 28, "F");
  
  doc.setFont("helvetica", "bold");
  doc.setFontSize(10.5);
  doc.setTextColor(15, 23, 42);
  doc.text("TIBSA CYBER INTELLIGENCE SUITE", margin + 6, y + 8);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  doc.setTextColor(30, 41, 59);
  doc.text("Analyst Operator: System Orchestrated AI Pipeline", margin + 6, y + 14);
  doc.text("Platform Version: TIBSA v1.8.4 (Active Threat Intel Mode)", margin + 6, y + 20);

  // Cyber decorations
  doc.setFillColor(6, 182, 212);
  doc.rect(pageW - margin - 15, y + 6, 8, 8, "F");
  doc.setFillColor(15, 23, 42);
  doc.rect(pageW - margin - 25, y + 12, 8, 8, "F");

  addPage();

  // ───────────────────────────────────────────────────────────────────────────
  // SECTION 2: EXECUTIVE SUMMARY (AI GENERATED)
  // ───────────────────────────────────────────────────────────────────────────
  const aiSummary = results.ai_summary?.executive_summary;
  if (aiSummary && !results.ai_summary?.error) {
    doc.setTextColor(15, 23, 42); // Slate 900
    doc.setFont("helvetica", "bold");
    doc.setFontSize(15);
    doc.text(`${currentSectionIndex++}. EXECUTIVE AI THREAT BRIEFING`, margin, y);
    
    doc.setFillColor(riskColor[0], riskColor[1], riskColor[2]);
    doc.rect(margin, y + 3, 30, 1.2, "F");
    y += 9;

    const summaryLines = doc.splitTextToSize(sanitize(aiSummary), contentW - 14);
    
    doc.setFillColor(250, 250, 250);
    doc.setDrawColor(226, 232, 240);
    const cardH = summaryLines.length * 5.5 + 10;
    doc.roundedRect(margin, y, contentW, cardH, 1, 1, "FD");

    // Left solid visual accent band
    doc.setFillColor(riskColor[0], riskColor[1], riskColor[2]);
    doc.rect(margin, y, 2.5, cardH, "F");

    doc.setTextColor(15, 23, 42); // High-contrast Slate 900 text
    doc.setFont("helvetica", "normal");
    doc.setFontSize(11);
    doc.text(summaryLines, margin + 8, y + 7);
    y += cardH + 12;
  }

  // ───────────────────────────────────────────────────────────────────────────
  // SECTION 3: INVESTIGATION OVERVIEW
  // ───────────────────────────────────────────────────────────────────────────
  // We always have target information, so we always show the overview
  checkPage(50);
  doc.setTextColor(15, 23, 42);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(15);
  doc.text(`${currentSectionIndex++}. INVESTIGATION OVERVIEW`, margin, y);
  
  doc.setFillColor(15, 23, 42);
  doc.rect(margin, y + 3, 30, 1.2, "F");
  y += 9;

  doc.setFillColor(248, 250, 252);
  doc.rect(margin, y, contentW, 30, "F");
  
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42); // Strong Slate 900 contrast
  doc.setFont("helvetica", "bold");
  doc.text("PARAMETER", margin + 6, y + 7);
  doc.text("DETAILS / OBSERVATION", margin + 70, y + 7);

  doc.setDrawColor(226, 232, 240);
  doc.line(margin, y + 11, pageW - margin, y + 11);

  doc.setFont("helvetica", "normal");
  doc.setTextColor(15, 23, 42);
  doc.text("Target Identifier", margin + 6, y + 17);
  doc.setFont("courier", "bold");
  doc.text(sanitize(investigation.target), margin + 70, y + 17);
  
  doc.setFont("helvetica", "normal");
  doc.text("Extraction Classification", margin + 6, y + 24);
  doc.text(investigation.target_type.toUpperCase() + " Indicator", margin + 70, y + 24);
  
  y += 36;

  // ───────────────────────────────────────────────────────────────────────────
  // SECTION 4: RISK SCORE & SEVERITY
  // ───────────────────────────────────────────────────────────────────────────
  if (results.risk) {
    checkPage(75);
    doc.setTextColor(15, 23, 42);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(15);
    doc.text(`${currentSectionIndex++}. RISK SCORE & COMPOSITE SEVERITY`, margin, y);
    doc.setFillColor(15, 23, 42);
    doc.rect(margin, y + 3, 30, 1.2, "F");
    y += 9;

    // Risk Gauge Block
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(226, 232, 240);
    doc.roundedRect(margin, y, contentW, 40, 2, 2, "FD");

    doc.setTextColor(15, 23, 42);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(12);
    doc.text(`Composite Score: ${Math.round(investigation.risk_score)} / 100`, margin + 8, y + 10);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text(`Verdict Classification: ${riskLabel.toUpperCase()} SEVERITY THREAT`, margin + 8, y + 16);

    // Draw Horizontal Risk Progress Bar
    const barX = margin + 8;
    const barY = y + 22;
    const barW = contentW - 16;
    const barH = 6;

    doc.setFillColor(226, 232, 240);
    doc.roundedRect(barX, barY, barW, barH, 1, 1, "F");

    // Colored progress fill
    doc.setFillColor(riskColor[0], riskColor[1], riskColor[2]);
    doc.roundedRect(barX, barY, (investigation.risk_score / 100) * barW, barH, 1, 1, "F");

    // Tick labels
    doc.setFontSize(9.5);
    doc.setTextColor(15, 23, 42); // Black ticks
    doc.text("0 (CLEAN)", barX, barY + 11);
    doc.text("40 (MEDIUM)", barX + barW * 0.4, barY + 11, { align: "center" });
    doc.text("75 (HIGH)", barX + barW * 0.75, barY + 11, { align: "center" });
    doc.text("100 (CRITICAL)", barX + barW, barY + 11, { align: "right" });

    y += 48;

    // Sub-metrics Progress Bars side-by-side
    checkPage(35);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(11.5);
    doc.setTextColor(15, 23, 42);
    doc.text("Composite Risk Breakdown Weights:", margin, y);
    y += 7;

    const subW = (contentW - 12) / 3;
    const subBars = [
      { name: "Reputation", val: results.risk.reputation_score, color: [220, 38, 38] },
      { name: "Infrastructure", val: results.risk.infrastructure_score, color: [217, 119, 6] },
      { name: "Phishing Model", val: results.risk.phishing_score, color: [37, 99, 235] }
    ];

    subBars.forEach((sb, idx) => {
      const bx = margin + idx * (subW + 6);
      doc.setFillColor(248, 250, 252);
      doc.roundedRect(bx, y, subW, 20, 1.5, 1.5, "F");

      doc.setFontSize(10);
      doc.setFont("helvetica", "bold");
      doc.setTextColor(15, 23, 42);
      doc.text(sb.name, bx + 5, y + 6);
      doc.text(String(Math.round(sb.val)), bx + subW - 5, y + 6, { align: "right" });

      // Miniature bar
      doc.setFillColor(226, 232, 240);
      doc.rect(bx + 5, y + 10, subW - 10, 3.5, "F");
      doc.setFillColor(sb.color[0], sb.color[1], sb.color[2]);
      doc.rect(bx + 5, y + 10, (sb.val / 100) * (subW - 10), 3.5, "F");
    });
    y += 28;

    // Contributing Factors
    if (results.risk.contributing_factors && results.risk.contributing_factors.length > 0) {
      checkPage(30);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(11.5);
      doc.setTextColor(15, 23, 42);
      doc.text("Identified Threat Contributing Indicators:", margin, y);
      y += 6;

      doc.setFont("helvetica", "normal");
      doc.setFontSize(11);
      doc.setTextColor(15, 23, 42);
      results.risk.contributing_factors.forEach((factor) => {
        checkPage(6);
        doc.setFillColor(217, 119, 6);
        doc.circle(margin + 3, y - 1.2, 1.2, "F");
        doc.text(sanitize(factor), margin + 8, y);
        y += 5.5;
      });
      y += 6;
    }
  }

  // ───────────────────────────────────────────────────────────────────────────
  // SECTION 5: REPUTATION INTELLIGENCE
  // ───────────────────────────────────────────────────────────────────────────
  const rep = results.reputation;
  const hasAbuseIPDB = rep?.abuseipdb && !rep.abuseipdb.error;
  const hasURLhaus = rep?.urlhaus && !rep.urlhaus.error;
  const hasThreatFox = rep?.threatfox && !rep.threatfox.error;
  const hasOTX = rep?.otx && !rep.otx.error;

  if (rep && (hasAbuseIPDB || hasURLhaus || hasThreatFox || hasOTX)) {
    checkPage(50);
    doc.setTextColor(15, 23, 42);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(15);
    doc.text(`${currentSectionIndex++}. THREAT REPUTATION FEED INTELLIGENCE`, margin, y);
    doc.setFillColor(15, 23, 42);
    doc.rect(margin, y + 3, 30, 1.2, "F");
    y += 9;

    // ABUSEIPDB CARD
    if (hasAbuseIPDB && rep.abuseipdb) {
      checkPage(30);
      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(226, 232, 240);
      doc.roundedRect(margin, y, contentW, 25, 1.5, 1.5, "FD");

      doc.setFont("helvetica", "bold");
      doc.setFontSize(11);
      doc.setTextColor(15, 23, 42);
      doc.text("AbuseIPDB Database Audit", margin + 6, y + 6);

      doc.setFont("helvetica", "normal");
      doc.setFontSize(10.5);
      doc.setTextColor(15, 23, 42);
      doc.text(`ISP: ${sanitize(rep.abuseipdb.isp)}`, margin + 6, y + 13);
      doc.text(`Confidence Rating: ${rep.abuseipdb.abuse_confidence_score}%`, margin + 6, y + 19);
      doc.text(`Total Reports: ${rep.abuseipdb.total_reports}`, margin + 90, y + 13);
      doc.text(`Location Country: ${sanitize(rep.abuseipdb.country_code)}`, margin + 90, y + 19);
      y += 30;
    }

    // URLHAUS CARD
    if (hasURLhaus && rep.urlhaus) {
      checkPage(30);
      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(226, 232, 240);
      doc.roundedRect(margin, y, contentW, 25, 1.5, 1.5, "FD");

      doc.setFont("helvetica", "bold");
      doc.setFontSize(11);
      doc.setTextColor(15, 23, 42);
      doc.text("URLhaus Malicious Payload Audit", margin + 6, y + 6);

      doc.setFont("helvetica", "normal");
      doc.setFontSize(10.5);
      doc.setTextColor(15, 23, 42);
      doc.text(`Listing Status: ${rep.urlhaus.query_status === "is_listed" ? "SUSPICIOUS (Listed)" : "Unlisted"}`, margin + 6, y + 13);
      doc.text(`URLs on Host: ${rep.urlhaus.urls_on_this_host?.length || 0}`, margin + 6, y + 19);
      doc.text(`Reference Link: ${sanitize(rep.urlhaus.urlhaus_reference || "None")}`, margin + 90, y + 13);
      y += 30;
    }

    // THREATFOX CARD
    if (hasThreatFox && rep.threatfox) {
      checkPage(30);
      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(226, 232, 240);
      doc.roundedRect(margin, y, contentW, 25, 1.5, 1.5, "FD");

      doc.setFont("helvetica", "bold");
      doc.setFontSize(11);
      doc.setTextColor(15, 23, 42);
      doc.text("ThreatFox IOC Database Audit", margin + 6, y + 6);

      doc.setFont("helvetica", "normal");
      doc.setFontSize(10.5);
      doc.setTextColor(15, 23, 42);
      const isListed = rep.threatfox.query_status === "ok";
      doc.text(`Listing Status: ${isListed ? "ACTIVE SUSPECTED IOC" : "No results"}`, margin + 6, y + 13);
      const firstIoc = rep.threatfox.iocs?.[0];
      doc.text(`Malware Association: ${sanitize(firstIoc?.malware_printable || "None")}`, margin + 6, y + 19);
      doc.text(`First Tracked Seen: ${sanitize(firstIoc?.first_seen || "N/A")}`, margin + 90, y + 13);
      y += 30;
    }

    // ALIENVAULT OTX CARD
    if (hasOTX && rep.otx) {
      checkPage(30);
      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(226, 232, 240);
      doc.roundedRect(margin, y, contentW, 25, 1.5, 1.5, "FD");

      doc.setFont("helvetica", "bold");
      doc.setFontSize(11);
      doc.setTextColor(15, 23, 42);
      doc.text("AlienVault OTX Threat Pulses", margin + 6, y + 6);

      doc.setFont("helvetica", "normal");
      doc.setFontSize(10.5);
      doc.setTextColor(15, 23, 42);
      doc.text(`Total Correlated Pulses: ${rep.otx.pulse_count}`, margin + 6, y + 13);
      const mainPulse = rep.otx.pulses?.[0];
      doc.text(`Primary Associated Pulse: ${sanitize(mainPulse?.name || "None")}`, margin + 6, y + 19);
      y += 30;
    }
  }

  // ───────────────────────────────────────────────────────────────────────────
  // SECTION 6: DNS / WHOIS / SSL ANALYSIS
  // ───────────────────────────────────────────────────────────────────────────
  const enr = results.enrichment;
  const hasDNS = enr?.dns?.records && enr.dns.records.length > 0;
  const hasWHOIS = enr?.whois && !enr.whois.error;
  const hasSSL = enr?.ssl && !enr.ssl.error;

  if (enr && (hasDNS || hasWHOIS || hasSSL)) {
    addPage();
    doc.setTextColor(15, 23, 42);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(15);
    doc.text(`${currentSectionIndex++}. DNS, WHOIS & SSL INFRASTRUCTURE DETAILS`, margin, y);
    doc.setFillColor(15, 23, 42);
    doc.rect(margin, y + 3, 30, 1.2, "F");
    y += 9;

    // DNS RECORDS TABLE
    if (hasDNS && enr.dns) {
      checkPage(50);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(11.5);
      doc.setTextColor(15, 23, 42);
      doc.text("Active DNS Record Layout:", margin, y);
      y += 6;

      doc.setFillColor(241, 245, 249);
      doc.rect(margin, y, contentW, 9, "F");
      doc.setFontSize(10);
      doc.setTextColor(15, 23, 42);
      doc.text("RECORD TYPE", margin + 6, y + 6.5);
      doc.text("VALUE / VALUE MAPPING", margin + 45, y + 6.5);
      doc.text("TTL", margin + contentW - 15, y + 6.5, { align: "right" });
      y += 9.5;

      doc.setFont("helvetica", "normal");
      doc.setFontSize(10);
      doc.setTextColor(15, 23, 42);

      enr.dns.records.slice(0, 8).forEach((record, index) => {
        checkPage(8);
        if (index % 2 === 1) {
          doc.setFillColor(250, 250, 250);
          doc.rect(margin, y, contentW, 7, "F");
        }
        doc.setFont("helvetica", "bold");
        doc.text(record.type, margin + 6, y + 5);
        doc.setFont("courier", "bold");
        doc.setFontSize(9.5);
        doc.text(sanitize(record.value), margin + 45, y + 5);
        doc.setFont("helvetica", "normal");
        doc.setFontSize(10);
        doc.text(String(record.ttl || 3600), margin + contentW - 15, y + 5, { align: "right" });
        y += 7;
      });
      y += 6;
    }

    // WHOIS DETAILS CARD
    if (hasWHOIS && enr.whois) {
      checkPage(50);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(11.5);
      doc.setTextColor(15, 23, 42);
      doc.text("WHOIS Domain Registration Audit:", margin, y);
      y += 6;

      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(226, 232, 240);
      doc.roundedRect(margin, y, contentW, 32, 1.5, 1.5, "FD");

      doc.setFontSize(10.5);
      doc.setTextColor(15, 23, 42);
      doc.setFont("helvetica", "bold");
      doc.text("Registrar Org:", margin + 6, y + 8);
      doc.setFont("helvetica", "normal");
      doc.text(sanitize(enr.whois.registrar || "Unknown"), margin + 36, y + 8);

      doc.setFont("helvetica", "bold");
      doc.text("Creation Date:", margin + 6, y + 16);
      doc.setFont("helvetica", "normal");
      doc.text(sanitize(enr.whois.creation_date), margin + 36, y + 16);

      doc.setFont("helvetica", "bold");
      doc.text("Expiration Date:", margin + 6, y + 24);
      doc.setFont("helvetica", "normal");
      doc.text(sanitize(enr.whois.expiration_date), margin + 36, y + 24);

      doc.setFont("helvetica", "bold");
      doc.text("Domain Age:", margin + 95, y + 8);
      doc.setFont("helvetica", "normal");
      doc.text(`${enr.whois.domain_age_days || 0} days`, margin + 128, y + 8);

      doc.setFont("helvetica", "bold");
      doc.text("Age Suspicious:", margin + 95, y + 16);
      doc.setFont("helvetica", "bold");
      if (enr.whois.is_newly_registered) {
        doc.setTextColor(220, 38, 38);
        doc.text("YES (New Register)", margin + 128, y + 16);
      } else {
        doc.setTextColor(22, 163, 74);
        doc.text("NO (Established)", margin + 128, y + 16);
      }
      y += 38;
    }

    // SSL CERTIFICATE DETAILS
    if (hasSSL && enr.ssl) {
      checkPage(50);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(11.5);
      doc.setTextColor(15, 23, 42);
      doc.text("SSL / TLS Certificate Authentication Details:", margin, y);
      y += 6;

      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(226, 232, 240);
      doc.roundedRect(margin, y, contentW, 32, 1.5, 1.5, "FD");

      doc.setFontSize(10.5);
      doc.setTextColor(15, 23, 42);
      
      doc.setFont("helvetica", "bold");
      doc.text("Subject CN:", margin + 6, y + 8);
      doc.setFont("helvetica", "normal");
      doc.text(sanitize(enr.ssl.subject_cn), margin + 32, y + 8);

      doc.setFont("helvetica", "bold");
      doc.text("Issuer CN:", margin + 6, y + 16);
      doc.setFont("helvetica", "normal");
      doc.text(sanitize(enr.ssl.issuer_cn), margin + 32, y + 16);

      doc.setFont("helvetica", "bold");
      doc.text("Validity:", margin + 6, y + 24);
      doc.setFont("helvetica", "normal");
      doc.text(`From ${sanitize(enr.ssl.not_before?.substring(0,10))} to ${sanitize(enr.ssl.not_after?.substring(0,10))}`, margin + 32, y + 24);

      doc.setFont("helvetica", "bold");
      doc.text("Self-Signed:", margin + 115, y + 8);
      doc.setFont("helvetica", "bold");
      if (enr.ssl.is_self_signed) {
        doc.setTextColor(220, 38, 38);
        doc.text("YES (High Risk)", margin + 138, y + 8);
      } else {
        doc.setTextColor(22, 163, 74);
        doc.text("No", margin + 138, y + 8);
      }

      doc.setFont("helvetica", "bold");
      doc.setTextColor(15, 23, 42);
      doc.text("Is Expired:", margin + 115, y + 16);
      doc.setFont("helvetica", "bold");
      if (enr.ssl.is_expired) {
        doc.setTextColor(220, 38, 38);
        doc.text("YES", margin + 138, y + 16);
      } else {
        doc.setTextColor(22, 163, 74);
        doc.text("No", margin + 138, y + 16);
      }
      y += 38;
    }
  }

  // ───────────────────────────────────────────────────────────────────────────
  // SECTION 7: PASSIVE DNS FINDINGS
  // ───────────────────────────────────────────────────────────────────────────
  const pdns = results.passive_dns;
  if (pdns && pdns.passive_dns && pdns.passive_dns.length > 0) {
    checkPage(60);
    doc.setTextColor(15, 23, 42);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(15);
    doc.text(`${currentSectionIndex++}. HISTORICAL PASSIVE DNS RESOLUTIONS`, margin, y);
    doc.setFillColor(15, 23, 42);
    doc.rect(margin, y + 3, 30, 1.2, "F");
    y += 9;

    doc.setFillColor(241, 245, 249);
    doc.rect(margin, y, contentW, 9, "F");
    doc.setFontSize(10);
    doc.setTextColor(15, 23, 42);
    doc.text("IP RESOLVED IP", margin + 6, y + 6.5);
    doc.text("MAPPED HOSTNAME", margin + 50, y + 6.5);
    doc.text("FIRST SEEN", margin + 115, y + 6.5);
    doc.text("LAST SEEN", margin + 148, y + 6.5);
    y += 9.5;

    doc.setFont("helvetica", "normal");
    doc.setFontSize(10);
    doc.setTextColor(15, 23, 42);

    pdns.passive_dns.slice(0, 12).forEach((entry, index) => {
      checkPage(8);
      if (index % 2 === 1) {
        doc.setFillColor(250, 250, 250);
        doc.rect(margin, y, contentW, 7, "F");
      }
      doc.setFont("courier", "bold");
      doc.text(entry.address, margin + 6, y + 5);
      doc.setFont("helvetica", "normal");
      doc.text(sanitize(entry.hostname), margin + 50, y + 5);
      doc.text(sanitize(entry.first?.substring(0, 10)), margin + 115, y + 5);
      doc.text(sanitize(entry.last?.substring(0, 10)), margin + 148, y + 5);
      y += 7;
    });
    y += 10;
  }

  // ───────────────────────────────────────────────────────────────────────────
  // SECTION 8: THREAT INDICATORS
  // ───────────────────────────────────────────────────────────────────────────
  const indicators = results.threat_indicators;
  if (indicators && indicators.checks && indicators.checks.length > 0) {
    addPage();
    doc.setTextColor(15, 23, 42);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(15);
    doc.text(`${currentSectionIndex++}. HEURISTIC THREAT SIGNAL CHECKS`, margin, y);
    doc.setFillColor(15, 23, 42);
    doc.rect(margin, y + 3, 30, 1.2, "F");
    y += 9;

    doc.setFont("helvetica", "normal");
    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text(`Evaluated Indicators: ${indicators.checks.length} Checks  |  Triggered Threat Indicators: ${indicators.total_triggered}`, margin, y);
    y += 7;

    indicators.checks.forEach((chk) => {
      checkPage(18);
      
      const isTriggered = chk.triggered;
      const borderC = isTriggered ? getIndicatorColor(chk.severity) : [226, 232, 240];
      const bgC = isTriggered ? [254, 242, 242] : [248, 250, 252];

      doc.setFillColor(bgC[0], bgC[1], bgC[2]);
      doc.setDrawColor(borderC[0], borderC[1], borderC[2]);
      doc.setLineWidth(0.4);
      doc.roundedRect(margin, y, contentW, 15, 0.5, 0.5, "FD");

      // Custom bullet indicator
      doc.setFillColor(borderC[0], borderC[1], borderC[2]);
      doc.rect(margin + 5, y + 5.5, 4, 4, "F");

      doc.setFont("helvetica", "bold");
      doc.setFontSize(10.5);
      doc.setTextColor(15, 23, 42);
      doc.text(sanitize(chk.name), margin + 14, y + 6);

      doc.setFont("helvetica", "normal");
      doc.setFontSize(9.5);
      doc.setTextColor(15, 23, 42);
      doc.text(sanitize(chk.description), margin + 14, y + 11);

      // Trigger Badge State right
      doc.setFont("helvetica", "bold");
      doc.setFontSize(10);
      if (isTriggered) {
        doc.setTextColor(220, 38, 38);
        doc.text(`TRIGGERED (${chk.severity.toUpperCase()})`, pageW - margin - 6, y + 9, { align: "right" });
      } else {
        doc.setTextColor(100, 116, 139);
        doc.text("CLEAN", pageW - margin - 6, y + 9, { align: "right" });
      }

      y += 18;
    });
    y += 6;
  }

  // ───────────────────────────────────────────────────────────────────────────
  // SECTION 9: INFRASTRUCTURE CORRELATIONS
  // ───────────────────────────────────────────────────────────────────────────
  const corr = results.correlation;
  if (corr && corr.relationships && corr.relationships.length > 0) {
    checkPage(50);
    doc.setTextColor(15, 23, 42);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(15);
    doc.text(`${currentSectionIndex++}. INFRASTRUCTURE CORRELATION ANALYSIS`, margin, y);
    doc.setFillColor(15, 23, 42);
    doc.rect(margin, y + 3, 30, 1.2, "F");
    y += 9;

    doc.setFont("helvetica", "normal");
    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text(`Correlations Evaluated: ${corr.rules_evaluated} Rules  |  Triggered Relational Clusters: ${corr.rules_triggered}`, margin, y);
    y += 7;

    corr.relationships.forEach((rule) => {
      if (!rule.triggered) return;
      checkPage(30);
      doc.setFillColor(254, 243, 199); // Amber 100
      doc.setDrawColor(245, 158, 11);   // Amber 500
      doc.setLineWidth(0.5);
      doc.roundedRect(margin, y, contentW, 22, 0.5, 0.5, "FD");

      doc.setFont("helvetica", "bold");
      doc.setFontSize(11);
      doc.setTextColor(146, 64, 14); // Dark Amber
      doc.text(`RULE: ${sanitize(rule.rule_name)}`, margin + 6, y + 6);

      doc.setFont("helvetica", "normal");
      doc.setFontSize(10);
      doc.setTextColor(120, 53, 4);
      doc.text(`Relationship: ${sanitize(rule.relationship_type)}  |  Correlation Confidence: ${rule.confidence.toUpperCase()}`, margin + 6, y + 12);
      
      const evStr = rule.evidence?.join("; ") || "";
      const evLines = doc.splitTextToSize(`Evidence: ${evStr}`, contentW - 16);
      doc.text(evLines, margin + 6, y + 18);

      y += 26;
    });
    y += 6;
  }

  // ───────────────────────────────────────────────────────────────────────────
  // SECTION 10: IOC RELATIONSHIP GRAPH (TEXT TREE MAP)
  // ───────────────────────────────────────────────────────────────────────────
  const graph = results.graph;
  if (graph && graph.nodes && graph.nodes.length > 0) {
    addPage();
    doc.setTextColor(15, 23, 42);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(15);
    doc.text(`${currentSectionIndex++}. IOC STRUCTURAL CORRELATION GRAPH TREE`, margin, y);
    doc.setFillColor(15, 23, 42);
    doc.rect(margin, y + 3, 30, 1.2, "F");
    y += 9;

    doc.setFont("helvetica", "normal");
    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text("Mapping structural links, resolved hosts, ASNs, and registrar nodes:", margin, y);
    y += 7;

    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(226, 232, 240);
    
    const logLines: string[] = [];
    const targetNode = graph.nodes.find(n => n.type === "target") || graph.nodes[0];
    
    if (targetNode) {
      logLines.push(`[TARGET] ${targetNode.label} (${targetNode.risk_level.toUpperCase()} severity)`);
      
      const childEdges = graph.edges.filter(e => e.source === targetNode.id);
      childEdges.forEach((edge, idx) => {
        const isLast = idx === childEdges.length - 1;
        const branch = isLast ? " └── " : " ├── ";
        const childNode = graph.nodes.find(n => n.id === edge.target);
        
        if (childNode) {
          logLines.push(`${branch}${edge.relationship.toUpperCase()} -> ${childNode.label} [Node: ${childNode.type.toUpperCase()}]`);
          
          const gEdges = graph.edges.filter(ge => ge.source === childNode.id);
          gEdges.forEach((ge, gIdx) => {
            const gIsLast = gIdx === gEdges.length - 1;
            const gIndent = isLast ? "      " : " │    ";
            const gBranch = gIsLast ? "└── " : "├── ";
            const gNode = graph.nodes.find(n => n.id === ge.target);
            if (gNode) {
              logLines.push(`${gIndent}${gBranch}${ge.relationship.toUpperCase()}: ${gNode.label} (${gNode.type.toUpperCase()})`);
            }
          });
        }
      });
    }

    const consoleBoxH = logLines.length * 5.5 + 10;
    checkPage(consoleBoxH + 12);
    doc.roundedRect(margin, y, contentW, consoleBoxH, 1, 1, "FD");

    doc.setFont("courier", "bold");
    doc.setFontSize(10); // Very clear high-contrast monospace text
    doc.setTextColor(15, 23, 42); // Black text
    
    logLines.forEach((line, index) => {
      doc.text(sanitize(line), margin + 6, y + 7 + index * 5.5);
    });
    
    y += consoleBoxH + 12;
  }

  // ───────────────────────────────────────────────────────────────────────────
  // SECTION 11: RECOMMENDATIONS & MITIGATIONS
  // ───────────────────────────────────────────────────────────────────────────
  const actions = results.ai_summary?.recommended_actions || [];
  const hasActions = actions.length > 0;

  if (hasActions) {
    checkPage(60);
    doc.setTextColor(15, 23, 42);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(15);
    doc.text(`${currentSectionIndex++}. REMEDIATION & PREVENTIVE MITIGATIONS`, margin, y);
    doc.setFillColor(15, 23, 42);
    doc.rect(margin, y + 3, 30, 1.2, "F");
    y += 9;

    actions.forEach((action, i) => {
      checkPage(18);
      
      doc.setFillColor(241, 245, 249);
      doc.roundedRect(margin, y, contentW, 14, 0.5, 0.5, "F");

      doc.setFillColor(15, 23, 42);
      doc.rect(margin + 4, y + 4, 6, 6, "F");
      doc.setTextColor(255, 255, 255);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(9.5);
      doc.text(`${i + 1}`, margin + 7, y + 8.5, { align: "center" });

      doc.setTextColor(15, 23, 42); // High-contrast black
      doc.setFont("helvetica", "normal");
      doc.setFontSize(10.5);
      const actLines = doc.splitTextToSize(sanitize(action), contentW - 20);
      doc.text(actLines, margin + 14, y + 8.2);

      y += 18;
    });
    y += 6;
  }

  // ───────────────────────────────────────────────────────────────────────────
  // SECTION 12: APPENDIX (RAW TECHNICAL DATA)
  // ───────────────────────────────────────────────────────────────────────────
  // Appendix raw data block is always drawn at the end
  checkPage(45);
  doc.setTextColor(15, 23, 42);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(15);
  doc.text(`${currentSectionIndex++}. APPENDIX: RAW CORRELATED DATA STAMPS`, margin, y);
  doc.setFillColor(15, 23, 42);
  doc.rect(margin, y + 3, 30, 1.2, "F");
  y += 9;

  const appData = [
    `CRITICALITY LEVEL   : ${riskLabel.toUpperCase()}`,
    `SCAN TIME DURATION  : DISPATCHED SYSTEM PIPELINE`,
    `GEOLOCATION CODE    : ${sanitize(enr?.geoip?.country_code || "US")} (${sanitize(enr?.geoip?.org || "ISP Cloud")})`,
    `ASN RESOLVED VALUE  : ${sanitize(enr?.geoip?.asn || "N/A")}`,
    `REGISTRY EXPIRE DATE: ${sanitize(enr?.whois?.expiration_date || "N/A")}`,
    `SSL ENCRYPT SUBJECT : ${sanitize(enr?.ssl?.subject_cn || "N/A")}`
  ];

  const appBoxH = appData.length * 5.5 + 10;
  checkPage(appBoxH + 6);
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  doc.roundedRect(margin, y, contentW, appBoxH, 1, 1, "FD");

  doc.setFont("courier", "bold");
  doc.setFontSize(10);
  doc.setTextColor(15, 23, 42); // High-contrast black raw logs
  
  appData.forEach((line, index) => {
    doc.text(sanitize(line), margin + 6, y + 7 + index * 5.5);
  });

  // ───────────────────────────────────────────────────────────────────────────
  // POST PASS: HEADERS, FOOTERS & PAGE NUMBERS
  // ───────────────────────────────────────────────────────────────────────────
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    
    // Header & Footer only on Subsequent Pages
    if (i > 1) {
      doc.setDrawColor(241, 245, 249);
      doc.setLineWidth(0.25);
      doc.line(margin, 14, pageW - margin, 14);

      doc.setFontSize(9.5);
      doc.setFont("helvetica", "normal");
      doc.setTextColor(100, 116, 139);
      doc.text("TIBSA CYBER INTELLIGENCE PORTAL", margin, 10);
      
      const headerTarget = `Target: ${investigation.target.toUpperCase()}`;
      doc.text(sanitize(headerTarget), pageW - margin, 10, { align: "right" });

      doc.text("CLASSIFICATION: TLP:AMBER | TIBSA HIGH-POSTURE INTEL", margin, 287);
      doc.text(`Page ${i} of ${pageCount}`, pageW - margin, 287, { align: "right" });
    } else {
      doc.setFontSize(10);
      doc.setFont("helvetica", "bold");
      doc.setTextColor(100, 116, 139);
      doc.text("RESTRICTED REPORT - CLASSIFICATION: TLP:AMBER", pageW / 2, 285, { align: "center" });
    }
  }

  // Save the PDF
  const safeName = investigation.target.replace(/[^a-zA-Z0-9_.-]/g, "_");
  doc.save(`TIBSA_SOC_Infra_Report_${safeName}_${new Date().toISOString().slice(0, 10)}.pdf`);
}
