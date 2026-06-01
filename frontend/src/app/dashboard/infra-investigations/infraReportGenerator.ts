/**
 * Premium SOC-Style PDF report generator for Threat Infrastructure Intelligence investigations.
 * Uses jsPDF to compile complex threat intelligence data into an elegant, high-impact PDF layout.
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
      return [100, 116, 139]; // Slate
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
    .replace(/[^\x00-\xFF]/g, (char) => {
      // Map common Arabic characters or others to basic latin equivalents if applicable, or strip them
      return "";
    })
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

  const addPage = () => {
    doc.addPage();
    y = 20;
  };

  const checkPage = (need: number) => {
    if (y + need > 270) {
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
  doc.rect(0, 0, pageW, 90, "F");

  // Cyan brand accent bar
  doc.setFillColor(6, 182, 212); // Cyan 500
  doc.rect(0, 90, pageW, 4, "F");

  // Logo / Branding text
  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(28);
  doc.text("TIBSA", margin, 35);
  
  doc.setFontSize(9);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(103, 114, 229); // Cyber Indigo
  doc.text("THREAT INTELLIGENCE PORTAL", margin, 42);

  // Document Title
  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(20);
  const titleLines = doc.splitTextToSize("THREAT INFRASTRUCTURE INVESTIGATION REPORT", contentW - 20);
  doc.text(titleLines, margin, 58);

  // Target Information Highlight Card
  y = 105;
  doc.setFillColor(248, 250, 252); // Slate 50
  doc.setDrawColor(226, 232, 240); // Slate 200
  doc.setLineWidth(0.5);
  doc.roundedRect(margin, y, contentW, 40, 2, 2, "FD");

  // Risk Rating badge inside metadata card
  doc.setFillColor(riskColor[0], riskColor[1], riskColor[2]);
  doc.roundedRect(pageW - margin - 38, y + 8, 30, 10, 1, 1, "F");
  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(9);
  doc.text(riskLabel.toUpperCase(), pageW - margin - 23, y + 14.5, { align: "center" });

  doc.setFontSize(7.5);
  doc.setTextColor(148, 163, 184);
  doc.text("SECURITY CLASSIFICATION", pageW - margin - 23, y + 23, { align: "center" });
  doc.setFont("helvetica", "bold");
  doc.setTextColor(15, 23, 42);
  doc.text("TLP:AMBER", pageW - margin - 23, y + 27, { align: "center" });

  // Metadata items
  doc.setTextColor(15, 23, 42);
  doc.setFontSize(10);
  
  doc.setFont("helvetica", "bold");
  doc.text("Target IOC:", margin + 6, y + 10);
  doc.setFont("helvetica", "normal");
  doc.setFont("courier", "bold");
  doc.setFontSize(9.5);
  doc.text(sanitize(investigation.target), margin + 35, y + 10);

  doc.setFont("helvetica", "bold");
  doc.setFontSize(10);
  doc.text("IOC Type:", margin + 6, y + 18);
  doc.setFont("helvetica", "normal");
  doc.text(investigation.target_type.toUpperCase(), margin + 35, y + 18);

  doc.setFont("helvetica", "bold");
  doc.text("Record ID:", margin + 6, y + 26);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(8.5);
  doc.text(sanitize(investigation.id), margin + 35, y + 26);

  doc.setFont("helvetica", "bold");
  doc.setFontSize(10);
  doc.text("Generated:", margin + 6, y + 34);
  doc.setFont("helvetica", "normal");
  doc.text(new Date().toUTCString(), margin + 35, y + 34);

  // Premium Section divider line
  y = 160;
  doc.setDrawColor(203, 213, 225); // Slate 300
  doc.setLineWidth(0.3);
  doc.line(margin, y, pageW - margin, y);

  // Subtitle / Abstract
  y = 172;
  doc.setTextColor(51, 65, 85); // Slate 700
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.text("REPORT ABSTRACT & OBJECTIVE", margin, y);
  
  y += 6;
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9.5);
  doc.setTextColor(71, 85, 105);
  const abstractText = 
    "This automated forensic dossier compiles domain, IP, WHOIS, reputation metrics, SSL credentials, DNS layouts, " +
    "and correlation matrices for the requested indicator. The findings represent a composite security posture built from live " +
    "global threat databases and heuristic risk engines. Action items and indicators contained herein are restricted to authorised SOC personnel.";
  const abstractLines = doc.splitTextToSize(abstractText, contentW);
  doc.text(abstractLines, margin, y);

  // Forensic stamps / Bottom visual blocks
  y = 230;
  doc.setFillColor(241, 245, 249);
  doc.rect(margin, y, contentW, 26, "F");
  
  doc.setFont("helvetica", "bold");
  doc.setFontSize(9);
  doc.setTextColor(15, 23, 42);
  doc.text("TIBSA CYBER INTELLIGENCE SUITE", margin + 6, y + 8);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(8);
  doc.setTextColor(71, 85, 105);
  doc.text("Analyst Operator: System Orchestrated AI Pipeline", margin + 6, y + 13);
  doc.text("Platform Version: TIBSA v1.8.4 (Active Threat Intel Mode)", margin + 6, y + 18);

  // Draw cyber square decorations
  doc.setFillColor(6, 182, 212);
  doc.rect(pageW - margin - 15, y + 6, 8, 8, "F");
  doc.setFillColor(15, 23, 42);
  doc.rect(pageW - margin - 25, y + 12, 8, 8, "F");

  // Save Cover Page, add page for next sections
  addPage();

  // ───────────────────────────────────────────────────────────────────────────
  // SECTION 2: EXECUTIVE SUMMARY (AI GENERATED)
  // ───────────────────────────────────────────────────────────────────────────
  doc.setTextColor(15, 23, 42);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(13);
  doc.text("1. EXECUTIVE AI THREAT BREIFING", margin, y);
  
  // Custom Visual Bar Accent
  doc.setFillColor(riskColor[0], riskColor[1], riskColor[2]);
  doc.rect(margin, y + 2.5, 30, 1, "F");
  y += 8;

  // AI Summary card box
  const aiSummary = results.ai_summary?.executive_summary || "No executive AI briefing is currently available for this investigation.";
  const summaryLines = doc.splitTextToSize(sanitize(aiSummary), contentW - 12);
  
  doc.setFillColor(250, 250, 250);
  doc.setDrawColor(241, 245, 249);
  const cardH = summaryLines.length * 4.5 + 8;
  doc.roundedRect(margin, y, contentW, cardH, 1, 1, "FD");

  // Left solid visual accent band
  doc.setFillColor(riskColor[0], riskColor[1], riskColor[2]);
  doc.rect(margin, y, 2, cardH, "F");

  doc.setTextColor(51, 65, 85);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.text(summaryLines, margin + 6, y + 6);
  y += cardH + 10;

  // ───────────────────────────────────────────────────────────────────────────
  // SECTION 3: INVESTIGATION OVERVIEW
  // ───────────────────────────────────────────────────────────────────────────
  checkPage(45);
  doc.setTextColor(15, 23, 42);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(13);
  doc.text("2. INVESTIGATION OVERVIEW", margin, y);
  
  doc.setFillColor(15, 23, 42);
  doc.rect(margin, y + 2.5, 30, 1, "F");
  y += 8;

  // Overview Table
  doc.setFillColor(248, 250, 252);
  doc.rect(margin, y, contentW, 25, "F");
  
  doc.setFontSize(8.5);
  doc.setTextColor(100, 116, 139);
  doc.setFont("helvetica", "bold");
  doc.text("PARAMETER", margin + 4, y + 6);
  doc.text("DETAILS / OBSERVATION", margin + 65, y + 6);

  doc.setDrawColor(226, 232, 240);
  doc.line(margin, y + 9, pageW - margin, y + 9);

  doc.setFont("helvetica", "normal");
  doc.setTextColor(51, 65, 85);
  doc.text("Target Identifier", margin + 4, y + 14);
  doc.setFont("courier", "bold");
  doc.text(sanitize(investigation.target), margin + 65, y + 14);
  
  doc.setFont("helvetica", "normal");
  doc.text("Extraction Classification", margin + 4, y + 20);
  doc.text(investigation.target_type.toUpperCase() + " Indicator", margin + 65, y + 20);
  
  y += 28;

  // ───────────────────────────────────────────────────────────────────────────
  // SECTION 4: RISK SCORE & SEVERITY
  // ───────────────────────────────────────────────────────────────────────────
  checkPage(65);
  doc.setTextColor(15, 23, 42);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(13);
  doc.text("3. RISK SCORE & COMPOSITE SEVERITY", margin, y);
  doc.setFillColor(15, 23, 42);
  doc.rect(margin, y + 2.5, 30, 1, "F");
  y += 8;

  // Risk Gauge Block
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  doc.roundedRect(margin, y, contentW, 35, 1.5, 1.5, "FD");

  doc.setTextColor(15, 23, 42);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(10);
  doc.text(`Composite Score: ${Math.round(investigation.risk_score)} / 100`, margin + 6, y + 8);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(8.5);
  doc.setTextColor(71, 85, 105);
  doc.text(`Verdict Classification: ${riskLabel.toUpperCase()} SEVERITY THREAT`, margin + 6, y + 13);

  // Draw Horizontal Risk Progress Bar
  const barX = margin + 6;
  const barY = y + 18;
  const barW = contentW - 12;
  const barH = 5;

  doc.setFillColor(226, 232, 240);
  doc.roundedRect(barX, barY, barW, barH, 1, 1, "F");

  // Colored progress fill
  doc.setFillColor(riskColor[0], riskColor[1], riskColor[2]);
  doc.roundedRect(barX, barY, (investigation.risk_score / 100) * barW, barH, 1, 1, "F");

  // Tick labels
  doc.setFontSize(7.5);
  doc.setTextColor(148, 163, 184);
  doc.text("0 (CLEAN)", barX, barY + 9);
  doc.text("40 (MEDIUM)", barX + barW * 0.4, barY + 9, { align: "center" });
  doc.text("75 (HIGH)", barX + barW * 0.75, barY + 9, { align: "center" });
  doc.text("100 (CRITICAL)", barX + barW, barY + 9, { align: "right" });

  y += 42;

  // Sub-metrics Progress Bars side-by-side
  if (results.risk) {
    checkPage(30);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(9.5);
    doc.setTextColor(51, 65, 85);
    doc.text("Composite Risk Breakdown Weights:", margin, y);
    y += 6;

    const subW = (contentW - 10) / 3;
    const subBars = [
      { name: "Reputation", val: results.risk.reputation_score, color: [220, 38, 38] },
      { name: "Infrastructure", val: results.risk.infrastructure_score, color: [217, 119, 6] },
      { name: "Phishing Model", val: results.risk.phishing_score, color: [37, 99, 235] }
    ];

    subBars.forEach((sb, idx) => {
      const bx = margin + idx * (subW + 5);
      doc.setFillColor(248, 250, 252);
      doc.roundedRect(bx, y, subW, 16, 1, 1, "F");

      doc.setFontSize(8);
      doc.setFont("helvetica", "bold");
      doc.setTextColor(51, 65, 85);
      doc.text(sb.name, bx + 4, y + 5);
      doc.text(String(Math.round(sb.val)), bx + subW - 4, y + 5, { align: "right" });

      // Miniature bar
      doc.setFillColor(226, 232, 240);
      doc.rect(bx + 4, y + 8, subW - 8, 2.5, "F");
      doc.setFillColor(sb.color[0], sb.color[1], sb.color[2]);
      doc.rect(bx + 4, y + 8, (sb.val / 100) * (subW - 8), 2.5, "F");
    });
    y += 24;
  }

  // Contributing Factors
  if (results.risk?.contributing_factors && results.risk.contributing_factors.length > 0) {
    checkPage(25);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(9);
    doc.setTextColor(51, 65, 85);
    doc.text("Identified Threat Contributing Indicators:", margin, y);
    y += 5;

    doc.setFont("helvetica", "normal");
    doc.setFontSize(8.5);
    doc.setTextColor(71, 85, 105);
    results.risk.contributing_factors.forEach((factor) => {
      checkPage(5);
      doc.setFillColor(217, 119, 6);
      doc.circle(margin + 2.5, y - 1, 1, "F");
      doc.text(sanitize(factor), margin + 6, y);
      y += 4.5;
    });
    y += 5;
  }

  // ───────────────────────────────────────────────────────────────────────────
  // SECTION 5: REPUTATION INTELLIGENCE
  // ───────────────────────────────────────────────────────────────────────────
  checkPage(45);
  doc.setTextColor(15, 23, 42);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(13);
  doc.text("4. THREAT REPUTATION FEED INTELLIGENCE", margin, y);
  doc.setFillColor(15, 23, 42);
  doc.rect(margin, y + 2.5, 30, 1, "F");
  y += 8;

  const rep = results.reputation;
  if (rep) {
    // ABUSEIPDB CARD
    if (rep.abuseipdb && !rep.abuseipdb.error) {
      checkPage(25);
      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(226, 232, 240);
      doc.roundedRect(margin, y, contentW, 20, 1, 1, "FD");

      doc.setFont("helvetica", "bold");
      doc.setFontSize(9);
      doc.setTextColor(15, 23, 42);
      doc.text("AbuseIPDB Database Audit", margin + 4, y + 5);

      doc.setFont("helvetica", "normal");
      doc.setFontSize(8);
      doc.setTextColor(71, 85, 105);
      doc.text(`ISP: ${sanitize(rep.abuseipdb.isp)}`, margin + 4, y + 10);
      doc.text(`Confidence Rating: ${rep.abuseipdb.abuse_confidence_score}%`, margin + 4, y + 15);
      doc.text(`Total Reports: ${rep.abuseipdb.total_reports}`, margin + 85, y + 10);
      doc.text(`Location Country: ${sanitize(rep.abuseipdb.country_code)}`, margin + 85, y + 15);
      y += 24;
    }

    // URLHAUS CARD
    if (rep.urlhaus && !rep.urlhaus.error) {
      checkPage(25);
      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(226, 232, 240);
      doc.roundedRect(margin, y, contentW, 20, 1, 1, "FD");

      doc.setFont("helvetica", "bold");
      doc.setFontSize(9);
      doc.setTextColor(15, 23, 42);
      doc.text("URLhaus Malicious Payload Audit", margin + 4, y + 5);

      doc.setFont("helvetica", "normal");
      doc.setFontSize(8);
      doc.setTextColor(71, 85, 105);
      doc.text(`Listing Status: ${rep.urlhaus.query_status === "is_listed" ? "SUSPICIOUS (Listed)" : "Unlisted"}`, margin + 4, y + 10);
      doc.text(`URLs on Host: ${rep.urlhaus.urls_on_this_host?.length || 0}`, margin + 4, y + 15);
      doc.text(`Reference Link: ${sanitize(rep.urlhaus.urlhaus_reference || "None")}`, margin + 85, y + 10);
      y += 24;
    }

    // THREATFOX CARD
    if (rep.threatfox && !rep.threatfox.error) {
      checkPage(25);
      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(226, 232, 240);
      doc.roundedRect(margin, y, contentW, 20, 1, 1, "FD");

      doc.setFont("helvetica", "bold");
      doc.setFontSize(9);
      doc.setTextColor(15, 23, 42);
      doc.text("ThreatFox IOC Database Audit", margin + 4, y + 5);

      doc.setFont("helvetica", "normal");
      doc.setFontSize(8);
      doc.setTextColor(71, 85, 105);
      const isListed = rep.threatfox.query_status === "ok";
      doc.text(`Listing Status: ${isListed ? "ACTIVE SUSPECTED IOC" : "No results"}`, margin + 4, y + 10);
      const firstIoc = rep.threatfox.iocs?.[0];
      doc.text(`Malware Association: ${sanitize(firstIoc?.malware_printable || "None")}`, margin + 4, y + 15);
      doc.text(`First Tracked Seen: ${sanitize(firstIoc?.first_seen || "N/A")}`, margin + 85, y + 10);
      y += 24;
    }

    // ALIENVAULT OTX CARD
    if (rep.otx && !rep.otx.error) {
      checkPage(25);
      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(226, 232, 240);
      doc.roundedRect(margin, y, contentW, 20, 1, 1, "FD");

      doc.setFont("helvetica", "bold");
      doc.setFontSize(9);
      doc.setTextColor(15, 23, 42);
      doc.text("AlienVault OTX Threat Pulses", margin + 4, y + 5);

      doc.setFont("helvetica", "normal");
      doc.setFontSize(8);
      doc.setTextColor(71, 85, 105);
      doc.text(`Total Correlated Pulses: ${rep.otx.pulse_count}`, margin + 4, y + 10);
      const mainPulse = rep.otx.pulses?.[0];
      doc.text(`Primary Associated Pulse: ${sanitize(mainPulse?.name || "None")}`, margin + 4, y + 15);
      y += 24;
    }
  }

  // ───────────────────────────────────────────────────────────────────────────
  // SECTION 6: DNS / WHOIS / SSL ANALYSIS
  // ───────────────────────────────────────────────────────────────────────────
  addPage();
  doc.setTextColor(15, 23, 42);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(13);
  doc.text("5. DNS, WHOIS & SSL INFRASTRUCTURE DETAILS", margin, y);
  doc.setFillColor(15, 23, 42);
  doc.rect(margin, y + 2.5, 30, 1, "F");
  y += 8;

  const enr = results.enrichment;
  if (enr) {
    // DNS RECORDS TABLE
    if (enr.dns?.records && enr.dns.records.length > 0) {
      checkPage(45);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(10);
      doc.setTextColor(51, 65, 85);
      doc.text("Active DNS Record Layout:", margin, y);
      y += 5;

      // Header row
      doc.setFillColor(241, 245, 249);
      doc.rect(margin, y, contentW, 7, "F");
      doc.setFontSize(8.5);
      doc.setTextColor(51, 65, 85);
      doc.text("RECORD TYPE", margin + 4, y + 5);
      doc.text("VALUE / VALUE MAPPING", margin + 40, y + 5);
      doc.text("TTL", margin + contentW - 15, y + 5, { align: "right" });
      y += 7.5;

      doc.setFont("helvetica", "normal");
      doc.setFontSize(8);
      doc.setTextColor(71, 85, 105);

      enr.dns.records.slice(0, 8).forEach((record, index) => {
        checkPage(6);
        if (index % 2 === 1) {
          doc.setFillColor(250, 250, 250);
          doc.rect(margin, y, contentW, 5.5, "F");
        }
        doc.setFont("helvetica", "bold");
        doc.text(record.type, margin + 4, y + 4);
        doc.setFont("courier", "bold");
        doc.setFontSize(7.5);
        doc.text(sanitize(record.value), margin + 40, y + 4);
        doc.setFont("helvetica", "normal");
        doc.setFontSize(8);
        doc.text(String(record.ttl || 3600), margin + contentW - 15, y + 4, { align: "right" });
        y += 5.5;
      });
      y += 5;
    }

    // WHOIS DETAILS CARD
    if (enr.whois && !enr.whois.error) {
      checkPage(45);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(10);
      doc.setTextColor(51, 65, 85);
      doc.text("WHOIS Domain Registration Audit:", margin, y);
      y += 5;

      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(226, 232, 240);
      doc.roundedRect(margin, y, contentW, 26, 1, 1, "FD");

      doc.setFontSize(8.5);
      doc.setTextColor(71, 85, 105);
      doc.setFont("helvetica", "bold");
      doc.text("Registrar Org:", margin + 4, y + 6);
      doc.setFont("helvetica", "normal");
      doc.text(sanitize(enr.whois.registrar || "Unknown"), margin + 32, y + 6);

      doc.setFont("helvetica", "bold");
      doc.text("Creation Date:", margin + 4, y + 12);
      doc.setFont("helvetica", "normal");
      doc.text(sanitize(enr.whois.creation_date), margin + 32, y + 12);

      doc.setFont("helvetica", "bold");
      doc.text("Expiration Date:", margin + 4, y + 18);
      doc.setFont("helvetica", "normal");
      doc.text(sanitize(enr.whois.expiration_date), margin + 32, y + 18);

      doc.setFont("helvetica", "bold");
      doc.text("Domain Age:", margin + 95, y + 6);
      doc.setFont("helvetica", "normal");
      doc.text(`${enr.whois.domain_age_days || 0} days`, margin + 122, y + 6);

      doc.setFont("helvetica", "bold");
      doc.text("Age Suspicious:", margin + 95, y + 12);
      doc.setFont("helvetica", "bold");
      if (enr.whois.is_newly_registered) {
        doc.setTextColor(220, 38, 38);
        doc.text("YES (New Register)", margin + 122, y + 12);
      } else {
        doc.setTextColor(22, 163, 74);
        doc.text("NO (Established)", margin + 122, y + 12);
      }
      y += 32;
    }

    // SSL CERTIFICATE DETAILS
    if (enr.ssl && !enr.ssl.error) {
      checkPage(45);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(10);
      doc.setTextColor(51, 65, 85);
      doc.text("SSL / TLS Certificate Authentication Details:", margin, y);
      y += 5;

      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(226, 232, 240);
      doc.roundedRect(margin, y, contentW, 26, 1, 1, "FD");

      doc.setFontSize(8.5);
      doc.setTextColor(71, 85, 105);
      
      doc.setFont("helvetica", "bold");
      doc.text("Subject CN:", margin + 4, y + 6);
      doc.setFont("helvetica", "normal");
      doc.text(sanitize(enr.ssl.subject_cn), margin + 30, y + 6);

      doc.setFont("helvetica", "bold");
      doc.text("Issuer CN:", margin + 4, y + 12);
      doc.setFont("helvetica", "normal");
      doc.text(sanitize(enr.ssl.issuer_cn), margin + 30, y + 12);

      doc.setFont("helvetica", "bold");
      doc.text("Validity:", margin + 4, y + 18);
      doc.setFont("helvetica", "normal");
      doc.text(`From ${sanitize(enr.ssl.not_before?.substring(0,10))} to ${sanitize(enr.ssl.not_after?.substring(0,10))}`, margin + 30, y + 18);

      doc.setFont("helvetica", "bold");
      doc.text("Self-Signed:", margin + 115, y + 6);
      doc.setFont("helvetica", "bold");
      if (enr.ssl.is_self_signed) {
        doc.setTextColor(220, 38, 38);
        doc.text("YES (High Risk)", margin + 138, y + 6);
      } else {
        doc.setTextColor(22, 163, 74);
        doc.text("No", margin + 138, y + 6);
      }

      doc.setFont("helvetica", "bold");
      doc.setTextColor(71, 85, 105);
      doc.text("Is Expired:", margin + 115, y + 12);
      doc.setFont("helvetica", "bold");
      if (enr.ssl.is_expired) {
        doc.setTextColor(220, 38, 38);
        doc.text("YES", margin + 138, y + 12);
      } else {
        doc.setTextColor(22, 163, 74);
        doc.text("No", margin + 138, y + 12);
      }
      y += 32;
    }
  }

  // ───────────────────────────────────────────────────────────────────────────
  // SECTION 7: PASSIVE DNS FINDINGS
  // ───────────────────────────────────────────────────────────────────────────
  const pdns = results.passive_dns;
  if (pdns && pdns.passive_dns && pdns.passive_dns.length > 0) {
    checkPage(55);
    doc.setTextColor(15, 23, 42);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(13);
    doc.text("6. HISTORICAL PASSIVE DNS RESOLUTIONS", margin, y);
    doc.setFillColor(15, 23, 42);
    doc.rect(margin, y + 2.5, 30, 1, "F");
    y += 8;

    doc.setFillColor(241, 245, 249);
    doc.rect(margin, y, contentW, 7, "F");
    doc.setFontSize(8.5);
    doc.setTextColor(51, 65, 85);
    doc.text("IP RESOLVED IP", margin + 4, y + 5);
    doc.text("MAPPED HOSTNAME", margin + 45, y + 5);
    doc.text("FIRST SEEN", margin + 110, y + 5);
    doc.text("LAST SEEN", margin + 145, y + 5);
    y += 7.5;

    doc.setFont("helvetica", "normal");
    doc.setFontSize(7.5);
    doc.setTextColor(71, 85, 105);

    pdns.passive_dns.slice(0, 12).forEach((entry, index) => {
      checkPage(6);
      if (index % 2 === 1) {
        doc.setFillColor(250, 250, 250);
        doc.rect(margin, y, contentW, 5.5, "F");
      }
      doc.setFont("courier", "bold");
      doc.text(entry.address, margin + 4, y + 4);
      doc.setFont("helvetica", "normal");
      doc.text(sanitize(entry.hostname), margin + 45, y + 4);
      doc.text(sanitize(entry.first?.substring(0, 10)), margin + 110, y + 4);
      doc.text(sanitize(entry.last?.substring(0, 10)), margin + 145, y + 4);
      y += 5.5;
    });
    y += 8;
  }

  // ───────────────────────────────────────────────────────────────────────────
  // SECTION 8: THREAT INDICATORS
  // ───────────────────────────────────────────────────────────────────────────
  const indicators = results.threat_indicators;
  if (indicators && indicators.checks && indicators.checks.length > 0) {
    addPage();
    doc.setTextColor(15, 23, 42);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(13);
    doc.text("7. HEURISTIC THREAT SIGNAL CHECKS", margin, y);
    doc.setFillColor(15, 23, 42);
    doc.rect(margin, y + 2.5, 30, 1, "F");
    y += 8;

    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.setTextColor(71, 85, 105);
    doc.text(`Evaluated Indicators: ${indicators.checks.length} Checks  |  Triggered Threat Indicators: ${indicators.total_triggered}`, margin, y);
    y += 6;

    indicators.checks.forEach((chk) => {
      checkPage(15);
      
      const isTriggered = chk.triggered;
      const borderC = isTriggered ? getIndicatorColor(chk.severity) : [226, 232, 240];
      const bgC = isTriggered ? [254, 242, 242] : [248, 250, 252];

      doc.setFillColor(bgC[0], bgC[1], bgC[2]);
      doc.setDrawColor(borderC[0], borderC[1], borderC[2]);
      doc.setLineWidth(0.4);
      doc.roundedRect(margin, y, contentW, 11, 0.5, 0.5, "FD");

      // Custom bullet indicator
      doc.setFillColor(borderC[0], borderC[1], borderC[2]);
      doc.rect(margin + 4, y + 3.5, 4, 4, "F");

      doc.setFont("helvetica", "bold");
      doc.setFontSize(8.5);
      doc.setTextColor(15, 23, 42);
      doc.text(sanitize(chk.name), margin + 12, y + 4.5);

      doc.setFont("helvetica", "normal");
      doc.setFontSize(7.5);
      doc.setTextColor(100, 116, 139);
      doc.text(sanitize(chk.description), margin + 12, y + 8.5);

      // Trigger Badge State right
      doc.setFont("helvetica", "bold");
      doc.setFontSize(8);
      if (isTriggered) {
        doc.setTextColor(220, 38, 38);
        doc.text(`TRIGGERED (${chk.severity.toUpperCase()})`, pageW - margin - 4, y + 6.5, { align: "right" });
      } else {
        doc.setTextColor(148, 163, 184);
        doc.text("CLEAN", pageW - margin - 4, y + 6.5, { align: "right" });
      }

      y += 13.5;
    });
    y += 5;
  }

  // ───────────────────────────────────────────────────────────────────────────
  // SECTION 9: INFRASTRUCTURE CORRELATIONS
  // ───────────────────────────────────────────────────────────────────────────
  const corr = results.correlation;
  if (corr && corr.relationships && corr.relationships.length > 0) {
    checkPage(45);
    doc.setTextColor(15, 23, 42);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(13);
    doc.text("8. INFRASTRUCTURE CORRELATION ANALYSIS", margin, y);
    doc.setFillColor(15, 23, 42);
    doc.rect(margin, y + 2.5, 30, 1, "F");
    y += 8;

    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.setTextColor(71, 85, 105);
    doc.text(`Correlations Evaluated: ${corr.rules_evaluated} Rules  |  Triggered Relational Clusters: ${corr.rules_triggered}`, margin, y);
    y += 6;

    corr.relationships.forEach((rule) => {
      if (!rule.triggered) return;
      checkPage(25);
      doc.setFillColor(254, 243, 199); // Amber 100
      doc.setDrawColor(245, 158, 11);   // Amber 500
      doc.setLineWidth(0.4);
      doc.roundedRect(margin, y, contentW, 16, 0.5, 0.5, "FD");

      doc.setFont("helvetica", "bold");
      doc.setFontSize(9);
      doc.setTextColor(146, 64, 14); // Dark Amber
      doc.text(`RULE: ${sanitize(rule.rule_name)}`, margin + 4, y + 5);

      doc.setFont("helvetica", "normal");
      doc.setFontSize(8);
      doc.setTextColor(120, 53, 4);
      doc.text(`Relationship: ${sanitize(rule.relationship_type)}  |  Correlation Confidence: ${rule.confidence.toUpperCase()}`, margin + 4, y + 10);
      
      const evStr = rule.evidence?.join("; ") || "";
      const evLines = doc.splitTextToSize(`Evidence: ${evStr}`, contentW - 12);
      doc.text(evLines, margin + 4, y + 14);

      y += 18.5;
    });
    y += 5;
  }

  // ───────────────────────────────────────────────────────────────────────────
  // SECTION 10: IOC RELATIONSHIP GRAPH (TEXT TREE MAP)
  // ───────────────────────────────────────────────────────────────────────────
  const graph = results.graph;
  if (graph && graph.nodes && graph.nodes.length > 0) {
    addPage();
    doc.setTextColor(15, 23, 42);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(13);
    doc.text("9. IOC STRUCTURAL CORRELATION GRAPH TREE", margin, y);
    doc.setFillColor(15, 23, 42);
    doc.rect(margin, y + 2.5, 30, 1, "F");
    y += 8;

    doc.setFont("helvetica", "normal");
    doc.setFontSize(8.5);
    doc.setTextColor(71, 85, 105);
    doc.text("Mapping structural links, resolved hosts, ASNs, and registrar nodes:", margin, y);
    y += 5;

    // Draw tree output inside a console block
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(226, 232, 240);
    
    // Construct structural mapping logs from nodes & edges
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
          
          // Grandchildren nodes mapping
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

    const consoleBoxH = logLines.length * 4.5 + 8;
    checkPage(consoleBoxH + 10);
    doc.roundedRect(margin, y, contentW, consoleBoxH, 1, 1, "FD");

    doc.setFont("courier", "bold");
    doc.setFontSize(8);
    doc.setTextColor(51, 65, 85);
    
    logLines.forEach((line, index) => {
      doc.text(sanitize(line), margin + 4, y + 6 + index * 4.5);
    });
    
    y += consoleBoxH + 10;
  }

  // ───────────────────────────────────────────────────────────────────────────
  // SECTION 11: RECOMMENDATIONS & MITIGATIONS
  // ───────────────────────────────────────────────────────────────────────────
  checkPage(55);
  doc.setTextColor(15, 23, 42);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(13);
  doc.text("10. REMEDIATION & PREVENTIVE MITIGATIONS", margin, y);
  doc.setFillColor(15, 23, 42);
  doc.rect(margin, y + 2.5, 30, 1, "F");
  y += 8;

  const actions = results.ai_summary?.recommended_actions || [];
  const defaultActions = [
    "Verify domain registration timeline. Monitor newly registered status parameters.",
    "Restrict ingress/egress firewall mappings referencing identified malicious IP subnets.",
    "Alert security response teams to trigger active phishing defense awareness metrics.",
    "Ensure standard network perimeter defense systems block DNS query resolution for target."
  ];
  const finalActions = actions.length > 0 ? actions : defaultActions;

  finalActions.forEach((action, i) => {
    checkPage(15);
    
    doc.setFillColor(241, 245, 249);
    doc.roundedRect(margin, y, contentW, 11, 0.5, 0.5, "F");

    // Draw square counter
    doc.setFillColor(15, 23, 42);
    doc.rect(margin + 3, y + 3, 5, 5, "F");
    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(7.5);
    doc.text(`${i + 1}`, margin + 5.5, y + 6.5, { align: "center" });

    doc.setTextColor(51, 65, 85);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    const actLines = doc.splitTextToSize(sanitize(action), contentW - 16);
    doc.text(actLines, margin + 11, y + 6.5);

    y += 14;
  });
  y += 5;

  // ───────────────────────────────────────────────────────────────────────────
  // SECTION 12: APPENDIX (RAW TECHNICAL DATA)
  // ───────────────────────────────────────────────────────────────────────────
  checkPage(40);
  doc.setTextColor(15, 23, 42);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(13);
  doc.text("11. APPENDIX: RAW CORRELATED DATA STAMPS", margin, y);
  doc.setFillColor(15, 23, 42);
  doc.rect(margin, y + 2.5, 30, 1, "F");
  y += 8;

  // Build raw metadata console logs
  const appData = [
    `CRITICALITY LEVEL   : ${riskLabel.toUpperCase()}`,
    `SCAN TIME DURATION  : DISPATCHED SYSTEM PIPELINE`,
    `GEOLOCATION CODE    : ${sanitize(enr?.geoip?.country_code || "US")} (${sanitize(enr?.geoip?.org || "ISP Cloud")})`,
    `ASN RESOLVED VALUE  : ${sanitize(enr?.geoip?.asn || "N/A")}`,
    `REGISTRY EXPIRE DATE: ${sanitize(enr?.whois?.expiration_date || "N/A")}`,
    `SSL ENCRYPT SUBJECT : ${sanitize(enr?.ssl?.subject_cn || "N/A")}`
  ];

  const appBoxH = appData.length * 4.5 + 8;
  checkPage(appBoxH + 5);
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  doc.roundedRect(margin, y, contentW, appBoxH, 1, 1, "FD");

  doc.setFont("courier", "bold");
  doc.setFontSize(7.5);
  doc.setTextColor(100, 116, 139);
  
  appData.forEach((line, index) => {
    doc.text(sanitize(line), margin + 4, y + 6 + index * 4.5);
  });

  // ───────────────────────────────────────────────────────────────────────────
  // POST PASS: HEADERS, FOOTERS & PAGE NUMBERS
  // ───────────────────────────────────────────────────────────────────────────
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    
    // Header & Footer only on Subsequent Pages
    if (i > 1) {
      // Line separator header
      doc.setDrawColor(241, 245, 249);
      doc.setLineWidth(0.2);
      doc.line(margin, 12, pageW - margin, 12);

      // Running top header text
      doc.setFontSize(7.5);
      doc.setFont("helvetica", "normal");
      doc.setTextColor(148, 163, 184);
      doc.text("TIBSA CYBER INTELLIGENCE PORTAL", margin, 9);
      
      const headerTarget = `Target: ${investigation.target.toUpperCase()}`;
      doc.text(sanitize(headerTarget), pageW - margin, 9, { align: "right" });

      // Bottom Footer text
      doc.text("CLASSIFICATION: TLP:AMBER | TIBSA HIGH-POSTURE INTEL", margin, 287);
      doc.text(`Page ${i} of ${pageCount}`, pageW - margin, 287, { align: "right" });
    } else {
      // Cover page footer
      doc.setFontSize(8);
      doc.setFont("helvetica", "bold");
      doc.setTextColor(148, 163, 184);
      doc.text("RESTRICTED REPORT - CLASSIFICATION: TLP:AMBER", pageW / 2, 285, { align: "center" });
    }
  }

  // Save the PDF
  const safeName = investigation.target.replace(/[^a-zA-Z0-9_.-]/g, "_");
  doc.save(`TIBSA_SOC_Infra_Report_${safeName}_${new Date().toISOString().slice(0, 10)}.pdf`);
}
