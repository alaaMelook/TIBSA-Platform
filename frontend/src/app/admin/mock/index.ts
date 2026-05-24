import type {
    AdminStats,
    AdminUser,
    ThreatDistribution,
    ThreatTrend,
    TopThreat,
    ScanVolumeData,
    UserGrowthData,
    TopScannedUrl,
    ServiceHealth,
    SystemMetric,
    ThreatFeedConfig,
    AuditLogEntry,
    RecentActivity,
} from "../types";

// ─── Admin Overview Stats ───────────────────────────────────
export const mockAdminStats: AdminStats = {
    totalUsers: 15,
    activeUsers: 15,
    totalScans: 48_392,
    scansToday: 1_284,
    threatsDetected: 3_847,
    threatsToday: 127,
    systemUptime: 99.97,
    avgResponseTime: 142,
};

// ─── User Management ────────────────────────────────────────
export const mockAdminUsers: AdminUser[] = [
    {
        id: "u-001", email: "gradteams759@gmail.com", full_name: "lolo",
        role: "admin", is_active: true, created_at: "2025-01-15T10:00:00Z",
        updated_at: "2026-05-24T08:00:00Z", last_login: "2026-05-24T20:10:00Z",
        total_scans: 2_340, threats_found: 189, storage_used: 456,
    },
    {
        id: "u-002", email: "abdelrahmanelmoghazy5@gmail.com", full_name: "Abdelrahman",
        role: "admin", is_active: true, created_at: "2025-03-22T14:00:00Z",
        updated_at: "2026-05-20T09:00:00Z", last_login: "2026-05-24T18:30:00Z",
        total_scans: 1_120, threats_found: 87, storage_used: 234,
    },
    {
        id: "u-003", email: "nadinerasmy237@gmail.com", full_name: "nadine",
        role: "admin", is_active: true, created_at: "2025-06-10T11:00:00Z",
        updated_at: "2026-05-22T15:00:00Z", last_login: "2026-05-23T12:00:00Z",
        total_scans: 890, threats_found: 56, storage_used: 178,
    },
    {
        id: "u-004", email: "mahmoud.zaghloula88@gmail.com", full_name: "mahmoud amr zaghloula",
        role: "admin", is_active: true, created_at: "2025-02-28T09:00:00Z",
        updated_at: "2026-05-24T07:00:00Z", last_login: "2026-05-24T19:45:00Z",
        total_scans: 3_200, threats_found: 312, storage_used: 890,
    },
    {
        id: "u-005", email: "yumnamedha70@gmail.com", full_name: "yumna medhat anter",
        role: "admin", is_active: true, created_at: "2025-08-15T16:00:00Z",
        updated_at: "2026-05-24T06:00:00Z", last_login: "2026-05-24T17:20:00Z",
        total_scans: 1_560, threats_found: 142, storage_used: 367,
    },
    {
        id: "u-006", email: "ranaaa.rj20@gmail.com", full_name: "Rana Ashraf",
        role: "admin", is_active: true, created_at: "2025-09-01T08:00:00Z",
        updated_at: "2026-05-24T06:00:00Z", last_login: "2026-05-24T16:00:00Z",
        total_scans: 980, threats_found: 78, storage_used: 210,
    },
    {
        id: "u-007", email: "kenzy.rasmy@gmail.com", full_name: "kr",
        role: "admin", is_active: true, created_at: "2025-11-20T13:00:00Z",
        updated_at: "2026-05-23T11:00:00Z", last_login: "2026-05-24T14:00:00Z",
        total_scans: 670, threats_found: 34, storage_used: 123,
    },
    {
        id: "u-008", email: "nadine.rasmy@hotamil.com", full_name: "nadine",
        role: "admin", is_active: true, created_at: "2026-01-05T10:00:00Z",
        updated_at: "2026-05-24T05:00:00Z", last_login: "2026-05-24T16:15:00Z",
        total_scans: 445, threats_found: 28, storage_used: 89,
    },
    {
        id: "u-009", email: "yumnamedhat50@gmail.com", full_name: "yumna medhat",
        role: "admin", is_active: true, created_at: "2026-02-10T09:00:00Z",
        updated_at: "2026-05-24T04:00:00Z", last_login: "2026-05-24T15:00:00Z",
        total_scans: 520, threats_found: 41, storage_used: 102,
    },
    {
        id: "u-010", email: "guhv5747@gmail.com", full_name: "test",
        role: "user", is_active: true, created_at: "2026-01-20T12:00:00Z",
        updated_at: "2026-05-20T10:00:00Z", last_login: "2026-05-20T10:00:00Z",
        total_scans: 45, threats_found: 3, storage_used: 12,
    },
    {
        id: "u-011", email: "test@tibsa.com", full_name: "test",
        role: "user", is_active: true, created_at: "2026-02-15T14:00:00Z",
        updated_at: "2026-05-18T08:00:00Z", last_login: "2026-05-18T08:00:00Z",
        total_scans: 30, threats_found: 2, storage_used: 8,
    },
    {
        id: "u-012", email: "ma@za.com", full_name: "mahmoud",
        role: "user", is_active: true, created_at: "2026-03-01T16:00:00Z",
        updated_at: "2026-05-22T12:00:00Z", last_login: "2026-05-22T12:00:00Z",
        total_scans: 120, threats_found: 9, storage_used: 34,
    },
    {
        id: "u-013", email: "demo@tibsa.com", full_name: "Demo User",
        role: "user", is_active: true, created_at: "2026-03-10T10:00:00Z",
        updated_at: "2026-05-21T14:00:00Z", last_login: "2026-05-21T14:00:00Z",
        total_scans: 78, threats_found: 5, storage_used: 20,
    },
    {
        id: "u-014", email: "testuser@gmail.com", full_name: "Test User",
        role: "user", is_active: true, created_at: "2026-04-05T11:00:00Z",
        updated_at: "2026-05-19T09:00:00Z", last_login: "2026-05-19T09:00:00Z",
        total_scans: 55, threats_found: 4, storage_used: 15,
    },
    {
        id: "u-015", email: "testjj@gmail.com", full_name: "test",
        role: "user", is_active: true, created_at: "2026-04-20T15:00:00Z",
        updated_at: "2026-05-17T07:00:00Z", last_login: "2026-05-17T07:00:00Z",
        total_scans: 22, threats_found: 1, storage_used: 6,
    },
];

// ─── Threat Distribution ────────────────────────────────────
export const mockThreatDistribution: ThreatDistribution[] = [
    { name: "Malware", value: 1_245, color: "#ef4444" },
    { name: "Phishing", value: 892, color: "#f97316" },
    { name: "C2 Server", value: 456, color: "#eab308" },
    { name: "Ransomware", value: 234, color: "#dc2626" },
    { name: "Botnet", value: 189, color: "#a855f7" },
    { name: "APT", value: 78, color: "#ec4899" },
    { name: "Other", value: 753, color: "#6b7280" },
];

// ─── Threat Trends (Last 14 days) ───────────────────────────
export const mockThreatTrends: ThreatTrend[] = Array.from({ length: 14 }, (_, i) => {
    const date = new Date();
    date.setDate(date.getDate() - (13 - i));
    return {
        date: date.toLocaleDateString("en-US", { month: "short", day: "numeric" }),
        critical: Math.floor(Math.random() * 15) + 5,
        high: Math.floor(Math.random() * 30) + 15,
        medium: Math.floor(Math.random() * 50) + 30,
        low: Math.floor(Math.random() * 40) + 20,
        safe: Math.floor(Math.random() * 100) + 80,
    };
});

// ─── Top Threats ────────────────────────────────────────────
export const mockTopThreats: TopThreat[] = [
    {
        id: "t-001", indicator: "185.220.101.47", type: "ip", threat_level: "critical",
        detections: 847, first_seen: "2026-05-10T08:00:00Z", last_seen: "2026-05-24T19:30:00Z",
        source: "TIBSA Internal",
    },
    {
        id: "t-002", indicator: "evil-phishing-login.com", type: "domain", threat_level: "high",
        detections: 623, first_seen: "2026-05-12T14:00:00Z", last_seen: "2026-05-24T18:00:00Z",
        source: "AlienVault OTX",
    },
    {
        id: "t-003", indicator: "e3b0c44298fc1c149afbf4c8996fb924", type: "hash", threat_level: "critical",
        detections: 512, first_seen: "2026-05-15T06:00:00Z", last_seen: "2026-05-24T20:00:00Z",
        source: "VirusTotal",
    },
    {
        id: "t-004", indicator: "https://malware-drop.xyz/payload.exe", type: "url", threat_level: "critical",
        detections: 398, first_seen: "2026-05-18T10:00:00Z", last_seen: "2026-05-24T17:00:00Z",
        source: "TIBSA Internal",
    },
    {
        id: "t-005", indicator: "103.253.41.98", type: "ip", threat_level: "high",
        detections: 287, first_seen: "2026-05-20T12:00:00Z", last_seen: "2026-05-24T16:00:00Z",
        source: "AbuseIPDB",
    },
];

// ─── Scan Volume (Last 7 days) ──────────────────────────────
export const mockScanVolume: ScanVolumeData[] = Array.from({ length: 7 }, (_, i) => {
    const date = new Date();
    date.setDate(date.getDate() - (6 - i));
    return {
        date: date.toLocaleDateString("en-US", { weekday: "short" }),
        url_scans: Math.floor(Math.random() * 200) + 150,
        file_scans: Math.floor(Math.random() * 80) + 40,
        malware_analysis: Math.floor(Math.random() * 30) + 10,
    };
});

// ─── User Growth (Last 6 months) ────────────────────────────
export const mockUserGrowth: UserGrowthData[] = [
    { month: "Dec", users: 3, active: 2 },
    { month: "Jan", users: 5, active: 4 },
    { month: "Feb", users: 8, active: 6 },
    { month: "Mar", users: 10, active: 8 },
    { month: "Apr", users: 12, active: 10 },
    { month: "May", users: 15, active: 15 },
];

// ─── Top Scanned URLs ──────────────────────────────────────
export const mockTopScannedUrls: TopScannedUrl[] = [
    { url: "https://suspicious-login.com/auth", scan_count: 234, last_scanned: "2026-05-24T19:30:00Z", threat_level: "critical" },
    { url: "https://free-download-tools.net", scan_count: 189, last_scanned: "2026-05-24T18:45:00Z", threat_level: "high" },
    { url: "https://secure-bank-verify.org", scan_count: 167, last_scanned: "2026-05-24T17:20:00Z", threat_level: "high" },
    { url: "https://microsoft-update.info", scan_count: 145, last_scanned: "2026-05-24T16:10:00Z", threat_level: "medium" },
    { url: "https://google.com", scan_count: 132, last_scanned: "2026-05-24T15:00:00Z", threat_level: "safe" },
    { url: "https://crypto-airdrop-claim.xyz", scan_count: 121, last_scanned: "2026-05-24T14:30:00Z", threat_level: "critical" },
    { url: "https://github.com", scan_count: 98, last_scanned: "2026-05-24T13:00:00Z", threat_level: "safe" },
    { url: "https://netflix-billing-update.com", scan_count: 87, last_scanned: "2026-05-24T12:00:00Z", threat_level: "high" },
];

// ─── System Health ──────────────────────────────────────────
export const mockServiceHealth: ServiceHealth[] = [
    { name: "API Gateway", status: "operational", uptime: 99.99, responseTime: 45, lastCheck: "2026-05-24T20:20:00Z", description: "Main REST API endpoint" },
    { name: "Scan Engine", status: "operational", uptime: 99.95, responseTime: 230, lastCheck: "2026-05-24T20:20:00Z", description: "URL and file scanning service" },
    { name: "Threat Intelligence", status: "operational", uptime: 99.92, responseTime: 180, lastCheck: "2026-05-24T20:20:00Z", description: "Threat feed aggregation and lookup" },
    { name: "AI Analysis Engine", status: "degraded", uptime: 98.50, responseTime: 890, lastCheck: "2026-05-24T20:20:00Z", description: "ML-powered malware analysis" },
    { name: "Database (Primary)", status: "operational", uptime: 99.99, responseTime: 12, lastCheck: "2026-05-24T20:20:00Z", description: "PostgreSQL primary instance" },
    { name: "Cache Layer", status: "operational", uptime: 99.98, responseTime: 3, lastCheck: "2026-05-24T20:20:00Z", description: "Redis caching layer" },
    { name: "Notification Service", status: "operational", uptime: 99.90, responseTime: 67, lastCheck: "2026-05-24T20:20:00Z", description: "Email and push notifications" },
    { name: "Report Generator", status: "operational", uptime: 99.85, responseTime: 450, lastCheck: "2026-05-24T20:20:00Z", description: "PDF/CSV report generation" },
];

// ─── System Metrics (Last 24h, hourly) ──────────────────────
export const mockSystemMetrics: SystemMetric[] = Array.from({ length: 24 }, (_, i) => {
    const timestamp = new Date();
    timestamp.setHours(timestamp.getHours() - (23 - i));
    return {
        timestamp: timestamp.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" }),
        cpu: Math.floor(Math.random() * 30) + 25,
        memory: Math.floor(Math.random() * 20) + 55,
        disk: 42 + (i * 0.1),
        network: Math.floor(Math.random() * 50) + 20,
    };
});

// ─── Threat Feed Configs ────────────────────────────────────
export const mockThreatFeeds: ThreatFeedConfig[] = [
    {
        id: "tf-001", name: "AlienVault OTX", provider: "AT&T Cybersecurity",
        source_url: "https://otx.alienvault.com/api/v1/pulses/subscribed",
        is_active: true, last_updated: "2026-05-24T19:00:00Z",
        indicators_count: 45_230, update_frequency: "Every 15 minutes",
        reliability_score: 92, category: "general",
    },
    {
        id: "tf-002", name: "AbuseIPDB", provider: "AbuseIPDB",
        source_url: "https://api.abuseipdb.com/api/v2/blacklist",
        is_active: true, last_updated: "2026-05-24T18:30:00Z",
        indicators_count: 12_890, update_frequency: "Every 30 minutes",
        reliability_score: 88, category: "malware",
    },
    {
        id: "tf-003", name: "PhishTank", provider: "OpenDNS",
        source_url: "https://data.phishtank.com/data/online-valid.json",
        is_active: true, last_updated: "2026-05-24T17:45:00Z",
        indicators_count: 8_920, update_frequency: "Hourly",
        reliability_score: 85, category: "phishing",
    },
    {
        id: "tf-004", name: "Feodo Tracker", provider: "abuse.ch",
        source_url: "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        is_active: true, last_updated: "2026-05-24T16:00:00Z",
        indicators_count: 3_456, update_frequency: "Every 5 minutes",
        reliability_score: 95, category: "c2",
    },
    {
        id: "tf-005", name: "URLhaus", provider: "abuse.ch",
        source_url: "https://urlhaus-api.abuse.ch/v1/",
        is_active: false, last_updated: "2026-05-20T12:00:00Z",
        indicators_count: 15_670, update_frequency: "Every 10 minutes",
        reliability_score: 90, category: "malware",
    },
    {
        id: "tf-006", name: "MISP Galaxy (APT)", provider: "CIRCL",
        source_url: "https://www.circl.lu/doc/misp-galaxy/",
        is_active: true, last_updated: "2026-05-24T15:00:00Z",
        indicators_count: 2_340, update_frequency: "Daily",
        reliability_score: 94, category: "apt",
    },
];

// ─── Audit Log ──────────────────────────────────────────────
export const mockAuditLog: AuditLogEntry[] = [
    { id: "al-001", timestamp: "2026-05-24T20:15:00Z", user_email: "gradteams759@gmail.com", user_name: "lolo", action: "USER_ROLE_CHANGE", resource: "user:u-003", details: "Changed role from 'user' to 'admin'", ip_address: "192.168.1.100", status: "success" },
    { id: "al-002", timestamp: "2026-05-24T20:10:00Z", user_email: "gradteams759@gmail.com", user_name: "lolo", action: "LOGIN", resource: "auth", details: "Admin login successful", ip_address: "192.168.1.100", status: "success" },
    { id: "al-003", timestamp: "2026-05-24T19:45:00Z", user_email: "nadinerasmy237@gmail.com", user_name: "nadine", action: "SCAN_CREATED", resource: "scan:s-892", details: "URL scan initiated for suspicious-login.com", ip_address: "10.0.0.45", status: "success" },
    { id: "al-004", timestamp: "2026-05-24T19:30:00Z", user_email: "mahmoud.zaghloula88@gmail.com", user_name: "mahmoud amr zaghloula", action: "THREAT_FEED_UPDATE", resource: "feed:tf-001", details: "Manually triggered AlienVault OTX feed sync", ip_address: "172.16.0.22", status: "success" },
    { id: "al-005", timestamp: "2026-05-24T19:15:00Z", user_email: "unknown@hacker.net", user_name: "Unknown", action: "LOGIN_FAILED", resource: "auth", details: "Failed login attempt — invalid credentials (3rd attempt)", ip_address: "103.253.41.98", status: "failure" },
    { id: "al-006", timestamp: "2026-05-24T18:50:00Z", user_email: "abdelrahmanelmoghazy5@gmail.com", user_name: "Abdelrahman", action: "REPORT_EXPORTED", resource: "report:r-456", details: "Exported threat analysis report as PDF", ip_address: "10.0.0.67", status: "success" },
    { id: "al-007", timestamp: "2026-05-24T18:30:00Z", user_email: "gradteams759@gmail.com", user_name: "lolo", action: "SYSTEM_CONFIG_CHANGE", resource: "settings", details: "Updated rate limit from 100 to 150 req/min", ip_address: "192.168.1.100", status: "warning" },
    { id: "al-008", timestamp: "2026-05-24T18:00:00Z", user_email: "yumnamedha70@gmail.com", user_name: "yumna medhat anter", action: "SCAN_CREATED", resource: "scan:s-891", details: "File scan initiated for suspected_malware.exe", ip_address: "10.0.0.89", status: "success" },
    { id: "al-009", timestamp: "2026-05-24T17:30:00Z", user_email: "ranaaa.rj20@gmail.com", user_name: "Rana Ashraf", action: "SCAN_CREATED", resource: "scan:s-890", details: "URL scan initiated for phishing-test.com", ip_address: "10.0.0.92", status: "success" },
    { id: "al-010", timestamp: "2026-05-24T17:00:00Z", user_email: "kenzy.rasmy@gmail.com", user_name: "kr", action: "API_KEY_GENERATED", resource: "api-key", details: "New API key generated for integration", ip_address: "10.0.0.102", status: "success" },
];

// ─── Recent Activity Feed ───────────────────────────────────
export const mockRecentActivity: RecentActivity[] = [
    { id: "ra-001", type: "threat", message: "Critical threat detected: C2 server 185.220.101.47 flagged by 3 feeds", timestamp: "2026-05-24T20:18:00Z", severity: "critical" },
    { id: "ra-002", type: "scan", message: "Batch scan completed: 45 URLs processed, 3 threats found", timestamp: "2026-05-24T20:15:00Z", severity: "info", user: "nadine" },
    { id: "ra-003", type: "user", message: "New user registered: testuser@gmail.com", timestamp: "2026-05-24T20:10:00Z", severity: "info" },
    { id: "ra-004", type: "auth", message: "Failed login attempt from suspicious IP 103.253.41.98", timestamp: "2026-05-24T19:55:00Z", severity: "warning" },
    { id: "ra-005", type: "system", message: "AI Analysis Engine response time elevated (890ms avg)", timestamp: "2026-05-24T19:40:00Z", severity: "warning" },
    { id: "ra-006", type: "threat", message: "Phishing domain evil-phishing-login.com added to blocklist", timestamp: "2026-05-24T19:30:00Z", severity: "success" },
    { id: "ra-007", type: "scan", message: "Malware analysis completed: suspected_malware.exe — HIGH risk", timestamp: "2026-05-24T19:20:00Z", severity: "critical", user: "yumna medhat anter" },
    { id: "ra-008", type: "system", message: "Threat feed sync completed: AlienVault OTX (1,247 new indicators)", timestamp: "2026-05-24T19:00:00Z", severity: "success" },
    { id: "ra-009", type: "user", message: "New user registered: demo@tibsa.com", timestamp: "2026-05-24T18:45:00Z", severity: "info" },
    { id: "ra-010", type: "scan", message: "Website pen test completed for acme-corp.com — 2 vulnerabilities found", timestamp: "2026-05-24T18:30:00Z", severity: "warning", user: "Abdelrahman" },
];
