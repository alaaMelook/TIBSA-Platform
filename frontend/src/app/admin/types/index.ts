// ─── Admin Dashboard Types ───────────────────────────────────
export interface AdminStats {
    totalUsers: number;
    activeUsers: number;
    totalScans: number;
    scansToday: number;
    threatsDetected: number;
    threatsToday: number;
    systemUptime: number; // percentage
    avgResponseTime: number; // ms
}

export interface StatCardData {
    label: string;
    value: string | number;
    change?: number; // percentage change
    changeLabel?: string;
    icon: React.ReactNode;
    color: "blue" | "green" | "red" | "amber" | "purple" | "cyan";
    trend?: "up" | "down" | "neutral";
}

// ─── User Management Types ──────────────────────────────────
export interface AdminUser {
    id: string;
    email: string;
    full_name: string;
    role: "user" | "admin";
    is_active: boolean;
    created_at: string;
    updated_at: string;
    last_login: string | null;
    total_scans: number;
    threats_found: number;
    storage_used: number; // MB
}

// ─── Threat Intelligence Hub ────────────────────────────────
export interface ThreatDistribution {
    name: string;
    value: number;
    color: string;
}

export interface ThreatTrend {
    date: string;
    critical: number;
    high: number;
    medium: number;
    low: number;
    safe: number;
}

export interface TopThreat {
    id: string;
    indicator: string;
    type: "ip" | "domain" | "hash" | "url" | "email";
    threat_level: "critical" | "high" | "medium" | "low";
    detections: number;
    first_seen: string;
    last_seen: string;
    source: string;
    name?: string;
    score?: number;
    trend?: "up" | "down" | "neutral";
}

// ─── Platform Analytics ─────────────────────────────────────
export interface ScanVolumeData {
    date: string;
    url_scans: number;
    file_scans: number;
    malware_analysis: number;
}

export interface UserGrowthData {
    month: string;
    users: number;
    active: number;
}

export interface TopScannedUrl {
    url: string;
    scan_count: number;
    last_scanned: string;
    threat_level: "safe" | "low" | "medium" | "high" | "critical";
}

// ─── System Health ──────────────────────────────────────────
export interface ServiceHealth {
    name: string;
    status: "operational" | "degraded" | "down";
    uptime: number; // percentage
    responseTime: number; // ms
    lastCheck: string;
    description: string;
}

export interface SystemMetric {
    timestamp: string;
    cpu: number;
    memory: number;
    disk: number;
    network: number;
}

// ─── Threat Feed Management ─────────────────────────────────
export interface ThreatFeedConfig {
    id: string;
    name: string;
    provider: string;
    source_url: string;
    is_active: boolean;
    last_updated: string;
    indicators_count: number;
    update_frequency: string;
    reliability_score: number; // 0-100
    category: "malware" | "phishing" | "c2" | "botnet" | "apt" | "general";
}

// ─── Audit Log ──────────────────────────────────────────────
export interface AuditLogEntry {
    id: string;
    timestamp: string;
    user_email: string;
    user_name: string;
    action: string;
    resource: string;
    details: string;
    ip_address: string;
    status: "success" | "failure" | "warning";
}

// ─── Recent Activity ────────────────────────────────────────
export interface RecentActivity {
    id: string;
    type: "scan" | "threat" | "user" | "system" | "auth";
    message: string;
    timestamp: string;
    severity: "info" | "warning" | "critical" | "success";
    user?: string;
}
