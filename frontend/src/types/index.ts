// ─── User & Auth Types ───────────────────────────────────────
export type UserRole = "user" | "admin";

export interface User {
    id: string;
    email: string;
    full_name: string;
    role: UserRole;
    is_active: boolean;
    created_at: string;
    updated_at: string;
}

export interface AuthState {
    user: User | null;
    token: string | null;
    isLoading: boolean;
    isAuthenticated: boolean;
}

export interface LoginCredentials {
    email: string;
    password: string;
}

export interface RegisterCredentials {
    email: string;
    password: string;
    full_name: string;
}

// ─── Scan Types ──────────────────────────────────────────────
export type ScanType = "url" | "file";
export type ScanStatus = "pending" | "in_progress" | "completed" | "failed";
export type ThreatLevel = "safe" | "low" | "medium" | "high" | "critical";

export interface ScanResult {
    id: string;
    user_id: string;
    scan_type: ScanType;
    target: string;
    status: ScanStatus;
    threat_level: ThreatLevel | null;
    report: ScanReport | null;
    created_at: string;
    completed_at: string | null;
}

export interface ScanReport {
    summary: string;
    details: Record<string, unknown>;
    indicators: ThreatIndicator[];
}

// ─── Threat Intelligence Types ───────────────────────────────
export interface ThreatIndicator {
    type: "ip" | "domain" | "hash" | "url" | "email";
    value: string;
    threat_level: ThreatLevel;
    source: string;
    last_seen: string;
}

export interface ThreatFeed {
    id: string;
    name: string;
    source_url: string;
    is_active: boolean;
    last_updated: string;
}

// ─── API Response Types ──────────────────────────────────────
export interface ApiResponse<T> {
    data: T;
    message?: string;
}

export interface PaginatedResponse<T> {
    data: T[];
    total: number;
    page: number;
    per_page: number;
    total_pages: number;
}

export interface ApiError {
    detail: string;
    status_code: number;
}
