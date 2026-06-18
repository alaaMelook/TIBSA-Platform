/**
 * API wrapper for communicating with the FastAPI backend.
 */

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

const defaults = {
    headers: {
        common: {
            Authorization: "",
        },
    },
};

interface RequestOptions {
    method?: string;
    body?: unknown;
    headers?: Record<string, string>;
    token?: string;
}

async function request<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
    const { method = "GET", body, headers = {}, token } = options;

    const config: RequestInit = {
        method,
        headers: {
            "Content-Type": "application/json",
            ...(defaults.headers.common.Authorization 
                ? { Authorization: defaults.headers.common.Authorization } 
                : {}),
            ...headers,
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
    };

    if (body) {
        config.body = JSON.stringify(body);
    }

    let response: Response;
    try {
        response = await fetch(`${API_BASE_URL}${endpoint}`, config);
    } catch {
        throw new Error(
            `Cannot connect to the backend server at ${API_BASE_URL}. ` +
            `Make sure the backend is running (uvicorn app.main:app --reload).`
        );
    }

    if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: "An error occurred" }));
        
        let errorMessage = `HTTP ${response.status}`;
        if (typeof error.detail === 'string') {
            errorMessage = error.detail;
        } else if (Array.isArray(error.detail)) {
            // Handle FastAPI validation error arrays
            errorMessage = error.detail.map((e: any) => `${e.loc?.[e.loc.length - 1]}: ${e.msg}`).join(", ");
        } else if (error.detail) {
            errorMessage = JSON.stringify(error.detail);
        }
        
        throw new Error(errorMessage);
    }

    return response.json();
}

// ─── API Methods ─────────────────────────────────────────────
export const api = {
    defaults,
    
    get: <T>(endpoint: string, token?: string) =>
        request<T>(endpoint, { token }),

    post: <T>(endpoint: string, body: unknown, token?: string) =>
        request<T>(endpoint, { method: "POST", body, token }),

    put: <T>(endpoint: string, body: unknown, token?: string) =>
        request<T>(endpoint, { method: "PUT", body, token }),

    patch: <T>(endpoint: string, body: unknown, token?: string) =>
        request<T>(endpoint, { method: "PATCH", body, token }),

    delete: <T>(endpoint: string, token?: string) =>
        request<T>(endpoint, { method: "DELETE", token }),

    uploadFile: <T>(endpoint: string, file: File, token?: string): Promise<T> => {
        const formData = new FormData();
        formData.append("file", file);
        return fetch(`${API_BASE_URL}${endpoint}`, {
            method: "POST",
            headers: token ? { Authorization: `Bearer ${token}` } : {},
            body: formData,
        }).then(async (res) => {
            if (!res.ok) {
                const err = await res.json().catch(() => ({ detail: "Upload failed" }));
                throw new Error(err.detail || `HTTP ${res.status}`);
            }
            return res.json() as Promise<T>;
        });
    },

    investigations: {
        create: (data: any, token?: string) =>
            api.post<any>("/api/v1/investigations/start", data, token),
        list: (token?: string) =>
            api.get<any>("/api/v1/investigations/", token),
        get: (id: string, token?: string) =>
            api.get<any>(`/api/v1/investigations/${id}`, token),
        getStatus: (id: string, token?: string) =>
            api.get<any>(`/api/v1/investigations/${id}/status`, token),
        getFindings: (id: string, token?: string) =>
            api.get<any>(`/api/v1/investigations/${id}/findings`, token),
        getResults: (id: string, token?: string) =>
            api.get<any>(`/api/v1/investigations/${id}/results`, token),
        stop: (id: string, token?: string) =>
            api.post<any>(`/api/v1/investigations/${id}/stop`, {}, token),
    },

    infraInvestigations: {
        create: (data: any, token?: string) =>
            api.post<any>("/api/v1/infra-investigations/start", data, token),
        list: (token?: string) =>
            api.get<any>("/api/v1/infra-investigations/", token),
        get: (id: string, token?: string) =>
            api.get<any>(`/api/v1/infra-investigations/${id}`, token),
        getStatus: (id: string, token?: string) =>
            api.get<any>(`/api/v1/infra-investigations/${id}/status`, token),
        stop: (id: string, token?: string) =>
            api.post<any>(`/api/v1/infra-investigations/${id}/stop`, {}, token),

        // ── Relational table endpoints (populated after pipeline completes) ──
        getIndicators: (
            id: string,
            token?: string,
            opts: { severity?: string; maliciousOnly?: boolean; limit?: number; offset?: number } = {}
        ) => {
            const params = new URLSearchParams();
            if (opts.severity)                         params.set("severity", opts.severity);
            if (opts.maliciousOnly)                    params.set("malicious_only", "true");
            if (opts.limit    !== undefined)           params.set("limit",  String(opts.limit));
            if (opts.offset   !== undefined)           params.set("offset", String(opts.offset));
            const qs = params.toString();
            return api.get<any>(`/api/v1/infra-investigations/${id}/indicators${qs ? `?${qs}` : ""}`, token);
        },

        getGraph: (id: string, token?: string) =>
            api.get<any>(`/api/v1/infra-investigations/${id}/graph`, token),

        getEnrichment: (id: string, token?: string, stage?: string) => {
            const qs = stage ? `?stage=${encodeURIComponent(stage)}` : "";
            return api.get<any>(`/api/v1/infra-investigations/${id}/enrichment${qs}`, token);
        },

        getReport: (id: string, token?: string) =>
            api.get<any>(`/api/v1/infra-investigations/${id}/report`, token),

        backfill: (id: string, token?: string) =>
            api.post<any>(`/api/v1/infra-investigations/${id}/backfill`, {}, token),
    },
};

