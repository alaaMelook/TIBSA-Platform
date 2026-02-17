/**
 * API wrapper for communicating with the FastAPI backend.
 */

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

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
            ...headers,
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
    };

    if (body) {
        config.body = JSON.stringify(body);
    }

    const response = await fetch(`${API_BASE_URL}${endpoint}`, config);

    if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: "An error occurred" }));
        throw new Error(error.detail || `HTTP ${response.status}`);
    }

    return response.json();
}

// ─── API Methods ─────────────────────────────────────────────
export const api = {
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
};
