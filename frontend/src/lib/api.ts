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
};
