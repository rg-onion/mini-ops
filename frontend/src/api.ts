export const BASE_URL = "/api";
const AUTH_TOKEN_KEY = "auth_token";

/** Returns auth + lang headers without making a request. Use for streaming (SSE) fetch calls. */
export function getAuthHeaders(tokenOverride?: string): Record<string, string> {
    const token = tokenOverride ?? localStorage.getItem(AUTH_TOKEN_KEY);
    const lang = localStorage.getItem("i18nextLng") || "en";
    return {
        "Accept-Language": lang,
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
    };
}

export function clearAuthToken() {
    localStorage.removeItem(AUTH_TOKEN_KEY);
}

export function handleUnauthorizedResponse(response: Response): boolean {
    if (response.status !== 401) return false;

    clearAuthToken();
    if (window.location.pathname !== "/login") {
        window.location.href = "/login";
    }
    return true;
}

export async function apiFetch(endpoint: string, options: RequestInit = {}) {
    const headers = {
        "Content-Type": "application/json",
        ...getAuthHeaders(),
        ...options.headers,
    };

    const response = await fetch(`${BASE_URL}${endpoint}`, {
        ...options,
        headers,
    });

    if (handleUnauthorizedResponse(response)) {
        throw new Error("Unauthorized");
    }

    return response;
}
