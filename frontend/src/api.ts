export const BASE_URL = "/api";
const AUTH_TOKEN_KEY = "auth_token";
let authToken: string | null = null;

function clearLegacyStoredAuthToken() {
    for (const storage of [localStorage, sessionStorage]) {
        try {
            storage.removeItem(AUTH_TOKEN_KEY);
        } catch {
            // Storage can be unavailable by browser policy; memory-only auth remains usable.
        }
    }
}

clearLegacyStoredAuthToken();

/** Returns auth + lang headers without making a request. Use for streaming (SSE) fetch calls. */
export function getAuthHeaders(tokenOverride?: string): Record<string, string> {
    const token = tokenOverride ?? authToken;
    const lang = localStorage.getItem("i18nextLng") || "en";
    return {
        "Accept-Language": lang,
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
    };
}

export function setAuthToken(token: string) {
    clearLegacyStoredAuthToken();
    authToken = token;
}

export function clearAuthToken() {
    authToken = null;
    clearLegacyStoredAuthToken();
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
