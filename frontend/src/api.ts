export const BASE_URL = "/api";

/** Returns auth + lang headers without making a request. Use for streaming (SSE) fetch calls. */
export function getAuthHeaders(): Record<string, string> {
    const token = localStorage.getItem("auth_token");
    const lang = localStorage.getItem("i18nextLng") || "en";
    return {
        "Accept-Language": lang,
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
    };
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

    if (response.status === 401) {
        window.location.href = "/login";
        throw new Error("Unauthorized");
    }

    return response;
}
