export const BASE_URL = "/api";

export async function apiFetch(endpoint: string, options: RequestInit = {}) {
    const token = localStorage.getItem("auth_token");
    const lang = localStorage.getItem("i18nextLng") || "en";
    const headers = {
        "Content-Type": "application/json",
        "Accept-Language": lang,
        ...options.headers,
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
    };

    const response = await fetch(`${BASE_URL}${endpoint}`, {
        ...options,
        headers,
    });

    if (response.status === 401) {
        // Redirect to login if unauthorized
        window.location.href = "/login";
        throw new Error("Unauthorized");
    }

    return response;
}
