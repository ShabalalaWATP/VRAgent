/**
 * Auth API utility - wraps fetch with authentication headers
 */

const API_URL = import.meta.env.VITE_API_URL || "/api";
const ACCESS_TOKEN_KEY = "vragent_access_token";

// Get the current access token
export function getAccessToken(): string | null {
  return localStorage.getItem(ACCESS_TOKEN_KEY);
}

// Check if user is authenticated
export function isAuthenticated(): boolean {
  return !!getAccessToken();
}

// Create headers with auth token
export function getAuthHeaders(): HeadersInit {
  const token = getAccessToken();
  const headers: HeadersInit = {
    "Content-Type": "application/json",
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

// Authenticated fetch wrapper
export async function authFetch(
  path: string,
  options?: RequestInit
): Promise<Response> {
  const token = getAccessToken();
  const headers = new Headers(options?.headers);
  
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  
  if (!headers.has("Content-Type") && !(options?.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(`${API_URL}${path}`, {
    ...options,
    headers,
  });

  // Handle 401 - token expired or invalid
  if (response.status === 401) {
    // Clear tokens and redirect to login
    localStorage.removeItem(ACCESS_TOKEN_KEY);
    localStorage.removeItem("vragent_refresh_token");
    
    // Only redirect if we're not already on the login page
    if (!window.location.pathname.includes("/login")) {
      window.location.href = "/login";
    }
  }

  return response;
}

// Authenticated JSON request helper
export async function authRequest<T>(
  path: string,
  options?: RequestInit
): Promise<T> {
  const response = await authFetch(path, options);
  
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || response.statusText);
  }
  
  return (await response.json()) as T;
}

// Auth API endpoints
export const authApi = {
  // Login
  login: async (email: string, password: string) => {
    const response = await fetch(`${API_URL}/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        username: email,
        password: password,
      }),
    });
    return response;
  },

  // Register
  register: async (email: string, username: string, password: string) => {
    const response = await fetch(`${API_URL}/auth/register`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email, username, password }),
    });
    return response;
  },

  // Get current user
  me: async () => {
    return authRequest<{
      id: number;
      email: string;
      username: string;
      role: "user" | "admin";
      status: "pending" | "approved" | "suspended";
      created_at: string;
      last_login?: string;
    }>("/auth/me");
  },

  // Refresh token
  refresh: async (refreshToken: string) => {
    const response = await fetch(`${API_URL}/auth/refresh`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    return response;
  },
};

// Admin API endpoints
export const adminApi = {
  // Get all users
  getUsers: () => authRequest<Array<{
    id: number;
    email: string;
    username: string;
    role: "user" | "admin";
    status: "pending" | "approved" | "suspended";
    created_at: string;
    last_login?: string;
  }>>("/admin/users"),

  // Create user
  createUser: (data: {
    email: string;
    username: string;
    password: string;
    role: "user" | "admin";
  }) => authRequest<any>("/admin/users", {
    method: "POST",
    body: JSON.stringify(data),
  }),

  // Approve user
  approveUser: (userId: number) =>
    authRequest<any>(`/admin/users/${userId}/approve`, { method: "POST" }),

  // Suspend user
  suspendUser: (userId: number) =>
    authRequest<any>(`/admin/users/${userId}/suspend`, { method: "POST" }),

  // Delete user
  deleteUser: (userId: number) =>
    authRequest<any>(`/admin/users/${userId}`, { method: "DELETE" }),

  // Update user role
  updateRole: (userId: number, role: "user" | "admin") =>
    authRequest<any>(`/admin/users/${userId}/role`, {
      method: "PUT",
      body: JSON.stringify({ role }),
    }),

  // Change user password
  changePassword: (userId: number, newPassword: string) =>
    authRequest<any>(`/admin/users/${userId}/password`, {
      method: "PUT",
      body: JSON.stringify({ new_password: newPassword }),
    }),
};
