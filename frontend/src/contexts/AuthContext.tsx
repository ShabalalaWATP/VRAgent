import { createContext, useContext, useState, useEffect, ReactNode, useCallback } from "react";

// User types
export type UserRole = "user" | "admin";
export type AccountStatus = "pending" | "approved" | "suspended";

export type User = {
  id: number;
  email: string;
  username: string;
  first_name?: string;
  last_name?: string;
  role: UserRole;
  status: AccountStatus;
  created_at: string;
  last_login?: string;
};

export type AuthTokens = {
  access_token: string;
  refresh_token: string;
  token_type: string;
};

type AuthContextType = {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  isAdmin: boolean;
  login: (username: string, password: string) => Promise<{ success: boolean; error?: string }>;
  logout: () => void;
  register: (email: string, username: string, firstName: string, lastName: string, password: string) => Promise<{ success: boolean; error?: string; message?: string }>;
  refreshAuth: () => Promise<boolean>;
  getAccessToken: () => string | null;
};

const AuthContext = createContext<AuthContextType>({
  user: null,
  isAuthenticated: false,
  isLoading: true,
  isAdmin: false,
  login: async () => ({ success: false }),
  logout: () => {},
  register: async () => ({ success: false }),
  refreshAuth: async () => false,
  getAccessToken: () => null,
});

export const useAuth = () => useContext(AuthContext);

const API_URL = import.meta.env.VITE_API_URL || "/api";

// Token storage keys
const ACCESS_TOKEN_KEY = "vragent_access_token";
const REFRESH_TOKEN_KEY = "vragent_refresh_token";

// Token management
const getStoredTokens = (): AuthTokens | null => {
  const accessToken = localStorage.getItem(ACCESS_TOKEN_KEY);
  const refreshToken = localStorage.getItem(REFRESH_TOKEN_KEY);
  if (accessToken && refreshToken) {
    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: "bearer",
    };
  }
  return null;
};

const storeTokens = (tokens: AuthTokens) => {
  localStorage.setItem(ACCESS_TOKEN_KEY, tokens.access_token);
  localStorage.setItem(REFRESH_TOKEN_KEY, tokens.refresh_token);
};

const clearTokens = () => {
  localStorage.removeItem(ACCESS_TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
};

type Props = {
  children: ReactNode;
};

export function AuthProvider({ children }: Props) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const getAccessToken = useCallback((): string | null => {
    return localStorage.getItem(ACCESS_TOKEN_KEY);
  }, []);

  // Fetch current user from API
  const fetchCurrentUser = useCallback(async (token: string): Promise<User | null> => {
    try {
      const response = await fetch(`${API_URL}/auth/me`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      if (response.ok) {
        return await response.json();
      }
      return null;
    } catch {
      return null;
    }
  }, []);

  // Refresh access token
  const refreshAuth = useCallback(async (): Promise<boolean> => {
    const tokens = getStoredTokens();
    if (!tokens?.refresh_token) return false;

    try {
      const response = await fetch(`${API_URL}/auth/refresh`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ refresh_token: tokens.refresh_token }),
      });

      if (response.ok) {
        const newTokens: AuthTokens = await response.json();
        storeTokens(newTokens);
        const userData = await fetchCurrentUser(newTokens.access_token);
        if (userData) {
          setUser(userData);
          return true;
        }
      }
      // Refresh failed - clear tokens
      clearTokens();
      setUser(null);
      return false;
    } catch {
      clearTokens();
      setUser(null);
      return false;
    }
  }, [fetchCurrentUser]);

  // Initialize auth state on mount
  useEffect(() => {
    const initAuth = async () => {
      const tokens = getStoredTokens();
      if (tokens?.access_token) {
        const userData = await fetchCurrentUser(tokens.access_token);
        if (userData) {
          setUser(userData);
        } else {
          // Token might be expired, try refresh
          await refreshAuth();
        }
      }
      setIsLoading(false);
    };
    initAuth();
  }, [fetchCurrentUser, refreshAuth]);

  // Auto-refresh token before it expires (every 20 minutes for 30-min tokens)
  useEffect(() => {
    if (!user) return;

    const refreshInterval = setInterval(async () => {
      const success = await refreshAuth();
      if (!success) {
        console.warn("[Auth] Auto-refresh failed, user will need to re-login");
      }
    }, 20 * 60 * 1000); // 20 minutes

    return () => clearInterval(refreshInterval);
  }, [user, refreshAuth]);

  // Login
  const login = async (username: string, password: string): Promise<{ success: boolean; error?: string }> => {
    try {
      const response = await fetch(`${API_URL}/auth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          username: username, // OAuth2 spec uses "username" field
          password: password,
        }),
      });

      if (response.ok) {
        const tokens: AuthTokens = await response.json();
        storeTokens(tokens);
        const userData = await fetchCurrentUser(tokens.access_token);
        if (userData) {
          setUser(userData);
          return { success: true };
        }
        return { success: false, error: "Failed to fetch user data" };
      } else {
        const errorData = await response.json().catch(() => ({}));
        return { 
          success: false, 
          error: errorData.detail || "Invalid username or password" 
        };
      }
    } catch (err: any) {
      return { success: false, error: err.message || "Network error" };
    }
  };

  // Logout
  const logout = useCallback(() => {
    clearTokens();
    setUser(null);
  }, []);

  // Register (request account)
  const register = async (
    email: string, 
    username: string,
    firstName: string,
    lastName: string,
    password: string
  ): Promise<{ success: boolean; error?: string; message?: string }> => {
    try {
      const response = await fetch(`${API_URL}/auth/register`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ email, username, first_name: firstName, last_name: lastName, password }),
      });

      const data = await response.json().catch(() => ({}));
      
      if (response.ok) {
        return { 
          success: true, 
          message: data.message || "Account request submitted. Please wait for admin approval." 
        };
      } else {
        return { 
          success: false, 
          error: data.detail || "Registration failed" 
        };
      }
    } catch (err: any) {
      return { success: false, error: err.message || "Network error" };
    }
  };

  const value: AuthContextType = {
    user,
    isAuthenticated: !!user && user.status === "approved",
    isLoading,
    isAdmin: user?.role === "admin",
    login,
    logout,
    register,
    refreshAuth,
    getAccessToken,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

// Higher-order component for protected routes
export function withAuth<P extends object>(
  Component: React.ComponentType<P>,
  requireAdmin: boolean = false
) {
  return function AuthenticatedComponent(props: P) {
    const { isAuthenticated, isAdmin, isLoading } = useAuth();

    if (isLoading) {
      return null; // Or a loading spinner
    }

    if (!isAuthenticated) {
      // Will be handled by ProtectedRoute component
      return null;
    }

    if (requireAdmin && !isAdmin) {
      return null;
    }

    return <Component {...props} />;
  };
}
