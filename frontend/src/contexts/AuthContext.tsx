"use client";

import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { supabase } from "@/lib/supabase";
import { api } from "@/lib/api";
import type { User, AuthState, LoginCredentials, RegisterCredentials, LoginResponse } from "@/types";

interface AuthContextType extends AuthState {
    login: (credentials: LoginCredentials) => Promise<LoginResponse | void>;
    verifyMfa: (factorId: string, code: string, tempToken: string) => Promise<any>;
    loginWithOAuth: (provider: "google" | "github") => Promise<void>;
    register: (credentials: RegisterCredentials) => Promise<void>;
    logout: () => Promise<void>;
    refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
    const router = useRouter();
    const [state, setState] = useState<AuthState>({
        user: null,
        token: null,
        isLoading: true,
        isAuthenticated: false,
    });

    // ─── Fetch user profile from backend ─────────────────────
    const fetchUser = useCallback(async (token: string) => {
        try {
            const user = await api.get<User>("/api/v1/users/me", token);
            
            // Check if user is inactive — redirect immediately
            if (user.is_active === false) {
                setState({
                    user,
                    token,
                    isLoading: false,
                    isAuthenticated: false,
                });
                // Redirect after a short delay to ensure state updates
                setTimeout(() => {
                    router.push("/suspended-account");
                }, 100);
                return;
            }
            
            setState({
                user,
                token,
                isLoading: false,
                isAuthenticated: true,
            });
        } catch (error: any) {
            localStorage.removeItem("tibsa_access_token");
            localStorage.removeItem("tibsa_refresh_token");
            api.defaults.headers.common.Authorization = "";
            setState({ user: null, token: null, isLoading: false, isAuthenticated: false });

            // Check if error is account deactivated
            if (error?.message?.includes("deactivated") || error?.message?.includes("inactive")) {
                setTimeout(() => {
                    router.push("/suspended-account");
                }, 100);
                return;
            }

            // On generic fetchUser failure (e.g. 401/403), redirect to login
            router.push("/login");
        }
    }, [router]);

    // ─── Initialize Auth State ───────────────
    useEffect(() => {
        // Clear all old Supabase auth keys
        const keysToRemove = [];
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && key.startsWith("sb-") && key.endsWith("-auth-token")) {
                keysToRemove.push(key);
            }
        }
        keysToRemove.forEach(k => localStorage.removeItem(k));

        const access_token = localStorage.getItem("tibsa_access_token");
        if (access_token) {
            api.defaults.headers.common.Authorization = `Bearer ${access_token}`;
            setState({ user: null, token: access_token, isLoading: true, isAuthenticated: true });
            fetchUser(access_token).catch(console.error);
        } else {
            setState({ user: null, token: null, isLoading: false, isAuthenticated: false });
        }
    }, [fetchUser]);

    // ─── Auth Actions ─────────────────────────────────────────
    const login = async (credentials: LoginCredentials) => {
        // Use secure backend endpoint (enforces rate limits and auditing)
        try {
            const res = await api.post<LoginResponse>("/api/v1/auth/login", credentials);
            
            if (res.mfa_required) {
                // Do not set session yet, let the UI handle MFA
                return res;
            }

            if (res.access_token && res.refresh_token) {
                localStorage.setItem("tibsa_access_token", res.access_token);
                localStorage.setItem("tibsa_refresh_token", res.refresh_token);
                api.defaults.headers.common.Authorization = `Bearer ${res.access_token}`;
                setState({ user: null, token: res.access_token, isLoading: true, isAuthenticated: true });
                fetchUser(res.access_token).catch(console.error);
            }
        } catch (err: any) {
            throw new Error(err.message || "Invalid credentials");
        }
    };

    const verifyMfa = async (factorId: string, code: string, tempToken: string) => {
        try {
            console.log("[verifyMfa] calling api.post");
            const res = await api.post<{ access_token: string, refresh_token: string }>(
                "/api/v1/auth/mfa/verify",
                { factor_id: factorId, code, mfa_token: tempToken }
            );
            console.log("[verifyMfa] api.post returned", res);
            
            if (res.access_token && res.refresh_token) {
                localStorage.setItem("tibsa_access_token", res.access_token);
                localStorage.setItem("tibsa_refresh_token", res.refresh_token);
                api.defaults.headers.common.Authorization = `Bearer ${res.access_token}`;

                // Immediately update state
                setState(prev => ({
                    ...prev,
                    token: res.access_token,
                    isAuthenticated: true,
                }));

                // Non-blocking fetch
                fetchUser(res.access_token).catch(console.error);
                
                return res;
            }
            return res;
        } catch (err: any) {
            throw new Error(err.message || "Invalid verification code");
        }
    };

    const register = async (credentials: RegisterCredentials) => {
        // Use secure backend endpoint (enforces password policies and rate limits)
        try {
            const res = await api.post<{ access_token: string, refresh_token: string }>("/api/v1/auth/register", credentials);
            if (res.access_token && res.refresh_token) {
                localStorage.setItem("tibsa_access_token", res.access_token);
                localStorage.setItem("tibsa_refresh_token", res.refresh_token);
                api.defaults.headers.common.Authorization = `Bearer ${res.access_token}`;
                setState({ user: null, token: res.access_token, isLoading: true, isAuthenticated: true });
                fetchUser(res.access_token).catch(console.error);
            }
        } catch (err: any) {
            // Use generic error for user enumeration protection where possible
            throw new Error(err.message || "Registration failed. Please check your inputs.");
        }
    };

    const logout = async () => {
        try {
            if (state.token) {
                await api.post("/api/v1/auth/logout", {}, state.token);
            }
        } catch (err) {
            console.error("Failed to log out on backend:", err);
        }
        localStorage.removeItem("tibsa_access_token");
        localStorage.removeItem("tibsa_refresh_token");
        api.defaults.headers.common.Authorization = "";
        setState({ user: null, token: null, isLoading: false, isAuthenticated: false });
        router.push("/");
    };

    const loginWithOAuth = async (provider: "google" | "github") => {
        const { error } = await supabase.auth.signInWithOAuth({
            provider,
            options: {
                redirectTo: `${window.location.origin}/dashboard`,
            },
        });
        if (error) throw new Error(error.message);
    };

    const refreshUser = async () => {
        const access_token = localStorage.getItem("tibsa_access_token");
        if (access_token) {
            await fetchUser(access_token);
        }
    };

    return (
        <AuthContext.Provider value={{ ...state, login, verifyMfa, loginWithOAuth, register, logout, refreshUser }}>
            {children}
        </AuthContext.Provider>
    );
}

export function useAuthContext() {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error("useAuthContext must be used within an AuthProvider");
    }
    return context;
}
