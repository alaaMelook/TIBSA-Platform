"use client";

import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { supabase } from "@/lib/supabase";
import { api } from "@/lib/api";
import type { User, AuthState, LoginCredentials, RegisterCredentials } from "@/types";

interface AuthContextType extends AuthState {
    login: (credentials: LoginCredentials) => Promise<void>;
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
            // Check if error is account deactivated
            if (error?.message?.includes("deactivated") || error?.message?.includes("inactive")) {
                setState({
                    user: null,
                    token: null,
                    isLoading: false,
                    isAuthenticated: false,
                });
                setTimeout(() => {
                    router.push("/suspended-account");
                }, 100);
                return;
            }

            // Backend might be down or profile not ready yet.
            // Still mark as authenticated with basic info from Supabase session.
            try {
                const { data: { user: authUser } } = await supabase.auth.getUser(token);
                if (authUser) {
                    setState({
                        user: {
                            id: authUser.id,
                            email: authUser.email || "",
                            full_name: authUser.user_metadata?.full_name || authUser.email?.split("@")[0] || "",
                            role: "user",
                            is_active: true,
                            created_at: authUser.created_at || "",
                            updated_at: "",
                        },
                        token,
                        isLoading: false,
                        isAuthenticated: true,
                    });
                    return;
                }
            } catch {
                // Supabase call also failed
            }
            setState({ user: null, token: null, isLoading: false, isAuthenticated: false });
        }
    }, [router]);

    // ─── Listen to Supabase auth state changes ───────────────
    useEffect(() => {
        const { data: { subscription } } = supabase.auth.onAuthStateChange(
            async (event, session) => {
                if (session?.access_token) {
                    await fetchUser(session.access_token);
                } else {
                    setState({ user: null, token: null, isLoading: false, isAuthenticated: false });
                }
            }
        );

        // Check initial session
        supabase.auth.getSession().then(({ data: { session } }) => {
            if (session?.access_token) {
                fetchUser(session.access_token);
            } else {
                setState((prev) => ({ ...prev, isLoading: false }));
            }
        });

        return () => subscription.unsubscribe();
    }, [fetchUser]);

    // ─── Auth Actions ─────────────────────────────────────────
    const login = async (credentials: LoginCredentials) => {
        // Use secure backend endpoint (enforces rate limits and auditing)
        try {
            const res = await api.post<{ access_token: string, refresh_token: string }>("/api/v1/auth/login", credentials);
            if (res.access_token && res.refresh_token) {
                const { error } = await supabase.auth.setSession({
                    access_token: res.access_token,
                    refresh_token: res.refresh_token
                });
                if (error) throw new Error(error.message);
                await fetchUser(res.access_token);
            }
        } catch (err: any) {
            throw new Error(err.message || "Invalid credentials");
        }
    };

    const register = async (credentials: RegisterCredentials) => {
        // Use secure backend endpoint (enforces password policies and rate limits)
        try {
            const res = await api.post<{ access_token: string, refresh_token: string }>("/api/v1/auth/register", credentials);
            if (res.access_token && res.refresh_token) {
                const { error } = await supabase.auth.setSession({
                    access_token: res.access_token,
                    refresh_token: res.refresh_token
                });
                if (error) throw new Error(error.message);
                await fetchUser(res.access_token);
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
        await supabase.auth.signOut();
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
        const { data: { session } } = await supabase.auth.getSession();
        if (session?.access_token) {
            await fetchUser(session.access_token);
        }
    };

    return (
        <AuthContext.Provider value={{ ...state, login, loginWithOAuth, register, logout, refreshUser }}>
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
