"use client";

import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import { supabase } from "@/lib/supabase";
import { api } from "@/lib/api";
import type { User, AuthState, LoginCredentials, RegisterCredentials } from "@/types";

interface AuthContextType extends AuthState {
    login: (credentials: LoginCredentials) => Promise<void>;
    register: (credentials: RegisterCredentials) => Promise<void>;
    logout: () => Promise<void>;
    refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
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
            setState({
                user,
                token,
                isLoading: false,
                isAuthenticated: true,
            });
        } catch {
            setState({ user: null, token: null, isLoading: false, isAuthenticated: false });
        }
    }, []);

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
        const { error } = await supabase.auth.signInWithPassword({
            email: credentials.email,
            password: credentials.password,
        });
        if (error) throw new Error(error.message);
    };

    const register = async (credentials: RegisterCredentials) => {
        // 1. Register with Supabase Auth
        const { data, error } = await supabase.auth.signUp({
            email: credentials.email,
            password: credentials.password,
            options: {
                data: { full_name: credentials.full_name },
            },
        });
        if (error) throw new Error(error.message);

        // 2. Create user profile in backend (role defaults to "user")
        if (data.session?.access_token) {
            await api.post("/api/v1/users/register", {
                email: credentials.email,
                full_name: credentials.full_name,
            }, data.session.access_token);
        }
    };

    const logout = async () => {
        await supabase.auth.signOut();
        setState({ user: null, token: null, isLoading: false, isAuthenticated: false });
    };

    const refreshUser = async () => {
        const { data: { session } } = await supabase.auth.getSession();
        if (session?.access_token) {
            await fetchUser(session.access_token);
        }
    };

    return (
        <AuthContext.Provider value={{ ...state, login, register, logout, refreshUser }}>
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
