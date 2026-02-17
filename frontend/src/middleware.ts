import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { createClient } from "@supabase/supabase-js";

/**
 * Middleware to protect routes.
 * - /dashboard/* and /admin/* require authentication
 * - /login and /register redirect to /dashboard if already authenticated
 */
export async function middleware(request: NextRequest) {
    const { pathname } = request.nextUrl;

    // Routes that require authentication
    const protectedRoutes = ["/dashboard", "/admin"];
    // Routes that should redirect if already logged in
    const authRoutes = ["/login", "/register"];

    const isProtectedRoute = protectedRoutes.some((route) => pathname.startsWith(route));
    const isAuthRoute = authRoutes.some((route) => pathname.startsWith(route));

    // Check for Supabase session cookie
    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
    const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

    if (!supabaseUrl || !supabaseAnonKey) {
        return NextResponse.next();
    }

    // Get the access token from cookies
    const accessToken = request.cookies.get("sb-access-token")?.value
        || request.cookies.get(`sb-${new URL(supabaseUrl).hostname.split(".")[0]}-auth-token`)?.value;

    const hasSession = !!accessToken;

    if (isProtectedRoute && !hasSession) {
        const url = request.nextUrl.clone();
        url.pathname = "/login";
        url.searchParams.set("redirect", pathname);
        return NextResponse.redirect(url);
    }

    if (isAuthRoute && hasSession) {
        return NextResponse.redirect(new URL("/dashboard", request.url));
    }

    return NextResponse.next();
}

export const config = {
    matcher: ["/dashboard/:path*", "/admin/:path*", "/login", "/register"],
};
