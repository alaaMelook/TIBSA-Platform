import { NextResponse } from "next/server";

// No-op middleware — all route protection is handled client-side by RoleGuard
export function middleware() {
    return NextResponse.next();
}

// Don't match any routes (effectively disables middleware)
export const config = {
    matcher: [],
};
