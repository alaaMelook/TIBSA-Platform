"use client";

import { redirect } from "next/navigation";

export default function ThreatsPage() {
    redirect("/dashboard");
    return null;
}
