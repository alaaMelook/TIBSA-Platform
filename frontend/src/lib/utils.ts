import { type ClassValue, clsx } from "clsx";

/**
 * Merge class names (useful with Tailwind)
 */
export function cn(...inputs: ClassValue[]) {
    return clsx(inputs);
}

/**
 * Format a date to a human-readable string
 */
export function formatDate(date: string | Date): string {
    return new Intl.DateTimeFormat("en-US", {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
    }).format(new Date(date));
}

/**
 * Truncate text with ellipsis
 */
export function truncate(text: string, maxLength: number): string {
    if (text.length <= maxLength) return text;
    return text.slice(0, maxLength) + "...";
}
