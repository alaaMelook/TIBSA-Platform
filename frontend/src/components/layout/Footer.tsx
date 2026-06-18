export function Footer() {
    return (
        <footer className="border-t border-[var(--border-soft)] bg-[var(--bg-main)] py-6">
            <div className="container mx-auto px-4 text-center text-sm text-[var(--text-muted)]">
                <p>&copy; {new Date().getFullYear()} TIBSA — Threat Intelligence-Based Security Application</p>
                <p className="mt-1">Graduation Project</p>
            </div>
        </footer>
    );
}
