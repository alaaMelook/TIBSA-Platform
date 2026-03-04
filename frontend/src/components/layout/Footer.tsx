export function Footer() {
    return (
        <footer className="border-t border-white/[0.08] bg-[#0f172a] py-6">
            <div className="container mx-auto px-4 text-center text-sm text-slate-500">
                <p>&copy; {new Date().getFullYear()} TIBSA — Threat Intelligence-Based Security Application</p>
                <p className="mt-1">Graduation Project</p>
            </div>
        </footer>
    );
}
