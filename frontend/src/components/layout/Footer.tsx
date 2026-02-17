export function Footer() {
    return (
        <footer className="border-t border-gray-200 bg-white py-6">
            <div className="container mx-auto px-4 text-center text-sm text-gray-500">
                <p>&copy; {new Date().getFullYear()} TIBSA — Threat Intelligence-Based Security Application</p>
                <p className="mt-1">Graduation Project</p>
            </div>
        </footer>
    );
}
