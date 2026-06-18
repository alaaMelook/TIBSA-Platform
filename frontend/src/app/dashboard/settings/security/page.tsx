import { MFAEnrollment } from "@/components/MFAEnrollment";

export default function SecuritySettingsPage() {
    return (
        <div className="max-w-4xl mx-auto">
            <div className="mb-8">
                <h1 className="text-2xl font-bold text-[var(--text-primary)] tracking-tight">Security Settings</h1>
                <p className="text-[var(--text-muted)] mt-1">Manage your account security and authentication methods.</p>
            </div>

            <div className="space-y-6">
                <MFAEnrollment />
            </div>
        </div>
    );
}
