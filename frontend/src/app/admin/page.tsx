"use client";

import { Card } from "@/components/ui";

export default function AdminPage() {
    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-2xl font-bold text-white">Admin Panel</h1>
                <p className="text-slate-400 mt-1">System overview and management</p>
            </div>

            {/* Admin Stats */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <Card className="!p-4">
                    <div className="text-sm text-slate-400">Total Users</div>
                    <div className="text-2xl font-bold text-white mt-1">0</div>
                </Card>
                <Card className="!p-4">
                    <div className="text-sm text-slate-400">Active Scans</div>
                    <div className="text-2xl font-bold text-blue-400 mt-1">0</div>
                </Card>
                <Card className="!p-4">
                    <div className="text-sm text-slate-400">Threats Today</div>
                    <div className="text-2xl font-bold text-red-400 mt-1">0</div>
                </Card>
                <Card className="!p-4">
                    <div className="text-sm text-slate-400">System Health</div>
                    <div className="text-2xl font-bold text-green-400 mt-1">OK</div>
                </Card>
            </div>

            {/* Quick Admin Actions */}
            <Card title="Admin Actions">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <a href="/admin/users" className="block p-4 rounded-lg border border-white/[0.08] hover:border-blue-500/30 hover:bg-blue-500/10 transition-all">
                        <h3 className="font-semibold text-white">👥 User Management</h3>
                        <p className="text-sm text-slate-400 mt-1">Manage users, assign roles (user/admin)</p>
                    </a>
                    <a href="/admin/threats" className="block p-4 rounded-lg border border-white/[0.08] hover:border-blue-500/30 hover:bg-blue-500/10 transition-all">
                        <h3 className="font-semibold text-white">🛡️ Threat Feeds</h3>
                        <p className="text-sm text-slate-400 mt-1">Configure threat intelligence feeds</p>
                    </a>
                    <a href="/admin/system" className="block p-4 rounded-lg border border-white/[0.08] hover:border-blue-500/30 hover:bg-blue-500/10 transition-all">
                        <h3 className="font-semibold text-white">⚙️ System Settings</h3>
                        <p className="text-sm text-slate-400 mt-1">API keys, billing, RBAC settings</p>
                    </a>
                    <a href="/admin/users" className="block p-4 rounded-lg border border-white/[0.08] hover:border-blue-500/30 hover:bg-blue-500/10 transition-all">
                        <h3 className="font-semibold text-white">📊 Analytics</h3>
                        <p className="text-sm text-slate-400 mt-1">Platform usage and security metrics</p>
                    </a>
                </div>
            </Card>
        </div>
    );
}
