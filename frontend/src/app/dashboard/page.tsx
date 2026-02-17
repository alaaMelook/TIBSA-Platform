"use client";

import { useAuth } from "@/hooks/useAuth";
import { Card } from "@/components/ui";

export default function DashboardPage() {
    const { user } = useAuth();

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
                <p className="text-gray-500 mt-1">Welcome back, {user?.full_name}</p>
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <Card className="!p-4">
                    <div className="text-sm text-gray-500">Total Scans</div>
                    <div className="text-2xl font-bold text-gray-900 mt-1">0</div>
                </Card>
                <Card className="!p-4">
                    <div className="text-sm text-gray-500">Threats Detected</div>
                    <div className="text-2xl font-bold text-red-600 mt-1">0</div>
                </Card>
                <Card className="!p-4">
                    <div className="text-sm text-gray-500">Active Scans</div>
                    <div className="text-2xl font-bold text-blue-600 mt-1">0</div>
                </Card>
                <Card className="!p-4">
                    <div className="text-sm text-gray-500">Reports</div>
                    <div className="text-2xl font-bold text-gray-900 mt-1">0</div>
                </Card>
            </div>

            {/* Quick Actions */}
            <Card title="Quick Actions">
                <div className="flex flex-wrap gap-3">
                    <button className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-700 transition-colors">
                        🔍 New URL Scan
                    </button>
                    <button className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-700 transition-colors">
                        📁 Upload File for Scan
                    </button>
                    <button className="px-4 py-2 bg-gray-100 text-gray-700 rounded-lg text-sm hover:bg-gray-200 transition-colors">
                        📄 View Reports
                    </button>
                </div>
            </Card>

            {/* Recent Activity */}
            <Card title="Recent Activity" description="Your latest scans and threat detections">
                <div className="text-center py-8 text-gray-400">
                    <p>No recent activity yet.</p>
                    <p className="text-sm mt-1">Start by scanning a URL or uploading a file.</p>
                </div>
            </Card>
        </div>
    );
}
