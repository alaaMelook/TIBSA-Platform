import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { AuthProvider } from "@/contexts/AuthContext";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "TIBSA — Threat Intelligence-Based Security Application",
  description: "A cybersecurity platform for threat intelligence, scanning, and security analysis.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `
              if (typeof window !== 'undefined') {
                const isMetaMaskError = (e) => {
                  const msg = e.message || e.reason?.message || e.reason || '';
                  return typeof msg === 'string' && (msg.includes('MetaMask') || msg.includes('chrome-extension://'));
                };
                window.addEventListener('error', (e) => {
                  if (isMetaMaskError(e)) {
                    e.stopImmediatePropagation();
                  }
                }, true);
                window.addEventListener('unhandledrejection', (e) => {
                  if (isMetaMaskError(e)) {
                    e.stopImmediatePropagation();
                  }
                }, true);
              }
            `,
          }}
        />
      </head>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
        suppressHydrationWarning
      >
        <AuthProvider>
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}
