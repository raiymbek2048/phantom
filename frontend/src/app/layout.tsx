import type { Metadata } from "next";
import "./globals.css";
import ToastContainer from "@/components/ToastContainer";
import LiveScanBar from "@/components/LiveScanBar";

export const metadata: Metadata = {
  title: "PHANTOM - AI Pentester",
  description: "AI-Powered Autonomous Penetration Testing System",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <body className="bg-gray-950 text-gray-100 min-h-screen antialiased">
        <LiveScanBar />
        {children}
        <ToastContainer />
      </body>
    </html>
  );
}
