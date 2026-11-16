import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Sentinel OSINT — Advanced All-in-One Intelligence Platform',
  description:
    'Defensive cybersecurity, authorized infrastructure reconnaissance, threat intelligence, and multi-source public OSINT investigation workspace.'
};

export default function RootLayout({
  children
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="antialiased selection:bg-cyan-500 selection:text-slate-950">
        {children}
      </body>
    </html>
  );
}
