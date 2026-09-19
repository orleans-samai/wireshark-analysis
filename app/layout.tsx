import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PacketLens — Network Analysis",
  description: "Análise visual, privada e local de capturas PCAP e PCAPNG.",
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="pt-BR" className="dark">
      <body className="antialiased">{children}</body>
    </html>
  );
}
