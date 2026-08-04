import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { headers } from "next/headers";
import "./globals.css";

const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });
const themeScript = `try{const saved=localStorage.getItem("openlake-theme");document.documentElement.dataset.theme=saved??(matchMedia("(prefers-color-scheme: light)").matches?"light":"dark")}catch{}`;

export async function generateMetadata(): Promise<Metadata> {
  const requestHeaders = await headers();
  const host = requestHeaders.get("x-forwarded-host") ?? requestHeaders.get("host") ?? "localhost:3000";
  const protocol = requestHeaders.get("x-forwarded-proto") ?? (host.startsWith("localhost") ? "http" : "https");
  const origin = `${protocol}://${host}`;
  const description = "Operate high-performance storage for AI infrastructure with OpenLake.";

  return {
    metadataBase: new URL(origin),
    title: { default: "OpenLake Control Plane", template: "%s · OpenLake" },
    description,
    icons: { icon: "/favicon.svg", shortcut: "/favicon.svg" },
    openGraph: {
      title: "OpenLake · Control plane for AI infrastructure",
      description,
      type: "website",
      url: origin,
    },
    twitter: {
      card: "summary",
      title: "OpenLake · Control plane for AI infrastructure",
      description,
    },
  };
}

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head><script dangerouslySetInnerHTML={{ __html: themeScript }}/></head>
      <body className={`${geistSans.variable} ${geistMono.variable}`}>{children}</body>
    </html>
  );
}
