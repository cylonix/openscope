import type { Metadata } from "next";
import { Manrope, Newsreader } from "next/font/google";
import { ThemeScript } from "@/components/theme-script";
import "./globals.css";

// Same fonts the openscopeai.com marketing site uses. next/font/google
// downloads at build time and self-hosts the woff2 — avoids the @import
// URL that PostCSS strips when bundling Tailwind.
const manrope = Manrope({
  weight: ["300", "400", "500", "600", "700"],
  variable: "--font-manrope",
  subsets: ["latin"],
  display: "swap",
});
const newsreader = Newsreader({
  weight: ["400", "700", "800"],
  style: ["italic"],
  variable: "--font-newsreader",
  subsets: ["latin"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "OpenScope Demo",
  description: "OpenScope — AI Agent Trust Perimeter. Customer-deployed router + DLP + audited Bedrock access.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    // suppressHydrationWarning: ThemeScript mutates <html> attrs before
    // React hydrates, which would otherwise trigger a mismatch warning.
    <html
      lang="en"
      className={`${manrope.variable} ${newsreader.variable} h-full antialiased`}
      suppressHydrationWarning
    >
      <head>
        <ThemeScript />
      </head>
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
