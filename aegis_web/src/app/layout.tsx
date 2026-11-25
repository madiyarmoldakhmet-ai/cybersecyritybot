import type { Metadata, Viewport } from "next";
import { Pixelify_Sans, Press_Start_2P } from "next/font/google";
import { MedeoMono } from "medeo-font/mono";
import "./globals.css";
import { Providers } from "@/components/Providers";

const pixelifySans = Pixelify_Sans({
  subsets: ["latin", "cyrillic"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-pixel-body",
  display: "swap",
});

const pressStart2P = Press_Start_2P({
  subsets: ["latin", "cyrillic"],
  weight: "400",
  variable: "--font-pixel-display",
  display: "swap",
});

export const metadata: Metadata = {
  title: "Commit Guardian — 16-Bit Christmas AI AppSec & Chat",
  description:
    "Праздничный 16-битный пиксельный AI-аудитор безопасности коммитов: Aegis Orca, 14 сканеров, системный анализ, защита ИИН и PDF-отчёты.",
};

export const viewport: Viewport = {
  colorScheme: "light dark",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="ru"
      suppressHydrationWarning
      className={`${pixelifySans.variable} ${pressStart2P.variable} ${MedeoMono.variable} h-full`}
    >
      <body className="min-h-full flex flex-col font-sans selection:bg-[#e94a32] selection:text-white">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
