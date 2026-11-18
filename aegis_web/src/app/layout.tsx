import type { Metadata, Viewport } from "next";
import { MedeoSans } from "medeo-font/sans";
import { MedeoMono } from "medeo-font/mono";
import { MedeoSerif } from "medeo-font/serif";
import { MedeoPixel } from "medeo-font/pixel";
import "./globals.css";
import { Providers } from "@/components/Providers";

export const metadata: Metadata = {
  title: "Commit Guardian — On-Premise AI AppSec & Chat",
  description:
    "Локальный AI-ассистент и аудитор безопасности коммитов: чат с Qwen/Ollama, SAST, Taint-анализ, защита ИИН и PDF-отчёты без утечки кода в облако.",
};

export const viewport: Viewport = {
  colorScheme: "light dark",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="ru"
      suppressHydrationWarning
      className={`${MedeoSans.variable} ${MedeoMono.variable} ${MedeoSerif.variable} ${MedeoPixel.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col font-sans selection:bg-[#e94a32] selection:text-white">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
