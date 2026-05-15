import { Syne, JetBrains_Mono, Instrument_Sans } from 'next/font/google'
import './globals.css'

const syne = Syne({
  subsets: ['latin'],
  weight: ['400', '500', '600'],
  variable: '--font-syne',
  display: 'swap',
})

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  weight: ['300', '400', '500', '700'],
  variable: '--font-mono',
  display: 'swap',
})

const instrumentSans = Instrument_Sans({
  subsets: ['latin'],
  weight: 'variable',
  variable: '--font-body',
  display: 'swap',
})

export const metadata = {
  title: 'Aegir — Network Intelligence Scanner',
  description: 'Real CVE correlation. AI-powered analysis. Your network\'s threat surface, decoded in seconds.',
}

export default function RootLayout({ children }) {
  return (
    <html lang="en" data-scroll-behavior="smooth">
      <body className={`${syne.variable} ${jetbrainsMono.variable} ${instrumentSans.variable}`}>
        {children}
      </body>
    </html>
  )
}
