import Navbar from '@/components/Navbar'
import Footer from '@/components/Footer'

export const metadata = {
  title: 'Legal — Aegir',
  description: 'Privacy, terms, consent and disclaimer documents for the Aegir network security intelligence platform.',
}

export default function LegalLayout({ children }) {
  return (
    <>
      <Navbar />
      <main style={{
        minHeight: '60vh',
        background: '#060608',
        padding: '140px 32px 80px',
      }}>
        <div style={{ maxWidth: '900px', margin: '0 auto' }}>
          {children}
        </div>
      </main>
      <Footer />
    </>
  )
}
