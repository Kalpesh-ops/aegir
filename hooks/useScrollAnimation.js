import { useEffect } from 'react'

export function useScrollAnimation() {
  useEffect(() => {
    /* ── SCROLL REVEAL ── */
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((el) => {
          if (el.isIntersecting) {
            el.target.classList.add('visible')
            observer.unobserve(el.target)
          }
        })
      },
      { threshold: 0.15 }
    )

    document
      .querySelectorAll('.reveal, .feature-card, .pipe-step')
      .forEach((el) => observer.observe(el))

    /* ── STICKY SCROLL — HOW IT WORKS ── */
    const howSection = document.getElementById('how-it-works')
    const steps = document.querySelectorAll('.how-step')
    const progressFill = document.getElementById('progress-fill')
    const terminalBody = document.getElementById('terminal-body')

    const termLines = [
      ['22:14:01', 'ok', 'INIT', 'Scanner kernel started', ''],
      ['22:14:01', '', 'INFO', 'Target: ', '192.168.1.1'],
      ['22:14:02', '', 'SCAN', 'Nmap engine initialized', ''],
      ['22:14:03', 'ok', 'OPEN', 'Port ', '22/tcp — OpenSSH 8.4'],
      ['22:14:03', 'ok', 'OPEN', 'Port ', '80/tcp — Apache 2.4.49'],
      ['22:14:04', 'warn', 'WARN', 'Port ', '3306/tcp — MySQL exposed'],
      ['22:14:05', '', 'CVE', 'Querying CIRCL database...', ''],
      ['22:14:05', 'err', 'CRIT', '', 'CVE-2021-41773 CVSS 9.8'],
      ['22:14:06', 'warn', 'HIGH', '', 'CVE-2022-22965 CVSS 7.2'],
      ['22:14:07', 'ok', 'PII', 'Redaction complete — 3 fields masked', ''],
      ['22:14:08', '', 'AI', 'Gemini analysis in progress...', ''],
      ['22:14:11', 'ok', 'DONE', 'Report generated — ', '2 critical'],
    ]

    function updateHowSection() {
      const rect = howSection.getBoundingClientRect()
      const sectionH = howSection.offsetHeight - window.innerHeight
      const progress = Math.max(0, Math.min(1, -rect.top / sectionH))

      const stepIdx = Math.min(2, Math.floor(progress * 3))
      steps.forEach((s, i) => s.classList.toggle('active', i === stepIdx))
      progressFill.style.height = progress * 100 + '%'

      const lines = terminalBody.children
      const lineCount = Math.floor(progress * termLines.length * 1.3)
      Array.from(lines).forEach((line, i) => {
        line.style.opacity = i <= lineCount ? '1' : '0.15'
      })
    }

    window.addEventListener('scroll', updateHowSection, { passive: true })

    /* ── COUNTER ANIMATION ── */
    const metricsObs = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return
          const items = entry.target.querySelectorAll('.metric-item')
          items.forEach((item, i) => {
            const target = parseInt(item.dataset.target)
            const el = item.querySelector('.count-val')
            if (!el) return
            item.classList.add('counting')
            const duration = 1600
            const start = performance.now()
            function update(now) {
              const t = Math.min((now - start) / duration, 1)
              const ease = 1 - Math.pow(1 - t, 3)
              const val = Math.round(ease * target)
              el.textContent = val.toLocaleString()
              if (t < 1) requestAnimationFrame(update)
            }
            setTimeout(() => requestAnimationFrame(update), i * 120)
          })
          metricsObs.unobserve(entry.target)
        })
      },
      { threshold: 0.3 }
    )

    const metricsGrid = document.querySelector('.metrics-grid')
    if (metricsGrid) metricsObs.observe(metricsGrid)

    /* ── REDUCE MOTION ── */
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      document
        .querySelectorAll('[style*="animation"]')
        .forEach((el) => (el.style.animation = 'none'))
    }

    return () => {
      observer.disconnect()
      window.removeEventListener('scroll', updateHowSection)
      metricsObs.disconnect()
    }
  }, [])
}
