'use client'

import { useEffect, useRef } from 'react'

export default function ParticleBackground() {
  const canvasRef = useRef(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')

    let W = 0, H = 0
    let particles = []
    let mouse = { x: -999, y: -999 }
    let animFrameId

    function resize() {
      W = canvas.width = canvas.offsetWidth
      H = canvas.height = canvas.offsetHeight
    }

    function Particle() {
      this.reset = function () {
        this.x = Math.random() * W
        this.y = Math.random() * H
        this.ox = this.x
        this.oy = this.y
        this.vx = (Math.random() - 0.5) * 0.4
        this.vy = (Math.random() - 0.5) * 0.4
        this.r = Math.random() * 1.5 + 0.5
        this.alpha = Math.random() * 0.5 + 0.1
      }
      this.reset()
    }

    function initParticles() {
      const count = Math.min(Math.floor((W * H) / 12000), 120)
      particles = Array.from({ length: count }, () => new Particle())
    }

    function drawParticles() {
      ctx.clearRect(0, 0, W, H)
      const maxDist = 120
      const repelDist = 80

      for (let i = 0; i < particles.length; i++) {
        const p = particles[i]
        p.x += p.vx
        p.y += p.vy
        if (p.x < 0 || p.x > W) p.vx *= -1
        if (p.y < 0 || p.y > H) p.vy *= -1

        const dx = p.x - mouse.x
        const dy = p.y - mouse.y
        const dist = Math.sqrt(dx * dx + dy * dy)
        if (dist < repelDist) {
          const force = (repelDist - dist) / repelDist
          p.x += (dx / dist) * force * 2.5
          p.y += (dy / dist) * force * 2.5
        }

        ctx.beginPath()
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2)
        ctx.fillStyle = `rgba(0,255,136,${p.alpha})`
        ctx.fill()

        for (let j = i + 1; j < particles.length; j++) {
          const q = particles[j]
          const ddx = p.x - q.x
          const ddy = p.y - q.y
          const d = Math.sqrt(ddx * ddx + ddy * ddy)
          if (d < maxDist) {
            const alpha = (1 - d / maxDist) * 0.12
            ctx.beginPath()
            ctx.moveTo(p.x, p.y)
            ctx.lineTo(q.x, q.y)
            ctx.strokeStyle = `rgba(0,255,136,${alpha})`
            ctx.lineWidth = 0.5
            ctx.stroke()
          }
        }
      }
      animFrameId = requestAnimationFrame(drawParticles)
    }

    function onMouseMove(e) {
      const r = canvas.getBoundingClientRect()
      mouse.x = e.clientX - r.left
      mouse.y = e.clientY - r.top
    }

    function onMouseLeave() {
      mouse.x = -999
      mouse.y = -999
    }

    function onResize() {
      resize()
      initParticles()
    }

    resize()
    initParticles()
    drawParticles()

    document.addEventListener('mousemove', onMouseMove)
    document.addEventListener('mouseleave', onMouseLeave)
    window.addEventListener('resize', onResize)

    return () => {
      cancelAnimationFrame(animFrameId)
      document.removeEventListener('mousemove', onMouseMove)
      document.removeEventListener('mouseleave', onMouseLeave)
      window.removeEventListener('resize', onResize)
    }
  }, [])

  return <canvas id="particle-canvas" ref={canvasRef} />
}
