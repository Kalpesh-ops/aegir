import ScanResultClient from '@/components/ScanResultClient'
import { DEMO_SCAN_DETAIL, DEMO_SCANS } from '@/lib/demoData'
import { notFound } from 'next/navigation'

export function generateStaticParams() {
  return DEMO_SCANS.map((s) => ({ id: s.id }))
}

const DETAIL_BY_ID = {
  [DEMO_SCAN_DETAIL.id]: DEMO_SCAN_DETAIL,
}

function buildPlaceholderDetail(summary) {
  // For showcase scans without a curated AI body, render the summary card
  // (KPIs + port table) only.
  return {
    id: summary.id,
    user_id: 'demo-user-0001',
    target_redacted: summary.target_redacted,
    scan_mode: summary.scan_mode,
    scan_timestamp: summary.scan_timestamp,
    ports_json: summary.ports_json || [],
    cve_findings_json: [],
    cve_count: summary.cve_count || 0,
    highest_cvss: summary.highest_cvss || 0,
    crit_count: summary.crit_count || 0,
    high_count: summary.high_count || 0,
    med_count: summary.med_count || 0,
    low_count: summary.low_count || 0,
    firewall_json: null,
    traffic_json: null,
    ai_summary: '## AI report preview\n\nA detailed Gemini-powered remediation report is available for this scan in the desktop app. The showcase site renders only the deterministic scan output (ports, services, CVE counts) so you can see the data structure without consuming AI quota.',
  }
}

export default async function ScanResultPage({ params: paramsPromise }) {
  const params = await paramsPromise
  const summary = DEMO_SCANS.find((s) => s.id === params.id)
  if (!summary) notFound()
  const detail = DETAIL_BY_ID[params.id] || buildPlaceholderDetail(summary)

  return (
    <ScanResultClient
      id={detail.id}
      target_redacted={detail.target_redacted}
      scan_timestamp={detail.scan_timestamp}
      ports={detail.ports_json}
      cve_findings={detail.cve_findings_json}
      ai_summary={detail.ai_summary}
      firewall={detail.firewall_json}
      traffic={detail.traffic_json}
      scan_mode={detail.scan_mode}
    />
  )
}
