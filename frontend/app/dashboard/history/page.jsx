import HistoryClient from '@/components/HistoryClient'
import { DEMO_SCANS } from '@/lib/demoData'

export default function HistoryPage() {
  return <HistoryClient scans={DEMO_SCANS} />
}
