export interface User {
  id: string
  email: string
  role: string
}

export interface Engagement {
  id: string
  client_name: string
  engagement_name: string
  authorized_scope: string[]
  start_date: string | null
  end_date: string | null
  status: string
  created_by: string | null
  created_at: string
}

export interface Scan {
  id: string
  engagement_id: string
  targets: string[]
  profile: string
  port_range: string
  protocol: string
  status: string
  kind: string
  hosts_total_in_scope: number
  hosts_discovered: number
  progress_pct: number
  started_at: string | null
  completed_at: string | null
  verified_at: string | null
  started_by: string | null
  created_at: string
}

export interface Host {
  id: string
  scan_id: string
  ip: string
  mac: string | null
  vendor: string | null
  hostname: string | null
  device_type: string | null
  os_guess: string | null
  os_confidence: number | null
  status: string
  discovery_method: string[] | null
  first_seen: string
  last_seen: string
  notes: string
  tags: string[] | null
}

export interface Port {
  id: string
  port: number
  protocol: string
  state: string
  service: string | null
  version: string | null
  banner: string | null
}

export interface HostDetail extends Host {
  ports: Port[]
  snmp: {
    sys_descr: string | null
    sys_name: string | null
    sys_location: string | null
    default_community_found: boolean
  } | null
}

export interface Finding {
  id: string
  scan_id: string
  host_id: string | null
  host_ip?: string | null
  severity: string
  type: string
  title: string
  description: string | null
  recommendation: string | null
  cve_refs: string[] | null
  port: number | null
  included_in_report: boolean
}

export interface Topology {
  nodes: Array<{
    id: string
    ip: string
    label: string
    device_type: string
    severity: string
  }>
  edges: Array<{
    source: string
    target: string
    type: string
  }>
}

export type Severity = 'info' | 'notable' | 'concerning' | 'critical'

export const SEVERITY_COLORS: Record<Severity, string> = {
  info: '#8B95A1',
  notable: '#E0B341',
  concerning: '#E08341',
  critical: '#E04B4B',
}

export const SEVERITY_ORDER: Severity[] = ['critical', 'concerning', 'notable', 'info']

export const DEVICE_TYPES = [
  'router',
  'switch',
  'firewall',
  'wireless_access_point',
  'workstation',
  'laptop',
  'smartphone',
  'tablet',
  'physical_server',
  'virtual_machine',
  'nas',
  'printer',
  'voip_phone',
  'conference',
  'smart_tv',
  'ip_camera',
  'iot',
  'smart_speaker',
  'unidentified',
  'rogue',
  'access_control',
]

export const DEVICE_ICONS: Record<string, string> = {
  router: '🌐',
  switch: '🔌',
  firewall: '🧱',
  wireless_access_point: '📶',
  workstation: '🖥️',
  laptop: '💻',
  smartphone: '📱',
  tablet: '📟',
  physical_server: '🗄️',
  virtual_machine: '☁️',
  nas: '💾',
  printer: '🖨️',
  voip_phone: '☎️',
  conference: '📺',
  smart_tv: '🎬',
  ip_camera: '📹',
  iot: '💡',
  smart_speaker: '🎙️',
  unidentified: '🕵️',
  rogue: '⚠️',
  access_control: '🖐️',
  bridge: '🌉',
  // legacy keys from scans before the granular taxonomy
  gateway: '🌐',
  network_gear: '🌐',
  server: '🗄️',
  mobile: '📱',
  camera: '📹',
  unknown: '🕵️',
}

export const DEVICE_TYPE_LABELS: Record<string, string> = {
  router: 'Router / Gateway',
  switch: 'Switch',
  firewall: 'Firewall',
  wireless_access_point: 'Wireless Access Point',
  workstation: 'Workstation',
  laptop: 'Laptop',
  smartphone: 'Smartphone',
  tablet: 'Tablet',
  physical_server: 'Physical Server',
  virtual_machine: 'Virtual Machine',
  nas: 'Network Attached Storage (NAS)',
  printer: 'Network Printer / Copier',
  voip_phone: 'VoIP Phone',
  conference: 'Conference / Media System',
  smart_tv: 'Smart TV / Streaming Device',
  ip_camera: 'IP Camera / NVR',
  iot: 'Smart Appliance / IoT',
  smart_speaker: 'Virtual Assistant / Smart Speaker',
  unidentified: 'Unidentified Host (Private MAC)',
  rogue: 'Rogue / Unauthorized Device',
  access_control: 'Access Control',
  // legacy keys from scans before the granular taxonomy
  gateway: 'Router / Gateway',
  network_gear: 'Router / Gateway',
  server: 'Physical Server',
  mobile: 'Smartphone',
  camera: 'IP Camera / NVR',
  unknown: 'Unidentified Host (Private MAC)',
}

// Map older stored device_type values onto the granular taxonomy so filters and
// labels stay correct for scans captured before the finer classification.
const DEVICE_ALIASES: Record<string, string> = {
  network_gear: 'router',
  gateway: 'router',
  mobile: 'smartphone',
  server: 'physical_server',
  camera: 'ip_camera',
  unknown: 'unidentified',
  rogue_device: 'rogue',
  virtual_assistant: 'smart_speaker',
  smart_appliance: 'iot',
  media_system: 'conference',
  streaming_device: 'smart_tv',
  voip: 'voip_phone',
  network_printer: 'printer',
  copier: 'printer',
  network_attached_storage: 'nas',
}

export function normalizeDeviceType(raw: string | null | undefined): string {
  if (!raw) return 'unidentified'
  const key = raw.toLowerCase().trim().replace(/[^a-z_]/g, '')
  return DEVICE_ALIASES[key] || key || 'unidentified'
}

export const PROFILE_LABELS: Record<string, string> = {
  quick: 'Quick',
  full: 'Full',
  stealth: 'Stealth',
  passive_only: 'Passive Only',
}
