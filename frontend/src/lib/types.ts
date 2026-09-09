export type SettingType = 'text' | 'number' | 'boolean' | 'select' | 'json'

export interface Setting {
  key: string
  category: string
  category_label: string
  label: string
  description: string
  type: SettingType
  value: any
  default: any
  options?: string[]
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

export interface ScanPass {
  index: number
  kind: 'discover' | 'reverify'
  started_at: string
  completed_at: string
  duration: number
  hosts: number
  ports: number
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
  reverify_started_at: string | null
  completed_at: string | null
  total_paused_seconds: number
  open_ports_count: number
  pass_history: ScanPass[]
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
  host_hostname?: string | null
  host_device_type?: string | null
  host_mac?: string | null
  severity: string
  type: string
  title: string
  description: string | null
  recommendation: string | null
  cve_refs: string[] | null
  port: number | null
  included_in_report: boolean
  status: string
  cvss_vector?: string | null
  cvss_score?: number | null
  cwe?: string | null
  notes?: string | null
  evidence?: Record<string, any> | null
  updated_at?: string | null
}

export interface FindingAuditEntry {
  id: string
  user_id: string | null
  action: string
  field: string | null
  old_value: string | null
  new_value: string | null
  created_at: string
}

export const FINDING_STATUSES = [
  'open',
  'triaged',
  'confirmed',
  'remediation_in_progress',
  'retest',
  'resolved',
  'accepted_risk',
  'false_positive',
] as const

export const FINDING_STATUS_LABELS: Record<string, string> = {
  open: 'Open',
  triaged: 'Triaged',
  confirmed: 'Confirmed',
  remediation_in_progress: 'In Remediation',
  retest: 'Ready for Retest',
  resolved: 'Resolved',
  accepted_risk: 'Accepted Risk',
  false_positive: 'False Positive',
}

export const FINDING_TYPE_LABELS: Record<string, string> = {
  default_credentials: 'Default Credentials',
  eol_software: 'EOL Software',
  exposed_admin_panel: 'Exposed Admin Panel',
  unencrypted_protocol: 'Unencrypted Protocol',
  unencrypted_video: 'Unencrypted Video Stream',
  weak_crypto: 'Weak TLS/Crypto',
  expired_certificate: 'Expired Certificate',
  smb_signing_disabled: 'SMB Signing Not Required',
  anonymous_ftp: 'Anonymous FTP',
  unrestricted_share: 'World-Readable SMB Share',
  dangerous_http_methods: 'Dangerous HTTP Methods',
  missing_auth: 'Missing Authentication',
  empty_password: 'Empty Password',
  web_service_exposed: 'Web Service Exposed',
  information_disclosure: 'Information Disclosure',
  unexpected_exposure: 'Unexpected Exposure',
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

// Stable, unique color per device type so pie/topology slices never repeat.
// Each canonical key maps to its own color; unknown keys get a deterministic
// spread from DEVICE_FALLBACK_COLORS via deviceTypeColor().
export const DEVICE_TYPE_COLORS: Record<string, string> = {
  router: '#3B82F6',
  switch: '#14B8A6',
  firewall: '#EF4444',
  wireless_access_point: '#F59E0B',
  workstation: '#8B5CF6',
  laptop: '#06B6D4',
  smartphone: '#EC4899',
  tablet: '#84CC16',
  physical_server: '#6B7280',
  virtual_machine: '#0EA5E9',
  nas: '#A855F7',
  printer: '#F97316',
  voip_phone: '#10B981',
  conference: '#6366F1',
  smart_tv: '#22C55E',
  ip_camera: '#E11D48',
  iot: '#EAB308',
  smart_speaker: '#D946EF',
  unidentified: '#94A3B8',
  rogue: '#DC2626',
  access_control: '#2DD4BF',
}

const DEVICE_FALLBACK_COLORS = [
  '#3B82F6', '#14B8A6', '#F97316', '#8B5CF6', '#22C55E', '#EF4444', '#06B6D4',
  '#EC4899', '#EAB308', '#6366F1', '#10B981', '#F43F5E', '#0EA5E9', '#A855F7',
  '#84CC16', '#F59E0B', '#2DD4BF', '#D946EF', '#94A3B8', '#DC2626', '#0891B2',
]

export function deviceTypeColor(key: string): string {
  const known = DEVICE_TYPE_COLORS[key]
  if (known) return known
  let h = 0
  for (let i = 0; i < key.length; i++) h = (h * 31 + key.charCodeAt(i)) >>> 0
  return DEVICE_FALLBACK_COLORS[h % DEVICE_FALLBACK_COLORS.length]
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
