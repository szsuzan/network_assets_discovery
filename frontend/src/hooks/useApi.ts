import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import type { Engagement, Scan, Host, HostDetail, Finding, Topology, Setting, User, DeletionRequest } from '../lib/types'

export function useLogin() {
  return useMutation({
    mutationFn: (data: { email: string; password: string }) =>
      api.post('/api/auth/login', data).then((r) => r.data as { access_token: string; token_type: string; role: string; must_change_password: boolean; id?: string | null }),
  })
}

export function useMe() {
  return useQuery({
    queryKey: ['me'],
    queryFn: () => api.get<User>('/api/auth/me').then((r) => r.data),
  })
}

export function useUsers() {
  return useQuery({
    queryKey: ['users'],
    queryFn: () => api.get<User[]>('/api/users').then((r) => r.data),
  })
}

export function useCreateUser() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { email: string; password: string; role: string; active?: boolean }) =>
      api.post<User>('/api/users', data).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  })
}

export function useUpdateUser() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: { role?: string; active?: boolean } }) =>
      api.patch<User>(`/api/users/${id}`, data).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  })
}

export function useResetUserPassword() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, password }: { id: string; password: string }) =>
      api.post<User>(`/api/users/${id}/reset-password`, { password }).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  })
}

export function useDeletionRequests() {
  return useQuery({
    queryKey: ['deletion-requests'],
    queryFn: () => api.get<DeletionRequest[]>('/api/deletion-requests').then((r) => r.data),
    refetchInterval: 15000,
  })
}

export function useCreateDeletionRequest() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { target_type: 'engagement' | 'scan'; target_id: string; reason?: string }) =>
      api.post<DeletionRequest>('/api/deletion-requests', data).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['deletion-requests'] }),
  })
}

export function useApproveDeletionRequest() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.post(`/api/deletion-requests/${id}/approve`).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['deletion-requests'] }),
  })
}

export function useRejectDeletionRequest() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, reason }: { id: string; reason?: string }) =>
      api
        .post(`/api/deletion-requests/${id}/reject${reason ? `?reason=${encodeURIComponent(reason)}` : ''}`)
        .then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['deletion-requests'] }),
  })
}

export function useCancelDeletionRequest() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.post(`/api/deletion-requests/${id}/cancel`).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['deletion-requests'] }),
  })
}

export function useChangePassword() {
  return useMutation({
    mutationFn: (data: { current_password: string; new_password: string }) =>
      api.post('/api/auth/change-password', data).then((r) => r.data),
  })
}

export function useEngagements() {
  return useQuery({
    queryKey: ['engagements'],
    queryFn: () => api.get<Engagement[]>('/api/engagements').then((r) => r.data),
  })
}

export function useEngagement(id: string | undefined) {
  return useQuery({
    queryKey: ['engagement', id],
    queryFn: () => api.get<Engagement>(`/api/engagements/${id}`).then((r) => r.data),
    enabled: !!id,
  })
}

export function useEngagementScans(id: string | undefined) {
  return useQuery({
    queryKey: ['engagement', id, 'scans'],
    queryFn: () => api.get<Scan[]>(`/api/engagements/${id}/scans`).then((r) => r.data),
    enabled: !!id,
    refetchInterval: (query) => {
      const scans = query.state.data ?? []
      if (scans.some((s) => {
        const st = s.status
        return st === 'queued' || st === 'discovering' || st === 'scanning' ||
               st === 'fingerprinting' || st === 'analyzing' || st === 'paused' ||
               st === 'agent_running' || st === 'reverifying'
      })) {
        return 3000
      }
      return false
    },
  })
}

export function useCreateEngagement() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: Partial<Engagement>) =>
      api.post<Engagement>('/api/engagements', data).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['engagements'] }),
  })
}

export function useUpdateEngagement() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...data }: { id: string } & Partial<Engagement>) =>
      api.patch<Engagement>(`/api/engagements/${id}`, data).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['engagements'] }),
  })
}

export function useDeleteEngagement() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/api/engagements/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['engagements'] }),
  })
}

export function useStartScan(engagementId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { name?: string; targets: string[]; profile: string; port_range: string; protocol: string; mode: string }) =>
      api.post<Scan>(`/api/engagements/${engagementId}/scans`, data).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['engagement', engagementId, 'scans'] }),
  })
}

export function useScan(scanId: string | undefined) {
  return useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => api.get<Scan>(`/api/scans/${scanId}`).then((r) => r.data),
    enabled: !!scanId,
    refetchInterval: (query) => {
      const status = query.state.data?.status
      if (
        status === 'queued' ||
        status === 'discovering' ||
        status === 'scanning' ||
        status === 'fingerprinting' ||
        status === 'analyzing' ||
        status === 'paused' ||
        status === 'agent_running' ||
        status === 'reverifying'
      ) {
        return 3000
      }
      return false
    },
  })
}

export function useHosts(scanId: string | undefined) {
  return useQuery({
    queryKey: ['scan', scanId, 'hosts'],
    queryFn: () => api.get<Host[]>(`/api/scans/${scanId}/hosts`).then((r) => r.data),
    enabled: !!scanId,
  })
}

export type ConsoleLogEntry = { ts: string | null; level: string; line: string }

export type ActivityEntry = {
  ts: string | null
  type: string
  scan_id?: string
  [key: string]: any
}

export function useScanLogs(scanId: string | undefined) {
  return useQuery({
    queryKey: ['scan', scanId, 'logs'],
    queryFn: () => api.get<ConsoleLogEntry[]>(`/api/scans/${scanId}/logs`).then((r) => r.data),
    enabled: !!scanId,
    // Keep the console fresh even if the WebSocket drops/reconnects; the page
    // is only mounted while the user is watching the live scan.
    refetchInterval: 5000,
  })
}


export function useScanActivity(scanId: string | undefined) {
  return useQuery({
    queryKey: ['scan', scanId, 'activity'],
    queryFn: () => api.get<ActivityEntry[]>(`/api/scans/${scanId}/activity`).then((r) => r.data),
    enabled: !!scanId,
    // Mirror the logs poll so the timeline catches up when the WebSocket drops.
    refetchInterval: 5000,
  })
}

export function useHostDetail(scanId: string | undefined, hostIp: string | undefined) {
  return useQuery({
    queryKey: ['scan', scanId, 'host', hostIp],
    queryFn: () => api.get<HostDetail>(`/api/scans/${scanId}/hosts/${hostIp}`).then((r) => r.data),
    enabled: !!scanId && !!hostIp,
    refetchInterval: 5000,
  })
}

export function usePatchHost(scanId: string, hostIp: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: Partial<Host>) =>
      api.patch(`/api/scans/${scanId}/hosts/${hostIp}`, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scan', scanId, 'host', hostIp] }),
  })
}

export function useFindings(scanId: string | undefined) {
  return useQuery({
    queryKey: ['scan', scanId, 'findings'],
    queryFn: () => api.get<Finding[]>(`/api/scans/${scanId}/findings`).then((r) => r.data),
    enabled: !!scanId,
  })
}

export function usePatchFinding() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Finding> }) =>
      api.patch(`/api/findings/${id}`, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scan'] }),
  })
}

export function useFindingAudit(scanId: string | undefined, findingId: string | undefined) {
  return useQuery({
    queryKey: ['scan', scanId, 'finding', findingId, 'audit'],
    queryFn: () =>
      api.get(`/api/scans/${scanId}/findings/${findingId}/audit`).then((r) => r.data),
    enabled: !!scanId && !!findingId,
  })
}

export interface RiskRule {
  key: string
  label: string
  description: string | null
  kind: string
  default_severity: string
  enabled: boolean
  severity: string | null
}

export function useRiskRules(scanId: string | undefined) {
  return useQuery({
    queryKey: ['scan', scanId, 'risk-rules'],
    queryFn: () => api.get<RiskRule[]>(`/api/scans/${scanId}/risk-rules`).then((r) => r.data),
    enabled: !!scanId,
  })
}

export function useUpdateRiskRules(scanId: string | undefined) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (rules: { key: string; enabled?: boolean; severity?: string | null }[]) =>
      api.put(`/api/scans/${scanId}/risk-rules`, rules).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scan', scanId, 'risk-rules'] }),
  })
}

export function useReanalyze(scanId: string | undefined) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => api.post(`/api/scans/${scanId}/reanalyze`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scan', scanId, 'findings'] }),
  })
}

export interface Webhook {
  id: string
  name: string
  url: string
  events: string[]
  enabled: boolean
  secret?: string | null
  created_at: string
  last_triggered_at: string | null
  last_status: number | null
  last_error: string | null
}

export function useWebhooks() {
  return useQuery({
    queryKey: ['webhooks'],
    queryFn: () => api.get<Webhook[]>('/api/webhooks').then((r) => r.data),
  })
}

export function useCreateWebhook() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: Partial<Webhook> & { url: string; name: string }) =>
      api.post('/api/webhooks', data).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['webhooks'] }),
  })
}

export function useUpdateWebhook() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Webhook> }) =>
      api.patch(`/api/webhooks/${id}`, data).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['webhooks'] }),
  })
}

export function useDeleteWebhook() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/api/webhooks/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['webhooks'] }),
  })
}

export function useTestWebhook() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.post(`/api/webhooks/${id}/test`).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['webhooks'] }),
  })
}

export function useTopology(scanId: string | undefined) {
  return useQuery({
    queryKey: ['scan', scanId, 'topology'],
    queryFn: () => api.get<Topology>(`/api/scans/${scanId}/topology`).then((r) => r.data),
    enabled: !!scanId,
  })
}

export function useScanDiff(scanId: string | undefined, otherScanId: string | undefined) {
  return useQuery({
    queryKey: ['scan', scanId, 'diff', otherScanId],
    queryFn: () => api.get(`/api/scans/${scanId}/diff/${otherScanId}`).then((r) => r.data),
    enabled: !!scanId && !!otherScanId,
  })
}

export function useStopScan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (scanId: string) => api.post(`/api/scans/${scanId}/stop`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scan'] }),
  })
}

export function useDeleteScan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (scanId: string) => api.delete(`/api/scans/${scanId}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['engagement'] }),
  })
}

export function usePauseScan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (scanId: string) => api.post(`/api/scans/${scanId}/pause`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scan'] }),
  })
}

export function useResumeScan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (scanId: string) => api.post(`/api/scans/${scanId}/resume`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scan'] }),
  })
}

export function useReverifyScan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (opts: { scanId: string; check_new_hosts?: boolean; port_range?: string }) =>
      api
        .post<Scan>(`/api/scans/${opts.scanId}/reverify`, {
          check_new_hosts: opts.check_new_hosts,
          port_range: opts.port_range,
        })
        .then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scan'] }),
  })
}

export function useUpdateScan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (opts: { scanId: string; data: Partial<Pick<Scan, 'name' | 'targets' | 'profile' | 'port_range' | 'protocol'>> }) =>
      api.patch<Scan>(`/api/scans/${opts.scanId}`, opts.data).then((r) => r.data),
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ['scan', vars.scanId] })
      qc.invalidateQueries({ queryKey: ['engagement'] })
    },
  })
}

export type AgentInfo = {
  id: string
  name: string
  status: string
  last_seen: string | null
  version?: string | null
  hostname?: string | null
  os?: string | null
  subnets: string[]
  capabilities: string[]
  notes?: string
  current_version?: string | null
  created_at: string
}

export function useAgents() {
  return useQuery({
    queryKey: ['agents'],
    queryFn: () => api.get<AgentInfo[]>('/api/agents').then((r) => r.data),
    refetchInterval: 15000,
  })
}

export function useCreateAgent() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { name: string; subnets: string[]; notes: string }) =>
      api.post<AgentInfo & { api_key: string }>('/api/agents', data).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agents'] }),
  })
}

export function useDeleteAgent() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/api/agents/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agents'] }),
  })
}

export function useResetAgentKey() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      api.post<AgentInfo & { api_key: string }>(`/api/agents/${id}/reset-key`).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agents'] }),
  })
}

export type AgentHealth = {
  id: string
  name: string
  live: string
  status: string
  last_seen: string | null
  age_seconds: number | null
  version?: string | null
  hostname?: string | null
  os?: string | null
  subnets: string[]
  capabilities: string[]
  notes?: string
  current_version?: string | null
  server_time: string
}

export function useAgentHealth() {
  return useMutation({
    mutationFn: (id: string) =>
      api.get<AgentHealth>(`/api/agents/${id}/health`).then((r) => r.data),
  })
}

export function useRestartAgent() {
  return useMutation({
    mutationFn: (id: string) =>
      api.post<{ ok: boolean; requested: boolean; name: string }>(`/api/agents/${id}/restart`).then((r) => r.data),
  })
}

export function useUpdateAgent() {
  return useMutation({
    mutationFn: (id: string) =>
      api
        .post<{ ok: boolean; requested: boolean; name: string; current_version?: string }>(
          `/api/agents/${id}/update`,
        )
        .then((r) => r.data),
  })
}

export function useSettings() {
  return useQuery({
    queryKey: ['settings'],
    queryFn: () => api.get<Setting[]>('/api/settings').then((r) => r.data),
    staleTime: 60_000,
  })
}

export function useUpdateSettings() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (values: Record<string, any>) =>
      api.put<Setting[]>('/api/settings', values).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['settings'] }),
  })
}
