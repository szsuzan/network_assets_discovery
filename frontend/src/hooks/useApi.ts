import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import type { Engagement, Scan, Host, HostDetail, Finding, Topology } from '../lib/types'

export function useLogin() {
  return useMutation({
    mutationFn: (data: { email: string; password: string }) =>
      api.post('/api/auth/login', data).then((r) => r.data),
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
    mutationFn: (data: { targets: string[]; profile: string; port_range: string; protocol: string }) =>
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

export function useScanLogs(scanId: string | undefined) {
  return useQuery({
    queryKey: ['scan', scanId, 'logs'],
    queryFn: () => api.get<ConsoleLogEntry[]>(`/api/scans/${scanId}/logs`).then((r) => r.data),
    enabled: !!scanId,
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
    mutationFn: (scanId: string) => api.delete(`/api/scans/${scanId}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scan'] }),
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
    mutationFn: (scanId: string) =>
      api.post<Scan>(`/api/scans/${scanId}/reverify`).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scan'] }),
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
