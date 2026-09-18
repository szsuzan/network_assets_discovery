export const ROLE_ADMIN = 'admin'
export const ROLE_PENTESTER = 'pentester'
export const ROLE_VIEWER = 'viewer'

export function currentRole(): string | null {
  return localStorage.getItem('role')
}

export function currentUserId(): string | null {
  return localStorage.getItem('user_id')
}

export function isAdmin(role: string | null = currentRole()): boolean {
  return role === ROLE_ADMIN
}

/** Users who can create/edit engagements and run scans (admin + pentester). */
export function canMutate(role: string | null = currentRole()): boolean {
  return role === ROLE_ADMIN || role === ROLE_PENTESTER
}

/** Only admins may hard-delete engagements/scans; everyone else must request it. */
export function canDelete(role: string | null = currentRole()): boolean {
  return role === ROLE_ADMIN
}

export function clearAuth(): void {
  localStorage.removeItem('token')
  localStorage.removeItem('role')
  localStorage.removeItem('user_id')
}