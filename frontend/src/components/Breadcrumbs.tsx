import { Fragment } from 'react'
import { Link } from 'react-router-dom'

export interface Crumb {
  label: string
  to?: string
}

export default function Breadcrumbs({ items }: { items: Crumb[] }) {
  return (
    <nav aria-label="Breadcrumb" className="mb-4 flex flex-wrap items-center gap-x-1.5 gap-y-1 text-sm">
      {items.map((c, i) => (
        <Fragment key={i}>
          {i > 0 && <span className="text-gray-600">/</span>}
          {c.to ? (
            <Link
              to={c.to}
              className="text-gray-400 transition-colors hover:text-white"
            >
              {c.label}
            </Link>
          ) : (
            <span className="truncate text-gray-200">{c.label}</span>
          )}
        </Fragment>
      ))}
    </nav>
  )
}