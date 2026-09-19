import { useEffect } from 'react'

/** Sets the document title while the calling component is mounted. */
export function usePageTitle(title: string) {
  useEffect(() => {
    const prev = document.title
    document.title = `${title} · SubNex`
    return () => {
      document.title = prev
    }
  }, [title])
}