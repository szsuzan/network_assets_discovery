import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import App from './App'
import './index.css'
import { ThemeProvider } from './lib/theme'
import subnexIcon from './assets/subnex-icon.svg'
import subnexIconLight from './assets/subnex-icon-light.svg'

const faviconLight = document.createElement('link')
faviconLight.rel = 'icon'
faviconLight.media = '(prefers-color-scheme: light)'
faviconLight.href = subnexIcon
faviconLight.type = 'image/svg+xml'
document.head.appendChild(faviconLight)

const faviconDark = document.createElement('link')
faviconDark.rel = 'icon'
faviconDark.media = '(prefers-color-scheme: dark)'
faviconDark.href = subnexIconLight
faviconDark.type = 'image/svg+xml'
document.head.appendChild(faviconDark)

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
    },
  },
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </ThemeProvider>
    </QueryClientProvider>
  </React.StrictMode>
)
