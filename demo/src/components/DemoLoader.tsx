'use client'

import dynamic from 'next/dynamic'

const Demo = dynamic(() => import('./Demo'), { ssr: false })

export function DemoLoader() {
  return <Demo />
}
