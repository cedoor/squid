import { NextRequest, NextResponse } from 'next/server'
import { getDemoEvaluator } from '@/lib/load-demo-evaluator'

export async function POST(req: NextRequest) {
  const evaluator = getDemoEvaluator()
  const body = Buffer.from(await req.arrayBuffer())
  if (body.length < 4) {
    return NextResponse.json({ error: 'body must be u32-le(a_len) || a || b' }, { status: 400 })
  }
  const aLen = body.readUInt32LE(0)
  if (4 + aLen > body.length) {
    return NextResponse.json({ error: 'a_len overruns body' }, { status: 400 })
  }
  const a = body.subarray(4, 4 + aLen)
  const b = body.subarray(4 + aLen)
  try {
    const out = new Uint8Array(evaluator.addU32(a, b))
    return new NextResponse(out, {
      headers: { 'Content-Type': 'application/octet-stream' },
    })
  } catch (err) {
    return NextResponse.json({ error: (err as Error).message }, { status: 400 })
  }
}
