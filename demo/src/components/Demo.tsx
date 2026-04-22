'use client'

import { useCallback } from 'react'
import { Poulpy } from '@/components/mascot/Poulpy'
import { Btn } from '@/components/atoms/Btn'
import { ServerTerminal } from '@/components/terminal/ServerTerminal'
import { Step1Keygen } from '@/components/steps/Step1Keygen'
import { Step2Encrypt } from '@/components/steps/Step2Encrypt'
import { Step3Evaluate } from '@/components/steps/Step3Evaluate'
import { Step4Decrypt } from '@/components/steps/Step4Decrypt'
import { useFhe } from '@/hooks/useFhe'

const GITHUB_REPO = 'https://github.com/cedoor/squid'

function GitHubLink() {
  return (
    <a
      className="demo-github-link"
      href={GITHUB_REPO}
      target="_blank"
      rel="noreferrer"
      aria-label="View source on GitHub"
    >
      <svg
        width={22}
        height={22}
        viewBox="0 0 98 96"
        aria-hidden
        focusable="false"
      >
        <path
          fill="currentColor"
          d="M48.854 0C21.839 0 0 22 0 49.217c0 21.756 13.993 40.172 33.405 46.69 2.427.49 3.316-1.059 3.316-2.362 0-1.141-.08-5.052-.08-9.127-13.59 2.934-16.42-5.867-16.42-5.867-2.184-5.704-5.42-7.17-5.42-7.17-4.448-3.015.324-3.015.324-3.015 4.934.326 7.523 5.052 7.523 5.052 4.367 7.496 11.404 5.378 14.235 4.074.404-3.178 1.699-5.378 3.074-6.6-10.839-1.141-22.23-5.378-22.23-24.188 0-5.378 1.94-9.778 5.014-13.2-.485-1.222-2.184-6.275.486-13.038 0 0 4.125-1.304 13.426 5.052a46.97 46.97 0 0 1 12.214-1.63c4.125 0 8.33.571 12.213 1.63 9.302-6.356 13.427-5.052 13.427-5.052 2.67 6.763.97 11.816.485 13.038 3.155 3.422 5.015 7.822 5.015 13.2 0 18.905-11.404 23.06-22.324 24.189 1.75 1.52 3.32 3.5 3.32 7.11 0 5.19-.04 9.3-.04 10.5 0 1.3.9 2.8 3.3 2.2 19.2-6.4 32.1-25 32.1-45.1C98 22 75.3 0 48.8 0z"
        />
      </svg>
    </a>
  )
}

function Footer() {
  return (
    <div
      className="demo-footer"
      style={{
        marginTop: 4,
        paddingTop: 14,
        borderTop: '1px dashed var(--rule)',
        display: 'flex',
        justifyContent: 'space-between',
        fontSize: 11.5,
        color: 'var(--ink-faint)',
        fontFamily: 'var(--font-mono)',
        letterSpacing: 0.3,
        flexWrap: 'wrap',
        gap: 8,
      }}
    >
      <span>scheme: CGGI · plaintext: u32</span>
      <span>
        legend:{' '}
        <span style={{ color: 'var(--plain)' }}>● plaintext</span>{' '}
        <span style={{ color: 'var(--cipher)' }}>● ciphertext</span>{' '}
        <span style={{ color: 'var(--key)' }}>● keys</span>
      </span>
      <span>squid-js demo · not for production use</span>
    </div>
  )
}

export default function Demo() {
  const { state, doKeygen, doEncrypt, doEvaluate, doDecrypt, doReset, setA, setB } = useFhe()
  const { phase, skPreview, ekBytes, a, b, ctA, ctB, ctSum, result, logs, error } = state

  const busy = phase !== 'idle'

  // Mood: thinking while busy, brief happy flash after keygen/decrypt, locked on error
  // Derive mood from state
  let mood: 'idle' | 'thinking' | 'happy' | 'locked' = 'idle'
  if (error) mood = 'locked'
  else if (busy) mood = 'thinking'
  else if (result !== null) mood = 'happy'

  const handleEncrypt = useCallback(() => {
    doEncrypt(a, b)
  }, [doEncrypt, a, b])

  const handleEvaluate = useCallback(() => {
    if (ctA && ctB) {
      doEvaluate(ctA, ctB)
    }
  }, [doEvaluate, ctA, ctB])

  const handleDecrypt = useCallback(() => {
    if (ctSum) doDecrypt(ctSum)
  }, [doDecrypt, ctSum])

  return (
    <div
      className="demo-root"
      style={{
        minHeight: '100vh',
        maxWidth: 1400,
        margin: '0 auto',
        display: 'flex',
        flexDirection: 'column',
        gap: 22,
      }}
    >
      {/* Header */}
      <header
        className="demo-header"
        style={{
          display: 'flex',
          paddingBottom: 18,
          borderBottom: '1px solid var(--rule)',
        }}
      >
        <Poulpy size={68} mood={mood} tint="var(--plain)" />
        <div className="demo-header-main" style={{ flex: 1 }}>
          <div
            style={{
              fontSize: 11,
              textTransform: 'uppercase',
              letterSpacing: 2,
              color: 'var(--ink-faint)',
              fontFamily: 'var(--font-mono)',
            }}
          >
            Poulpy · FHE playground
          </div>
          <h1
            className="demo-header-title"
            style={{
              margin: '4px 0 2px',
              fontFamily: 'var(--font-serif)',
              fontWeight: 500,
              letterSpacing: -0.6,
              lineHeight: 1.1,
            }}
          >
            Add two numbers{' '}
            <em style={{ fontStyle: 'italic', color: 'var(--cipher)' }}>without</em> the server
            ever seeing them.
          </h1>
          <div
            className="demo-header-sub"
            style={{ fontSize: 14, color: 'var(--ink-soft)', marginTop: 4, maxWidth: 780 }}
          >
            An end-to-end walkthrough of a CGGI homomorphic addition — keygen, encrypt, evaluate,
            decrypt — using the{' '}
            <a
              href="https://github.com/poulpy-fhe/poulpy"
              target="_blank"
              rel="noreferrer"
              style={{
                color: 'var(--ink)',
                textDecoration: 'underline',
                textDecorationColor: 'var(--plain)',
                textDecorationThickness: 2,
              }}
            >
              Poulpy
            </a>{' '}
            library.
          </div>
          {error && (
            <div
              style={{
                marginTop: 8,
                fontSize: 13,
                color: 'oklch(0.7 0.18 25)',
                fontFamily: 'var(--font-mono)',
              }}
            >
              ✗ {error}
            </div>
          )}
        </div>
        <div className="demo-header-actions" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Btn onClick={doReset} small>
            Reset demo
          </Btn>
          <GitHubLink />
        </div>
      </header>

      {/* Two-column grid */}
      <div className="demo-grid">
        {/* Left column — steps */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <Step1Keygen
            skPreview={skPreview}
            ekBytes={ekBytes}
            phase={phase}
            onGenerate={doKeygen}
          />
          <Step2Encrypt
            hasKeys={!!ekBytes}
            a={a}
            b={b}
            ctA={ctA}
            ctB={ctB}
            phase={phase}
            onSelectA={setA}
            onSelectB={setB}
            onEncrypt={handleEncrypt}
          />
          <Step3Evaluate
            ctA={ctA}
            ctB={ctB}
            ctSum={ctSum}
            phase={phase}
            onEvaluate={handleEvaluate}
          />
          <Step4Decrypt
            ctSum={ctSum}
            result={result}
            phase={phase}
            a={a}
            b={b}
            onDecrypt={handleDecrypt}
          />
          <Footer />
        </div>

        {/* Right column — server terminal */}
        <div
          className="demo-sidebar"
          style={{
            display: 'flex',
            flexDirection: 'column',
            gap: 10,
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'baseline',
              justifyContent: 'space-between',
            }}
          >
            <div>
              <div
                style={{
                  fontSize: 11,
                  textTransform: 'uppercase',
                  letterSpacing: 1.5,
                  color: 'var(--ink-faint)',
                }}
              >
                the other side
              </div>
              <h2
                style={{
                  margin: 0,
                  fontFamily: 'var(--font-serif)',
                  fontWeight: 500,
                  fontSize: 22,
                }}
              >
                Server log
              </h2>
            </div>
            <span style={{ fontSize: 11.5, color: 'var(--ink-faint)' }}>
              crypto runs in your browser
            </span>
          </div>
          <ServerTerminal logs={logs} running={busy} />
        </div>
      </div>
    </div>
  )
}
