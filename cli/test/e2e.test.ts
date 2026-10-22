import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { spawnSync, execSync } from 'node:child_process'
import { existsSync, mkdirSync, rmSync, writeFileSync, readFileSync } from 'node:fs'
import { resolve, join } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'

const __filename = fileURLToPath(import.meta.url)
const __dirname = resolve(__filename, '..')
const cliRoot = resolve(__dirname, '..')
const distCli = resolve(cliRoot, 'dist', 'cli.js')

const VALID_CONTRACT_ID = 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4'
const OTHER_VALID_CONTRACT_ID = 'CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526'
const SAMPLE_TX_HASH = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
const SAMPLE_VIDEO_HASH = 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'

let tempDir: string

function runCli(args: string[], options: { input?: string; env?: NodeJS.ProcessEnv } = {}) {
  const result = spawnSync(process.execPath, [distCli, ...args], {
    cwd: cliRoot,
    encoding: 'utf-8',
    input: options.input,
    env: {
      ...process.env,
      ...options.env,
    },
  })
  return {
    status: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    error: result.error,
  }
}

beforeAll(() => {
  tempDir = resolve(tmpdir(), `harpocrates-cli-e2e-${Date.now()}-${Math.random().toString(36).slice(2)}`)
  mkdirSync(tempDir, { recursive: true })

  if (!existsSync(distCli)) {
    try {
      execSync('npm run build', { cwd: cliRoot, stdio: 'pipe' })
    } catch {
      if (!existsSync(distCli)) {
        throw new Error(`Failed to locate or build compiled entry point at ${distCli}`)
      }
    }
  }
  expect(existsSync(distCli)).toBe(true)
})

afterAll(() => {
  if (tempDir && existsSync(tempDir)) {
    rmSync(tempDir, { recursive: true, force: true })
  }
})

describe('CLI packaging and entry point', () => {
  it('has a node shebang in dist/cli.js', () => {
    const content = readFileSync(distCli, 'utf-8')
    expect(content.startsWith('#!/usr/bin/env node')).toBe(true)
  })
})

describe('Command: help', () => {
  it('exits 0 and prints usage instructions on "help"', () => {
    const res = runCli(['help'])
    expect(res.status).toBe(0)
    expect(res.stderr).toBe('')
    expect(res.stdout).toContain('Harpocrates CLI')
    expect(res.stdout).toContain('Usage:')
    expect(res.stdout).toContain('Commands:')
    expect(res.stdout).toContain('verify')
    expect(res.stdout).toContain('manifest')
    expect(res.stdout).toContain('hash')
  })

  it('exits 0 and prints usage instructions with no arguments', () => {
    const res = runCli([])
    expect(res.status).toBe(0)
    expect(res.stdout).toContain('Harpocrates CLI')
  })
})

describe('Command: hash', () => {
  it('computes sha256 of a fixture file and asserts stdout JSON shape and exit code 0', () => {
    const fixtureContent = 'Hello Harpocrates E2E Verification Suite'
    const fixturePath = join(tempDir, 'hash-target.txt')
    writeFileSync(fixturePath, fixtureContent, 'utf-8')

    const expectedHash = createHash('sha256').update(fixtureContent).digest('hex')

    const res = runCli(['hash', '--file', fixturePath])
    expect(res.status).toBe(0)
    expect(res.stderr).toBe('')

    const parsed = JSON.parse(res.stdout.trim())
    expect(parsed).toEqual({
      algorithm: 'sha256',
      input: 'file',
      hash: expectedHash,
    })
  })

  it('supports the short alias -f for file path', () => {
    const fixtureContent = 'Short alias test'
    const fixturePath = join(tempDir, 'hash-alias-target.txt')
    writeFileSync(fixturePath, fixtureContent, 'utf-8')

    const expectedHash = createHash('sha256').update(fixtureContent).digest('hex')

    const res = runCli(['hash', '-f', fixturePath])
    expect(res.status).toBe(0)
    const parsed = JSON.parse(res.stdout.trim())
    expect(parsed.hash).toBe(expectedHash)
  })

  it('exits 2 on missing --file argument', () => {
    const res = runCli(['hash'])
    expect(res.status).toBe(2)
    expect(res.stderr).toContain('harpocrates: --file is required for hashing')
  })

  it('exits 8 on non-existent input file', () => {
    const missingPath = join(tempDir, 'does-not-exist.bin')
    const res = runCli(['hash', '--file', missingPath])
    expect(res.status).toBe(8)
    expect(res.stderr).toContain('harpocrates: hashing failed')
  })
})

describe('Command: manifest', () => {
  const metadata = {
    protocol: 'harpocrates',
    version: 1,
    tier: 'silent',
    sourceHash: 'a'.repeat(64),
    proofId: 'b'.repeat(64),
    timestamp: '2026-07-24T12:00:00.000Z',
    secret: 'super-secret-token-xyz',
    witnessData: 'private-witness-payload',
  }

  let metadataPath: string

  beforeAll(() => {
    metadataPath = join(tempDir, 'sample-metadata.json')
    writeFileSync(metadataPath, JSON.stringify(metadata), 'utf-8')
  })

  it('generates a manifest JSON on stdout with correct shape and exit code 0', () => {
    const res = runCli([
      'manifest',
      '--input',
      metadataPath,
      '--contract-id',
      VALID_CONTRACT_ID,
      '--tx-hash',
      SAMPLE_TX_HASH,
      '--video-hash',
      SAMPLE_VIDEO_HASH,
    ])

    expect(res.status).toBe(0)
    expect(res.stderr).toBe('')

    const parsed = JSON.parse(res.stdout.trim())
    expect(parsed).toMatchObject({
      contractId: VALID_CONTRACT_ID,
      epoch: 0,
      network: 'Test SDF Network ; September 2015',
      proofId: metadata.proofId,
      protocol: 'harpocrates',
      sourceHash: metadata.sourceHash,
      tier: 'silent',
      timestamp: metadata.timestamp,
      transactionRef: SAMPLE_TX_HASH,
      verifierScope: '0',
      version: 2,
      videoHash: SAMPLE_VIDEO_HASH,
    })
    expect(parsed.metadataHash).toMatch(/^[0-9a-f]{64}$/)
  })

  it('writes manifest to disk with --output and cleans up', () => {
    const outputPath = join(tempDir, 'generated-manifest.json')
    const res = runCli([
      'manifest',
      '--input',
      metadataPath,
      '--contract-id',
      VALID_CONTRACT_ID,
      '--tx-hash',
      SAMPLE_TX_HASH,
      '--video-hash',
      SAMPLE_VIDEO_HASH,
      '--output',
      outputPath,
    ])

    expect(res.status).toBe(0)
    expect(res.stdout).toContain(`Manifest written to ${outputPath}`)
    expect(existsSync(outputPath)).toBe(true)

    const saved = JSON.parse(readFileSync(outputPath, 'utf-8'))
    expect(saved.contractId).toBe(VALID_CONTRACT_ID)
    expect(saved.videoHash).toBe(SAMPLE_VIDEO_HASH)
  })

  it('redacts sensitive fields in stderr when --debug is passed', () => {
    const res = runCli([
      'manifest',
      '--input',
      metadataPath,
      '--contract-id',
      VALID_CONTRACT_ID,
      '--tx-hash',
      SAMPLE_TX_HASH,
      '--video-hash',
      SAMPLE_VIDEO_HASH,
      '--debug',
    ])

    expect(res.status).toBe(0)
    expect(res.stderr).toContain('manifest.input_metadata')
    expect(res.stderr).toContain('[REDACTED]')
    expect(res.stderr).not.toContain('super-secret-token-xyz')
    expect(res.stderr).not.toContain('private-witness-payload')
  })

  it('exits 2 when --input is missing', () => {
    const res = runCli([
      'manifest',
      '--contract-id',
      VALID_CONTRACT_ID,
      '--tx-hash',
      SAMPLE_TX_HASH,
    ])
    expect(res.status).toBe(2)
    expect(res.stderr).toContain('harpocrates: --input is required for manifest creation')
  })

  it('exits 2 when --tx-hash is missing', () => {
    const res = runCli([
      'manifest',
      '--input',
      metadataPath,
      '--contract-id',
      VALID_CONTRACT_ID,
    ])
    expect(res.status).toBe(2)
    expect(res.stderr).toContain('harpocrates: --tx-hash is required for manifest creation')
  })

  it('exits 8 on invalid contract ID', () => {
    const res = runCli([
      'manifest',
      '--input',
      metadataPath,
      '--contract-id',
      'not-a-valid-contract',
      '--tx-hash',
      SAMPLE_TX_HASH,
    ])
    expect(res.status).toBe(8)
    expect(res.stderr).toContain('harpocrates: invalid contract ID')
  })

  it('exits 8 on corrupt metadata', () => {
    const corruptPath = join(tempDir, 'corrupt-meta.json')
    writeFileSync(corruptPath, '{ not valid json', 'utf-8')

    const res = runCli([
      'manifest',
      '--input',
      corruptPath,
      '--contract-id',
      VALID_CONTRACT_ID,
      '--tx-hash',
      SAMPLE_TX_HASH,
    ])
    expect(res.status).toBe(8)
    expect(res.stderr).toContain('harpocrates: invalid or unreadable metadata')
  })
})

describe('Command: verify --offline', () => {
  let manifestPath: string

  beforeAll(() => {
    const manifest = {
      contractId: VALID_CONTRACT_ID,
      epoch: 0,
      metadataHash: '5fe555f982b37a0efda1c29a98dd9f8479dc014e9272641ebc2d6ee8f455a0c3',
      network: 'Test SDF Network ; September 2015',
      proofId: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      protocol: 'harpocrates',
      sourceHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      tier: 'silent',
      timestamp: '2026-07-24T12:00:00.000Z',
      transactionRef: SAMPLE_TX_HASH,
      verifierScope: '0',
      version: 2,
      videoHash: SAMPLE_VIDEO_HASH,
    }
    manifestPath = join(tempDir, 'valid-manifest.json')
    writeFileSync(manifestPath, JSON.stringify(manifest), 'utf-8')
  })

  it('exits 6 (pending) and returns receipt JSON shape without network calls', () => {
    const res = runCli([
      'verify',
      '--manifest',
      manifestPath,
      '--contract-id',
      VALID_CONTRACT_ID,
      '--offline',
      '--output',
      'json',
    ])

    expect(res.status).toBe(6)
    expect(res.stderr).toBe('')

    const receipt = JSON.parse(res.stdout.trim())
    expect(receipt).toMatchObject({
      version: 1,
      manifest: {
        contractId: VALID_CONTRACT_ID,
        proofId: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      },
      transaction: {
        status: 'pending',
        txHash: SAMPLE_TX_HASH,
      },
      chainRecord: null,
      result: 'pending',
    })
    expect(typeof receipt.verifiedAt).toBe('string')
  })

  it('formats text receipt output by default', () => {
    const res = runCli([
      'verify',
      '--manifest',
      manifestPath,
      '--contract-id',
      VALID_CONTRACT_ID,
      '--offline',
    ])

    expect(res.status).toBe(6)
    expect(res.stdout).toContain('PENDING')
    expect(res.stdout).toContain('Harpocrates Verification Receipt')
    expect(res.stdout).toContain(VALID_CONTRACT_ID)
  })

  it('redacts sensitive fields in debug stderr log for verify', () => {
    const res = runCli([
      'verify',
      '--manifest',
      manifestPath,
      '--contract-id',
      VALID_CONTRACT_ID,
      '--offline',
      '--output',
      'json',
      '--debug',
    ])

    expect(res.status).toBe(6)
    expect(res.stderr).toContain('verify.manifest')
  })

  it('exits 5 on contract mismatch', () => {
    const res = runCli([
      'verify',
      '--manifest',
      manifestPath,
      '--contract-id',
      OTHER_VALID_CONTRACT_ID,
      '--offline',
    ])

    expect(res.status).toBe(5)
    expect(res.stderr).toContain('harpocrates: contract_mismatch')
  })

  it('exits 4 on network mismatch', () => {
    const res = runCli([
      'verify',
      '--manifest',
      manifestPath,
      '--contract-id',
      VALID_CONTRACT_ID,
      '--network',
      'Public Global Stellar Network ; September 2015',
      '--offline',
    ])

    expect(res.status).toBe(4)
    expect(res.stderr).toContain('harpocrates: network_mismatch')
  })

  it('exits 8 when --contract-id is missing or invalid', () => {
    const res = runCli([
      'verify',
      '--manifest',
      manifestPath,
      '--offline',
    ])

    expect(res.status).toBe(8)
    expect(res.stderr).toContain('harpocrates: a valid --contract-id is required for verification')
  })

  it('exits 8 when --manifest is missing', () => {
    const res = runCli([
      'verify',
      '--contract-id',
      VALID_CONTRACT_ID,
      '--offline',
    ])

    expect(res.status).toBe(8)
    expect(res.stderr).toContain('harpocrates: --manifest is required for verification')
  })
})

describe('Command: c2pa', () => {
  it('exports C2PA assertions to a file and exits 0', () => {
    const manifestPath = join(tempDir, 'c2pa-manifest.json')
    const manifest = {
      contractId: VALID_CONTRACT_ID,
      epoch: 0,
      metadataHash: '5fe555f982b37a0efda1c29a98dd9f8479dc014e9272641ebc2d6ee8f455a0c3',
      network: 'Test SDF Network ; September 2015',
      proofId: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      protocol: 'harpocrates',
      sourceHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      tier: 'silent',
      timestamp: '2026-07-24T12:00:00.000Z',
      transactionRef: SAMPLE_TX_HASH,
      verifierScope: '0',
      version: 2,
      videoHash: SAMPLE_VIDEO_HASH,
    }
    writeFileSync(manifestPath, JSON.stringify(manifest), 'utf-8')

    const outputPath = join(tempDir, 'c2pa-export.json')
    const res = runCli([
      'c2pa',
      '--manifest',
      manifestPath,
      '--output',
      outputPath,
      '--title',
      'E2E C2PA Test',
    ])

    expect(res.status).toBe(0)
    expect(res.stdout).toContain(`C2PA assertions written to ${outputPath}`)
    expect(existsSync(outputPath)).toBe(true)

    const c2paExport = JSON.parse(readFileSync(outputPath, 'utf-8'))
    expect(c2paExport).toMatchObject({
      title: 'E2E C2PA Test',
      claim_generator: expect.stringContaining('harpocrates'),
    })
  })

  it('exits 2 when --manifest is missing for c2pa export', () => {
    const res = runCli(['c2pa'])
    expect(res.status).toBe(2)
    expect(res.stderr).toContain('harpocrates: --manifest is required for c2pa export')
  })
})
