const { spawn } = require('node:child_process')
const path = require('node:path')

const projectRoot = path.resolve(__dirname, '..')
const npmCommand = process.platform === 'win32'
  ? process.env.ComSpec || 'cmd.exe'
  : 'npm'
const npmArguments = process.platform === 'win32'
  ? ['/d', '/s', '/c', 'npm.cmd run dev']
  : ['run', 'dev']
const processes = []
let stopping = false

function stopAll() {
  if (stopping) return
  stopping = true
  for (const child of processes) {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill()
    }
  }
}

function startService(name, cwd) {
  const child = spawn(npmCommand, npmArguments, {
    cwd,
    stdio: 'inherit',
  })
  processes.push(child)

  child.on('error', (error) => {
    console.error(`Could not start ${name}:`, error.message)
    stopAll()
    process.exitCode = 1
  })

  child.on('exit', (code, signal) => {
    if (stopping) return
    if (code !== 0 && code !== null) {
      console.error(`${name} exited with code ${code}.`)
      stopAll()
      process.exitCode = code
    } else if (signal) {
      console.error(`${name} stopped unexpectedly (${signal}).`)
      stopAll()
      process.exitCode = 1
    }
  })
}

async function isBackendReady() {
  try {
    const response = await fetch('http://localhost:3000/api/v1/health', {
      signal: AbortSignal.timeout(1500),
    })
    const result = await response.json()
    return response.ok && result.success && result.data?.api === 'healthy'
  } catch {
    return false
  }
}

process.on('SIGINT', stopAll)
process.on('SIGTERM', stopAll)

async function main() {
  if (await isBackendReady()) {
    console.log('Backend is already responding on http://localhost:3000; reusing it.')
  } else {
    startService('backend', path.join(projectRoot, 'backend'))
  }
  startService('frontend', path.join(projectRoot, 'frontend'))
}

void main()
