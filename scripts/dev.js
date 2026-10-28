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

function openBrowser(url) {
  const command = process.platform === 'win32'
    ? process.env.ComSpec || 'cmd.exe'
    : process.platform === 'darwin'
      ? 'open'
      : 'xdg-open'
  const argumentsList = process.platform === 'win32'
    ? ['/d', '/s', '/c', `start "" "${url}"`]
    : [url]
  const browser = spawn(command, argumentsList, {
    stdio: 'ignore',
    windowsHide: true,
  })
  browser.on('error', (error) => {
    console.error(`Could not open the SecureVault page: ${error.message}`)
  })
}

async function waitForFrontend() {
  const url = 'http://localhost:5173'
  const deadline = Date.now() + 60_000
  while (!stopping && Date.now() < deadline) {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(1500) })
      if (response.ok) {
        openBrowser(url)
        return
      }
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 1000))
    }
  }
  if (!stopping) {
    console.error('The frontend did not become ready within 60 seconds.')
  }
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
  void waitForFrontend()
}

void main()
