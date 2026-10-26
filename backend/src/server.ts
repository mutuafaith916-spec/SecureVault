
import 'dotenv/config'
import { createApp } from './app.js'
import { loadEnvironment } from './config/environment.js'
import AppDataSource from './config/database.js'

async function startServer() {
  try {
    const environment = loadEnvironment()

    await AppDataSource.initialize()

    const app = createApp(environment, AppDataSource)
    const port = Number(process.env.PORT) || 3000

    app.listen(port, () => {
      console.log(`SecureVault server listening on port ${port}`)
    })
  } catch (error) {
    console.error('Failed to start SecureVault server:', error)
    process.exit(1)
  }
}

startServer()
