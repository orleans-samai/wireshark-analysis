import { fileURLToPath } from "node:url"

const shutdown = () => process.exit(0)
process.once("SIGINT", shutdown)
process.once("SIGTERM", shutdown)

const cli = new URL("../node_modules/vinext/dist/cli.js", import.meta.url)
process.argv = [process.execPath, fileURLToPath(cli), "dev", "--port", "4173", "--strictPort"]
await import(cli.href)
