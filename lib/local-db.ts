const DATABASE_NAME = "packetlens-local"
const DATABASE_VERSION = 1
const STORE_NAME = "records"

type LocalRecord<T> = {
  key: string
  value: T
  updatedAt: string
}

let databasePromise: Promise<IDBDatabase> | null = null

function openDatabase() {
  if (typeof window === "undefined" || !window.indexedDB) return Promise.reject(new Error("IndexedDB indisponível"))
  if (databasePromise) return databasePromise
  databasePromise = new Promise<IDBDatabase>((resolve, reject) => {
    const request = window.indexedDB.open(DATABASE_NAME, DATABASE_VERSION)
    request.onupgradeneeded = () => {
      const database = request.result
      if (!database.objectStoreNames.contains(STORE_NAME)) database.createObjectStore(STORE_NAME, { keyPath: "key" })
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error || new Error("Não foi possível abrir o armazenamento local"))
    request.onblocked = () => reject(new Error("O armazenamento local está bloqueado por outra aba"))
  }).catch((error) => {
    databasePromise = null
    throw error
  })
  return databasePromise
}

function requestResult<T>(request: IDBRequest<T>) {
  return new Promise<T>((resolve, reject) => {
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error || new Error("Falha no armazenamento local"))
  })
}

export async function readLocalRecord<T>(key: string): Promise<T | undefined> {
  const database = await openDatabase()
  const transaction = database.transaction(STORE_NAME, "readonly")
  const row = await requestResult(transaction.objectStore(STORE_NAME).get(key)) as LocalRecord<T> | undefined
  return row?.value
}

export async function writeLocalRecord<T>(key: string, value: T): Promise<void> {
  const database = await openDatabase()
  await new Promise<void>((resolve, reject) => {
    const transaction = database.transaction(STORE_NAME, "readwrite")
    transaction.objectStore(STORE_NAME).put({ key, value, updatedAt: new Date().toISOString() } satisfies LocalRecord<T>)
    transaction.oncomplete = () => resolve()
    transaction.onerror = () => reject(transaction.error || new Error("Falha ao salvar localmente"))
    transaction.onabort = () => reject(transaction.error || new Error("Gravação local cancelada"))
  })
}

export async function deleteLocalRecord(key: string): Promise<void> {
  const database = await openDatabase()
  await new Promise<void>((resolve, reject) => {
    const transaction = database.transaction(STORE_NAME, "readwrite")
    transaction.objectStore(STORE_NAME).delete(key)
    transaction.oncomplete = () => resolve()
    transaction.onerror = () => reject(transaction.error || new Error("Falha ao remover dado local"))
  })
}
