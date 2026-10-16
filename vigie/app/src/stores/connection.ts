import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { api, isApiError, type ApiError, type Status } from '@/lib/api'

// Appairage et joignabilité du veilleur. Le jeton reste côté Rust : le
// webview ne connaît que l'appareil (nom, numéro, adresse du veilleur).

export type Trouble = 'offline' | 'server'

const nowSeconds = (): number => Math.floor(Date.now() / 1000)

export const asApiError = (err: unknown): ApiError =>
  isApiError(err) ? err : { kind: 'server', message: String(err) }

export const useConnection = defineStore('connection', () => {
  /** `null` tant que la session enregistrée n'a pas été lue. */
  const paired = ref<boolean | null>(null)
  const device = ref<Status | null>(null)
  /** Dernier échec de lecture, effacé par la réponse suivante. */
  const trouble = ref<Trouble | null>(null)
  /** Heure de la dernière réponse du veilleur. */
  const lastOk = ref<number | null>(null)
  /** Message à garder après un changement d'écran (révocation, retrait). */
  const notice = ref<string | null>(null)

  const online = computed(() => trouble.value === null)

  async function init(): Promise<void> {
    try {
      device.value = await api.status()
    } catch {
      device.value = null
    }
    paired.value = device.value !== null
  }

  async function pair(link: string): Promise<void> {
    device.value = await api.pair(link)
    paired.value = true
    notice.value = null
    ok()
  }

  /** Retire cet appareil ; si le veilleur est injoignable, dit quoi lancer. */
  async function unpair(): Promise<void> {
    const result = await api.unpair()
    notice.value = result.revoked
      ? 'Cet appareil est retiré : le veilleur a révoqué son jeton.'
      : `Le veilleur est injoignable : le jeton local est supprimé, mais l’appareil n° ${result.device_id} reste actif côté veilleur. Sur le VPS : vigie device revoke ${result.device_id}`
    forget()
  }

  function ok(): void {
    trouble.value = null
    lastOk.value = nowSeconds()
  }

  function fail(err: ApiError): void {
    switch (err.kind) {
      case 'offline':
        trouble.value = 'offline'
        break
      case 'server':
      case 'storage':
        trouble.value = 'server'
        break
      case 'unauthorized':
        notice.value = 'Le veilleur ne reconnaît plus cet appareil : il a été révoqué. Appairez-le de nouveau.'
        forget()
        break
      case 'not_paired':
        forget()
        break
      default:
        break
    }
  }

  function forget(): void {
    device.value = null
    paired.value = false
    trouble.value = null
  }

  return { paired, device, trouble, lastOk, notice, online, init, pair, unpair, ok, fail, forget }
})
