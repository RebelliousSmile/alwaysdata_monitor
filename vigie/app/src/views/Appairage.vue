<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'
import ScreenTitle from '@/components/ScreenTitle.vue'
import type { ErrorKind } from '@/lib/api'
import { parsePairLink } from '@/lib/pairing'
import { isMobile } from '@/lib/platform'
import { asApiError, useConnection } from '@/stores/connection'
import { useSites } from '@/stores/sites'

// Appairage : le lien vigie://pair, scanné (mobile) ou collé, est vérifié
// ici puis échangé contre un jeton par la commande Rust `pair`. Le jeton ne
// revient jamais au webview.
const router = useRouter()
const connection = useConnection()
const sites = useSites()

const mobile = isMobile()
const link = ref('')
const busy = ref(false)
const failure = ref<string | null>(null)

const PAIR_ERRORS: Partial<Record<ErrorKind, string>> = {
  unauthorized: 'Code refusé : expiré (10 minutes), déjà utilisé ou inconnu. Relancez vigie device pair.',
  offline: 'Le veilleur ne répond pas à cette adresse.',
}

const canSubmit = computed(() => link.value.trim() !== '' && !busy.value)

async function submit(text: string = link.value): Promise<void> {
  failure.value = null
  const check = parsePairLink(text, import.meta.env.DEV)
  if (!check.ok) {
    failure.value = check.message
    return
  }
  busy.value = true
  try {
    await connection.pair(text.trim())
    // Un autre veilleur, peut-être : rien de l'ancien appairage ne reste.
    sites.clear()
    link.value = ''
    await router.push({ name: 'sites' })
  } catch (err) {
    const error = asApiError(err)
    failure.value =
      error.kind === 'invalid_link'
        ? `Lien refusé : ${error.message}`
        : (PAIR_ERRORS[error.kind] ?? `Appairage impossible : ${error.message}`)
  } finally {
    busy.value = false
  }
}

async function scanCode(): Promise<void> {
  failure.value = null
  try {
    // Chargé à la demande : le plugin n'existe que dans les builds mobiles.
    const { scan, Format } = await import('@tauri-apps/plugin-barcode-scanner')
    const result = await scan({ formats: [Format.QRCode] })
    link.value = result.content
    await submit(result.content)
  } catch (err) {
    failure.value = `Scan impossible : ${String(err)}. Collez le lien à la place.`
  }
}
</script>

<template>
  <ScreenTitle title="Appairer cet appareil" />
  <p
    v-if="connection.notice"
    role="status"
    class="rounded-card border border-line bg-surface-2 p-3.5 text-sm"
    data-notice
  >
    {{ connection.notice }}
  </p>
  <p
    v-if="connection.paired === true && connection.device"
    class="rounded-card border border-line bg-surface p-3.5 text-sm"
    data-paired
  >
    Cet appareil est déjà appairé (« {{ connection.device.name }} », n° {{ connection.device.device_id }}).
    Un nouvel appairage remplace le jeton actuel.
  </p>
  <section class="flex flex-col gap-2 rounded-card border border-line bg-surface p-4">
    <p>Sur le VPS, créez un code d’appairage valable 10 minutes :</p>
    <pre class="overflow-x-auto rounded-control bg-code p-3 font-mono text-sm">vigie device pair --name téléphone</pre>
    <p class="text-sm text-text-2">
      La commande affiche un QR code et un lien vigie://pair. {{ mobile ? 'Scannez le QR code, ou collez le lien.' : 'Collez le lien ci-dessous.' }}
    </p>
  </section>
  <button
    v-if="mobile"
    type="button"
    class="flex min-h-[48px] items-center justify-center rounded-control bg-primary font-semibold text-primary-on disabled:opacity-60"
    :disabled="busy"
    data-scan
    @click="scanCode"
  >
    Scanner le QR code
  </button>
  <form
    class="flex flex-col gap-2"
    @submit.prevent="submit()"
  >
    <label
      for="pair-link"
      class="text-sm text-text-2"
    >Lien d’appairage</label>
    <input
      id="pair-link"
      v-model="link"
      type="text"
      inputmode="url"
      autocomplete="off"
      autocapitalize="off"
      spellcheck="false"
      placeholder="vigie://pair?u=…&amp;c=…"
      class="min-h-tap rounded-control border border-control bg-surface px-3 font-mono text-sm text-text"
    >
    <button
      type="submit"
      class="flex min-h-[48px] items-center justify-center rounded-control font-semibold disabled:opacity-60"
      :class="mobile ? 'border border-control text-text' : 'bg-primary text-primary-on'"
      :disabled="!canSubmit"
    >
      {{ busy ? 'Appairage…' : 'Appairer' }}
    </button>
  </form>
  <p
    v-if="failure"
    role="alert"
    class="text-sm text-danger-text"
    data-failure
  >
    {{ failure }}
  </p>
</template>
