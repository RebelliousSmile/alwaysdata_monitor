<script setup lang="ts">
import { getVersion } from '@tauri-apps/api/app'
import { computed, onMounted, ref } from 'vue'
import AppIcon from '@/components/AppIcon.vue'
import DataGate from '@/components/DataGate.vue'
import StatusChip from '@/components/StatusChip.vue'
import type { Device, TokenStorage } from '@/lib/api'
import { now } from '@/lib/clock'
import { THEMES } from '@/lib/theme'
import { formatSpan, formatWhen } from '@/lib/time'
import { asApiError, useConnection } from '@/stores/connection'
import { useSites } from '@/stores/sites'
import { useTheme } from '@/stores/theme'

// Réglages globaux, en lecture, et la seule action sur l'appareil : son
// retrait. La version vient du binaire (tauri.conf.json).
const connection = useConnection()
const sites = useSites()
const theme = useTheme()
const settings = computed(() => sites.settings?.data)

const version = ref<string | null>(null)
onMounted(async () => {
  try {
    version.value = await getVersion()
  } catch {
    version.value = null
  }
})

function deviceState(device: Device): { tone: 'ok' | 'neutral'; label: string } {
  if (device.revoked_at !== null) return { tone: 'neutral', label: `Révoqué ${formatWhen(device.revoked_at, now.value)}` }
  return { tone: 'ok', label: 'Actif' }
}

// Où vit le jeton de cet appareil. Seul l'ancien fichier est un état
// dégradé : la migration est retentée à chaque lancement.
const TOKEN_STORAGE: Record<TokenStorage, { tone: 'ok' | 'warn'; label: string; detail: string }> = {
  keyring: {
    tone: 'ok',
    label: 'Trousseau du système',
    detail: 'Jeton rangé dans le Credential Manager de Windows, pour ce poste seulement.',
  },
  private_file: {
    tone: 'ok',
    label: 'Stockage privé',
    detail: 'Jeton dans le stockage privé de l’application, exclu de la sauvegarde et du transfert vers un autre téléphone.',
  },
  file_legacy: {
    tone: 'warn',
    label: 'Ancien fichier',
    detail: 'Le jeton n’a pas pu être rangé dans le trousseau : il reste dans le fichier de l’appareil. Nouvel essai au prochain lancement.',
  },
}
const tokenStorage = computed(() => {
  const storage = connection.device?.token_storage
  return storage ? TOKEN_STORAGE[storage] : null
})

const confirming = ref(false)
const removing = ref(false)
const removeError = ref<string | null>(null)

async function remove(): Promise<void> {
  removing.value = true
  removeError.value = null
  try {
    await connection.unpair()
  } catch (err) {
    removeError.value = `Retrait impossible : ${asApiError(err).message}`
  } finally {
    removing.value = false
    confirming.value = false
  }
}
</script>

<template>
  <h1 class="sr-only">
    Réglages
  </h1>
  <DataGate
    :ready="settings !== undefined"
    :error="sites.errors.settings"
    not-paired="Le destinataire des alertes et les appareils appairés s’affichent ici."
  >
    <template v-if="settings">
      <section
        aria-labelledby="alertes"
        class="flex flex-col gap-1"
      >
        <h2
          id="alertes"
          class="text-xs uppercase tracking-wider text-text-3"
        >
          Alertes
        </h2>
        <dl class="divide-y divide-line rounded-card border border-line bg-surface text-sm">
          <div class="flex flex-wrap gap-x-3 px-3.5 py-2.5">
            <dt class="w-44 flex-none text-text-2">
              Destinataire
            </dt>
            <dd
              class="font-mono"
              data-recipient
            >
              {{ settings.alerts.to }}
            </dd>
          </div>
          <div class="flex flex-wrap gap-x-3 px-3.5 py-2.5">
            <dt class="w-44 flex-none text-text-2">
              Relance
            </dt>
            <dd>toutes les {{ formatSpan(settings.reminder_period) }} tant que l’incident n’est pas acquitté</dd>
          </div>
        </dl>
        <p class="text-xs text-text-3">
          Le destinataire se change dans config.toml sur le VPS ; « vigie test-alert » envoie un e-mail d’essai.
        </p>
      </section>

      <section
        aria-labelledby="appareils"
        class="flex flex-col gap-1"
      >
        <h2
          id="appareils"
          class="text-xs uppercase tracking-wider text-text-3"
        >
          Appareils
        </h2>
        <ul class="divide-y divide-line rounded-card border border-line bg-surface text-sm">
          <li
            v-for="device in settings.devices"
            :key="device.id"
            class="flex flex-col gap-0.5 px-3.5 py-2.5"
            data-device
          >
            <div class="flex flex-wrap items-center gap-2">
              <span class="flex-1 font-semibold">
                {{ device.name }}<span class="font-normal text-text-3"> · n° {{ device.id }}</span>
                <span
                  v-if="device.current"
                  class="font-normal text-text-2"
                > · cet appareil</span>
              </span>
              <StatusChip v-bind="deviceState(device)" />
            </div>
            <span class="text-xs text-text-3">
              Appairé {{ formatWhen(device.created_at, now) }}<template v-if="device.seen_at !== null">, vu {{ formatWhen(device.seen_at, now) }}</template>
            </span>
          </li>
        </ul>
        <p class="text-xs text-text-3">
          Révoquer un autre appareil : vigie device revoke &lt;n°&gt; sur le VPS.
        </p>
      </section>
    </template>
  </DataGate>

  <section
    v-if="connection.paired === true"
    class="flex flex-col gap-2 rounded-card border border-line bg-surface p-3.5"
    data-unpair
  >
    <div
      v-if="tokenStorage"
      class="flex flex-col gap-0.5"
      data-token-storage
    >
      <div class="flex flex-wrap items-center gap-2">
        <span class="flex-1 text-sm font-semibold">Jeton de cet appareil</span>
        <StatusChip
          :tone="tokenStorage.tone"
          :label="tokenStorage.label"
        />
      </div>
      <span class="text-xs text-text-3">{{ tokenStorage.detail }}</span>
    </div>
    <p class="text-sm text-text-2">
      Retirer cet appareil révoque son jeton côté veilleur et l’efface de l’appareil.
    </p>
    <button
      v-if="!confirming"
      type="button"
      class="flex min-h-tap items-center justify-center rounded-control border border-danger-line text-danger-text"
      @click="confirming = true"
    >
      Retirer cet appareil
    </button>
    <div
      v-else
      class="flex gap-2"
    >
      <button
        type="button"
        class="flex min-h-tap flex-1 items-center justify-center rounded-control bg-danger font-semibold text-bg disabled:opacity-60"
        :disabled="removing"
        @click="remove"
      >
        {{ removing ? 'Retrait…' : 'Confirmer le retrait' }}
      </button>
      <button
        type="button"
        class="flex min-h-tap flex-1 items-center justify-center rounded-control border border-control text-text"
        :disabled="removing"
        @click="confirming = false"
      >
        Annuler
      </button>
    </div>
    <p
      v-if="removeError"
      role="alert"
      class="text-sm text-danger-text"
    >
      {{ removeError }}
    </p>
  </section>

  <RouterLink
    :to="{ name: 'sources-failles' }"
    class="flex min-h-tap items-center gap-3 rounded-card border border-line bg-surface px-3.5 py-3 text-text"
    data-sources-link
  >
    <span class="flex-1">Sources de failles</span>
    <span class="text-text-3"><AppIcon
      name="next"
      :size="18"
    /></span>
  </RouterLink>
  <section
    aria-labelledby="theme"
    class="flex flex-col gap-1"
    data-theme-choice
  >
    <h2
      id="theme"
      class="text-xs uppercase tracking-wider text-text-3"
    >
      Thème
    </h2>
    <div
      role="radiogroup"
      aria-labelledby="theme"
      class="grid grid-cols-2 rounded-control border border-line bg-surface p-[3px]"
    >
      <label
        v-for="choice in THEMES"
        :key="choice.value"
        class="flex min-h-tap cursor-pointer items-center justify-center rounded-sym text-md text-text-2 has-[:checked]:bg-surface-3 has-[:checked]:font-semibold has-[:checked]:text-text has-[:focus-visible]:outline has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-ok"
      >
        <input
          type="radio"
          name="theme"
          class="sr-only"
          :value="choice.value"
          :checked="theme.theme === choice.value"
          @change="theme.set(choice.value)"
        >
        {{ choice.label }}
      </label>
    </div>
  </section>
  <p
    class="text-center text-xs text-text-3"
    data-version
  >
    Console Vigie{{ version ? ` ${version}` : '' }}
  </p>
</template>
