<script setup lang="ts">
import { computed, ref } from 'vue'
import DataGate from '@/components/DataGate.vue'
import ScreenTitle from '@/components/ScreenTitle.vue'
import StatusChip from '@/components/StatusChip.vue'
import type { ApiError } from '@/lib/api'
import { SEVERITY_LABEL, checkLabel, isExternal, resultChip, tlsNotAfter } from '@/lib/checks'
import { now } from '@/lib/clock'
import { useSiteData } from '@/lib/site-data'
import { formatWhen } from '@/lib/time'

// Disponibilité : contrôles externes, certificat, incidents des 30 jours.
const { site, sites, to, detail, error, history, missing } = useSiteData()

const external = computed(() => (detail.value?.checks ?? []).filter((c) => isExternal(c.name)))

const certificate = computed(() => {
  const notAfter = tlsNotAfter(detail.value?.checks ?? [])
  if (notAfter === null) return undefined
  const days = Math.floor((notAfter - now.value) / 86400)
  const date = new Intl.DateTimeFormat('fr-FR', {
    timeZone: 'Europe/Paris',
    day: 'numeric',
    month: 'long',
    year: 'numeric',
  }).format(new Date(notAfter * 1000))
  const left = days < 0 ? 'expiré' : days === 0 ? 'expire aujourd’hui' : days === 1 ? 'encore 1 jour' : `encore ${days} jours`
  return { date, left, tone: days < 14 ? ('warn' as const) : ('ok' as const) }
})

const closed = computed(() => history.value?.incidents ?? [])

// « Afficher plus » : page suivante des incidents clos, ajoutée au bout. Un
// échec (429…) reste affiché, sans relance automatique.
const busy = ref(false)
const moreError = ref<ApiError | null>(null)
const notice = computed(() => sites.notices[`history:${site.value}`])

async function showMore(): Promise<void> {
  busy.value = true
  moreError.value = await sites.moreHistory(site.value)
  if (moreError.value?.kind === 'cursor_expired') moreError.value = null
  busy.value = false
}
</script>

<template>
  <ScreenTitle
    title="Disponibilité"
    hint="Contrôles externes, incidents des 30 jours, certificat"
  />
  <DataGate
    :ready="detail !== undefined"
    :error="error"
    :missing="missing"
    not-paired="Les contrôles externes du site, avec leur durée et leur heure, s’affichent ici."
  >
    <section
      aria-labelledby="externes"
      class="flex flex-col gap-1"
    >
      <h2
        id="externes"
        class="text-xs uppercase tracking-wider text-text-3"
      >
        Contrôles externes
      </h2>
      <ul class="divide-y divide-line rounded-card border border-line bg-surface text-sm">
        <li
          v-for="check in external"
          :key="check.name"
          class="flex flex-col gap-1 px-3.5 py-2.5"
          data-check
        >
          <div class="flex flex-wrap items-center gap-2">
            <span class="flex-1 font-semibold">{{ checkLabel(check.name) }}</span>
            <StatusChip v-bind="resultChip(check)" />
          </div>
          <p
            v-if="check.detail"
            class="text-text-2"
          >
            {{ check.detail }}
          </p>
          <p class="text-xs text-text-3">
            <template v-if="check.last_run !== null">
              Passé {{ formatWhen(check.last_run, now) }}<template v-if="check.duration_ms !== null">
                · {{ check.duration_ms }} ms
              </template>
            </template>
            <template v-else>
              Jamais passé
            </template>
          </p>
        </li>
      </ul>
    </section>

    <section
      aria-labelledby="certificat"
      class="flex flex-col gap-1"
    >
      <h2
        id="certificat"
        class="text-xs uppercase tracking-wider text-text-3"
      >
        Certificat
      </h2>
      <div
        class="flex flex-wrap items-center gap-2 rounded-card border border-line bg-surface px-3.5 py-3 text-sm"
        data-certificate
      >
        <template v-if="certificate">
          <span class="flex-1">Valide jusqu’au {{ certificate.date }}</span>
          <StatusChip
            :tone="certificate.tone"
            :label="certificate.left"
          />
        </template>
        <span
          v-else
          class="text-text-3"
        >Pas encore relevé par le contrôle du certificat.</span>
      </div>
    </section>

    <section
      aria-labelledby="historique"
      class="flex flex-col gap-1"
    >
      <h2
        id="historique"
        class="text-xs uppercase tracking-wider text-text-3"
      >
        Incidents fermés depuis 30 jours
      </h2>
      <ul
        v-if="closed.length"
        class="divide-y divide-line rounded-card border border-line bg-surface text-sm"
      >
        <li
          v-for="incident in closed"
          :key="incident.id"
          data-closed
        >
          <RouterLink
            :to="to('alerte', { id: String(incident.id) })"
            class="flex flex-col gap-0.5 px-3.5 py-2.5 text-text"
          >
            <span class="font-semibold">{{ checkLabel(incident.check) }} · {{ SEVERITY_LABEL[incident.severity] }}</span>
            <span class="text-text-2">{{ incident.detail }}</span>
            <span class="text-xs text-text-3">
              Ouvert {{ formatWhen(incident.opened_at, now) }}<template v-if="incident.closed_at !== null">, fermé {{ formatWhen(incident.closed_at, now) }}</template>
            </span>
          </RouterLink>
        </li>
      </ul>
      <p
        v-else-if="history"
        class="text-sm text-text-3"
      >
        Aucun incident fermé depuis 30 jours.
      </p>
      <p
        v-else
        class="text-sm text-text-3"
      >
        Historique pas encore lu.
      </p>
      <p
        v-if="notice"
        role="status"
        class="rounded-control bg-info-bg px-3 py-2 text-sm text-text"
        data-list-notice
      >
        {{ notice }}
      </p>
      <p
        v-if="moreError"
        role="alert"
        class="text-sm text-danger-text"
        data-more-error
      >
        {{ moreError.message }}
      </p>
      <button
        v-if="history?.next_cursor"
        type="button"
        class="flex min-h-tap items-center justify-center rounded-control border border-control text-text"
        :disabled="busy"
        data-more
        @click="showMore"
      >
        Afficher plus
      </button>
    </section>
  </DataGate>
</template>
