<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import DataGate from '@/components/DataGate.vue'
import PointRow from '@/components/PointRow.vue'
import ScreenTitle from '@/components/ScreenTitle.vue'
import StateScreen from '@/components/StateScreen.vue'
import {
  SEVERITY_LABEL,
  SEVERITY_STATE,
  bySeverity,
  checkLabel,
  checkScreen,
  mailEvents,
} from '@/lib/checks'
import type { Incident } from '@/lib/api'
import { now } from '@/lib/clock'
import { useSiteData } from '@/lib/site-data'
import { formatWhen } from '@/lib/time'

// Liste des points ouverts et détail d'une alerte : côte à côte au-delà de
// 900 px, l'un ou l'autre sur mobile.
const route = useRoute()
const { to, detail, error, history, missing } = useSiteData()
const detailOpen = computed(() => route.name === 'alerte')

const points = computed(() => [...(detail.value?.open_incidents ?? [])].sort(bySeverity))

/** Contrôles passés sans constat, et sans incident ouvert. */
const fine = computed(() => {
  const open = new Set(points.value.map((i) => i.check))
  return (detail.value?.checks ?? []).filter((c) => c.result === 'ok' && !open.has(c.name))
})

const mails = computed(() => mailEvents([...points.value, ...(history.value?.incidents ?? [])]))

function fact(incident: Incident): string {
  const parts = [checkLabel(incident.check), `ouvert ${formatWhen(incident.opened_at, now.value)}`]
  if (incident.acked_at !== null) parts.push(`acquitté ${formatWhen(incident.acked_at, now.value)}`)
  return parts.join(' · ')
}

const count = computed(() => {
  const n = points.value.length
  return n === 1 ? '1 point ouvert' : `${n} points ouverts`
})
</script>

<template>
  <div
    class="flex flex-col gap-3 wide:grid wide:grid-cols-[minmax(0,2fr)_minmax(0,3fr)] wide:items-start wide:gap-4"
    data-list-detail
  >
    <section
      class="flex-col gap-3"
      :class="detailOpen ? 'hidden wide:flex' : 'flex'"
      data-list
    >
      <ScreenTitle
        title="À traiter"
        hint="Du plus grave au moins grave"
      />
      <DataGate
        :ready="detail !== undefined"
        :error="error"
        :missing="missing"
        not-paired="Les points ouverts du site, les alertes envoyées et ce qui va bien s’affichent ici."
      >
        <template v-if="detail">
          <StateScreen
            v-if="detail.state === 'first_read'"
            state="first_read"
            title="Première lecture"
            text="Le veilleur n’a encore lu aucun contrôle ni reçu aucun rapport de ce site."
          />
          <section
            v-else-if="points.length"
            aria-labelledby="points"
            class="flex flex-col gap-1"
          >
            <h2
              id="points"
              class="text-xs uppercase tracking-wider text-text-3"
            >
              {{ count }}
            </h2>
            <ul class="divide-y divide-line overflow-hidden rounded-card border border-line bg-surface">
              <li
                v-for="incident in points"
                :key="incident.id"
                data-point
              >
                <PointRow
                  :to="to('alerte', { id: String(incident.id) })"
                  :state="SEVERITY_STATE[incident.severity]"
                  :label="SEVERITY_LABEL[incident.severity]"
                  :title="incident.detail"
                  :fact="fact(incident)"
                  :where="checkScreen(incident.check).label"
                  :selected="route.params.id === String(incident.id)"
                />
              </li>
            </ul>
          </section>
          <StateScreen
            v-else
            state="ok"
            title="Rien à traiter"
            text="Aucun incident ouvert sur ce site."
          />

          <section
            v-if="fine.length"
            aria-labelledby="fine"
            class="flex flex-col gap-1"
          >
            <h2
              id="fine"
              class="text-xs uppercase tracking-wider text-text-3"
            >
              Le reste va bien
            </h2>
            <ul class="divide-y divide-line rounded-card border border-line bg-surface text-sm">
              <li
                v-for="check in fine"
                :key="check.name"
                class="flex items-center gap-2 px-3.5 py-2"
                data-fine
              >
                <span
                  class="text-ok"
                  aria-hidden="true"
                >✓</span>
                <span class="flex-1">{{ checkLabel(check.name) }}</span>
                <span
                  v-if="check.last_run !== null"
                  class="text-xs text-text-3"
                >{{ formatWhen(check.last_run, now) }}</span>
              </li>
            </ul>
          </section>

          <section
            aria-labelledby="mails"
            class="flex flex-col gap-1"
          >
            <h2
              id="mails"
              class="text-xs uppercase tracking-wider text-text-3"
            >
              Alertes envoyées
            </h2>
            <ul
              v-if="mails.length"
              class="divide-y divide-line rounded-card border border-line bg-surface text-sm"
            >
              <li
                v-for="mail in mails"
                :key="`${mail.incident.id}-${mail.kind}`"
                class="flex flex-wrap items-baseline gap-x-2 px-3.5 py-2"
                data-mail
              >
                <span class="font-semibold">{{ mail.kind }}</span>
                <span class="flex-1 text-text-2">{{ checkLabel(mail.incident.check) }} · n° {{ mail.incident.id }}</span>
                <span class="text-xs text-text-3">{{ formatWhen(mail.at, now) }}</span>
              </li>
            </ul>
            <p
              v-else
              class="text-sm text-text-3"
            >
              Aucun e-mail envoyé pour les incidents ouverts ni pour ceux fermés depuis 30 jours.
            </p>
          </section>
        </template>
      </DataGate>
    </section>
    <section
      class="flex-col gap-3"
      :class="detailOpen ? 'flex' : 'hidden wide:flex'"
      data-detail
    >
      <RouterView />
    </section>
  </div>
</template>
