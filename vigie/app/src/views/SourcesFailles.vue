<script setup lang="ts">
import { computed } from 'vue'
import DataGate from '@/components/DataGate.vue'
import ScreenTitle from '@/components/ScreenTitle.vue'
import StatusChip from '@/components/StatusChip.vue'
import type { VulnSource } from '@/lib/api'
import { SEVERITY_LABEL } from '@/lib/checks'
import { now } from '@/lib/clock'
import { useSites } from '@/stores/sites'
import { formatWhen } from '@/lib/time'
import { redistributionLabel, severityTone } from '@/lib/vulns'

// Sources de failles du veilleur (#21, vue veilleur de F2) : âge de la
// dernière réussite, dernière issue, entrées, licence et attribution de
// chaque source, jeu actif de KEV et d'EPSS, constat vulns-sync ouvert.
// Lecture seule ; tout texte venu d'une source est interpolé.

const sites = useSites()
const sources = computed(() => sites.vulnSources?.data)
const error = computed(() => sites.errors['vuln-sources'])

const OUTCOMES: Record<string, string> = {
  loaded: 'chargée',
  unchanged: 'inchangée',
  not_modified: 'inchangée (304)',
  failed: 'en échec',
  busy: 'chargement déjà en cours',
  refused_shrink: 'refusée : base qui rétrécit',
  rate_limited: 'reportée : débit de la source',
}

function outcome(source: VulnSource): string {
  if (source.last_outcome === null) return 'jamais tentée'
  return OUTCOMES[source.last_outcome] ?? source.last_outcome
}

function age(source: VulnSource): string {
  return source.last_success_at === null
    ? 'jamais synchronisée'
    : `synchronisée ${formatWhen(source.last_success_at, now.value)}`
}
</script>

<template>
  <ScreenTitle
    title="Sources de failles"
    hint="Bases de failles et tables d’exploitation lues par le veilleur"
  />
  <DataGate
    :ready="sources !== undefined"
    :error="error"
    not-paired="Les bases de failles du veilleur, leur âge et leurs attributions s’affichent ici."
  >
    <p
      v-if="sources && !sources.sources.length"
      class="text-sm text-text-3"
      data-empty
    >
      Aucune source de failles déclarée ([vulns] sources de config.toml sur le VPS).
    </p>
    <ul
      v-else
      class="flex flex-col gap-2"
    >
      <li
        v-for="source in sources?.sources ?? []"
        :key="source.id"
        class="flex flex-col gap-1 rounded-card border border-line bg-surface px-3.5 py-3 text-sm"
        data-source
      >
        <div class="flex flex-wrap items-center gap-2">
          <span class="min-w-0 flex-1 break-all font-mono font-semibold">{{ source.id }}</span>
          <StatusChip
            :tone="source.last_success_at === null ? 'neutral' : 'ok'"
            :label="source.kind === 'enrichment' ? 'Exploitation' : 'Failles'"
          />
        </div>
        <p class="text-text-2">
          {{ age(source) }} · dernière tentative {{ outcome(source) }} · {{ source.entries }} entrée(s)
        </p>
        <p
          v-if="source.dataset"
          class="text-text-3"
        >
          Jeu {{ source.dataset.version }} publié {{ formatWhen(source.dataset.released, now) }}
        </p>
        <p class="text-text-3">
          Licence : {{ source.license || 'par enregistrement' }}
        </p>
        <p
          v-if="source.attribution"
          class="break-words text-xs text-text-3"
          data-attribution
        >
          {{ source.attribution }}
        </p>
        <p
          v-if="redistributionLabel(source.redistribution)"
          class="text-xs font-semibold text-text-2"
        >
          {{ redistributionLabel(source.redistribution) }}
        </p>
        <RouterLink
          v-if="source.incident"
          :to="{ name: 'alerte', params: { site: '_veilleur', id: String(source.incident.id) } }"
          class="flex flex-wrap items-center gap-2"
          data-incident
        >
          <StatusChip
            :tone="severityTone(source.incident.severity)"
            :label="SEVERITY_LABEL[source.incident.severity]"
          />
          <span>Incident n° {{ source.incident.id }} : base en retard depuis {{ formatWhen(source.incident.opened_at, now) }}</span>
        </RouterLink>
      </li>
    </ul>
  </DataGate>
</template>
