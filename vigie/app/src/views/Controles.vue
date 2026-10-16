<script setup lang="ts">
import { computed } from 'vue'
import DataGate from '@/components/DataGate.vue'
import NotYet from '@/components/NotYet.vue'
import ScreenTitle from '@/components/ScreenTitle.vue'
import StatusChip from '@/components/StatusChip.vue'
import type { Check } from '@/lib/api'
import { checkLabel, isExternal, resultChip } from '@/lib/checks'
import { now } from '@/lib/clock'
import { useSiteData } from '@/lib/site-data'
import { formatSpan, formatWhen } from '@/lib/time'

// Contrôles : chaque contrôle du site avec son dernier résultat et son heure.
const { detail, error, missing } = useSiteData()

const groups = computed(() => {
  const checks = detail.value?.checks ?? []
  return [
    { key: 'externes', title: 'Contrôles externes', checks: checks.filter((c) => isExternal(c.name)) },
    { key: 'agent', title: 'Contrôles de l’agent', checks: checks.filter((c) => !isExternal(c.name)) },
  ]
})

function cadence(check: Check): string | undefined {
  if (check.name === 'heartbeat' && check.interval !== null) return `silence toléré ${formatSpan(check.interval)}`
  if (check.interval !== null) return `toutes les ${formatSpan(check.interval)}`
  if (check.name.startsWith('agent:')) return 'à chaque rapport de l’agent'
  return undefined
}
</script>

<template>
  <ScreenTitle
    title="Contrôles"
    hint="Contrôles externes et contrôles de l’agent"
  />
  <DataGate
    :ready="detail !== undefined"
    :error="error"
    :missing="missing"
    not-paired="Chaque contrôle s’affiche ici avec son dernier résultat et son heure."
  >
    <section
      v-for="group in groups"
      :key="group.key"
      :aria-labelledby="`groupe-${group.key}`"
      class="flex flex-col gap-1"
    >
      <h2
        :id="`groupe-${group.key}`"
        class="text-xs uppercase tracking-wider text-text-3"
      >
        {{ group.title }}
      </h2>
      <ul
        v-if="group.checks.length"
        class="divide-y divide-line rounded-card border border-line bg-surface text-sm"
      >
        <li
          v-for="check in group.checks"
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
            {{ check.last_run !== null ? `Passé ${formatWhen(check.last_run, now)}` : 'Jamais passé' }}<template v-if="cadence(check)">
              · {{ cadence(check) }}
            </template>
          </p>
        </li>
      </ul>
      <p
        v-else
        class="text-sm text-text-3"
      >
        {{ group.key === 'agent' ? (detail?.agent ? 'L’agent n’a encore envoyé aucun rapport.' : 'Aucun agent déclaré pour ce site.') : 'Aucun contrôle externe.' }}
      </p>
    </section>
  </DataGate>
  <NotYet
    feature="wordpress"
    compact
  />
  <NotYet
    feature="personnalises"
    compact
  />
  <NotYet
    feature="file"
    compact
  />
</template>
