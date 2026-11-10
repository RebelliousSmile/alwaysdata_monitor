<script setup lang="ts">
import { computed, ref } from 'vue'
import DataGate from '@/components/DataGate.vue'
import NotYet from '@/components/NotYet.vue'
import ScreenTitle from '@/components/ScreenTitle.vue'
import StatusChip from '@/components/StatusChip.vue'
import type { ApiError } from '@/lib/api'
import { SEVERITY_LABEL } from '@/lib/checks'
import { now } from '@/lib/clock'
import { useSiteData } from '@/lib/site-data'
import { formatWhen } from '@/lib/time'
import {
  byComponent,
  cvss,
  fixText,
  percent,
  redistributionLabel,
  ruleLabel,
  severityTone,
  verdictLabel,
  versionsText,
  waiverLabel,
} from '@/lib/vulns'

// Failles connues des composants du site (#21), en lecture seule : aucune
// action d'écriture, la mise à jour se fait sur le site. Chaque faille porte
// ses attributions ; tout texte venu d'une source est interpolé, jamais rendu
// en HTML. 404 : site sans inventaire déclaré, jamais rapproché, ou veilleur
// antérieur à ces routes.

const { site, sites } = useSiteData()

const vulns = computed(() => sites.vulns[site.value]?.data)
const components = computed(() => sites.components[site.value]?.data)
const error = computed(() => sites.errors[`vulns:${site.value}`])
const unavailable = computed(() => error.value?.kind === 'not_found')
const groups = computed(() => byComponent(vulns.value?.items ?? []))
const notice = computed(() => sites.notices[`vulns:${site.value}`] ?? sites.notices[`components:${site.value}`])

const busy = ref(false)
const moreError = ref<ApiError | null>(null)

async function showMore(kind: 'vulns' | 'components'): Promise<void> {
  busy.value = true
  moreError.value = kind === 'vulns' ? await sites.moreVulns(site.value) : await sites.moreComponents(site.value)
  if (moreError.value?.kind === 'cursor_expired') moreError.value = null
  busy.value = false
}
</script>

<template>
  <ScreenTitle
    title="Failles"
    hint="Failles connues des composants du site, d’après son inventaire"
  />
  <NotYet
    v-if="unavailable"
    feature="wordpress"
  />
  <DataGate
    v-else
    :ready="vulns !== undefined"
    :error="error"
    not-paired="Les failles connues des composants du site s’affichent ici, avec leur gravité et leur version corrigée."
  >
    <p
      class="text-sm text-text-2"
      data-reminder
    >
      Lecture seule : mettre à jour un composant se fait sur le site. Les dérogations se saisissent sur le veilleur
      (vigie site vulns-ack).
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
      v-if="!groups.length"
      class="text-sm text-text-3"
      data-empty
    >
      Aucune faille connue ne touche les composants de la dernière lecture.
    </p>
    <section
      v-for="group in groups"
      :key="group.purl"
      class="flex flex-col gap-2 rounded-card border border-line bg-surface px-3.5 py-3"
      data-component
    >
      <div class="flex flex-wrap items-center gap-2">
        <h2 class="min-w-0 flex-1 break-all font-mono text-sm font-semibold">
          {{ group.purl }}
        </h2>
        <StatusChip
          :tone="severityTone(group.severity)"
          :label="SEVERITY_LABEL[group.severity]"
        />
      </div>
      <p class="text-sm text-text-2">
        {{ group.vulns.length }} faille(s) · {{ group.fixable ? 'correction disponible' : 'aucune correction connue' }}
      </p>
      <ul class="flex flex-col divide-y divide-line">
        <li
          v-for="vuln in group.vulns"
          :key="vuln.group"
          class="flex flex-col gap-1 py-2 text-sm"
          data-vuln
        >
          <div class="flex flex-wrap items-center gap-2">
            <span class="min-w-0 flex-1 break-all font-mono">{{ vuln.group }}</span>
            <StatusChip
              :tone="severityTone(vuln.severity)"
              :label="`${SEVERITY_LABEL[vuln.severity]} · ${verdictLabel(vuln.verdict)}`"
            />
          </div>
          <p
            v-if="vuln.ids.length > 1"
            class="break-all text-xs text-text-3"
          >
            {{ vuln.ids.filter((id) => id !== vuln.group).join(', ') }}
          </p>
          <p class="text-text-2">
            {{ versionsText(vuln) }}<template v-if="fixText(vuln)">
              · {{ fixText(vuln) }}
            </template>
          </p>
          <p class="text-text-3">
            Règle : {{ ruleLabel(vuln.rule) }}<template v-if="vuln.score !== null">
              · CVSS {{ cvss(vuln.score) }}
            </template><template v-if="vuln.epss">
              · EPSS {{ percent(vuln.epss.score) }}
            </template><template v-if="vuln.corrected">
              · plage corrigée
            </template>
          </p>
          <p
            v-if="vuln.kev"
            class="text-danger-text"
            data-kev
          >
            Exploitée (CISA KEV) depuis le {{ vuln.kev.date_added }}<template v-if="vuln.kev.ransomware">
              , usage par rançongiciel connu
            </template>
          </p>
          <p
            v-if="vuln.waiver"
            class="text-text-2"
            data-waiver
          >
            Sous dérogation ({{ vuln.waiver.source }}) jusqu’au {{ formatWhen(vuln.waiver.until, now) }} : {{ waiverLabel(vuln.waiver.state) }}
          </p>
          <p
            v-if="redistributionLabel(vuln.redistribution)"
            class="text-xs font-semibold text-text-2"
            data-redistribution
          >
            {{ redistributionLabel(vuln.redistribution) }}
          </p>
          <ul class="flex flex-col text-xs text-text-3">
            <li
              v-for="link in vuln.links"
              :key="link.url"
              class="break-all"
              data-link
            >
              {{ link.source }} : {{ link.url }}
            </li>
          </ul>
          <ul class="flex flex-col text-xs text-text-3">
            <li
              v-for="attribution in vuln.attributions"
              :key="attribution"
              class="break-words"
              data-attribution
            >
              {{ attribution }}
            </li>
          </ul>
        </li>
      </ul>
    </section>
    <p
      v-if="moreError"
      role="alert"
      class="text-sm text-danger-text"
      data-more-error
    >
      {{ moreError.message }}
    </p>
    <button
      v-if="vulns?.next_cursor"
      type="button"
      class="flex min-h-tap items-center justify-center rounded-control border border-control text-text"
      :disabled="busy"
      data-more
      @click="showMore('vulns')"
    >
      Afficher plus de failles
    </button>

    <section
      v-if="components"
      aria-labelledby="composants"
      class="flex flex-col gap-1"
    >
      <h2
        id="composants"
        class="text-xs uppercase tracking-wider text-text-3"
      >
        Composants rapprochés
      </h2>
      <ul class="divide-y divide-line rounded-card border border-line bg-surface text-sm">
        <li
          v-for="(component, index) in components.items"
          :key="`${index}-${component.source}-${component.purl}`"
          class="flex flex-wrap items-center gap-2 px-3.5 py-2"
          data-row
        >
          <span class="min-w-0 flex-1 break-all font-mono">{{ component.purl }}</span>
          <span class="text-text-3">{{ component.source }} · {{ component.version ?? 'version inconnue' }} · {{ component.vulns }} faille(s)</span>
          <StatusChip
            v-if="component.severity"
            :tone="severityTone(component.severity)"
            :label="SEVERITY_LABEL[component.severity]"
          />
        </li>
      </ul>
      <button
        v-if="components.next_cursor"
        type="button"
        class="flex min-h-tap items-center justify-center rounded-control border border-control text-text"
        :disabled="busy"
        data-more-components
        @click="showMore('components')"
      >
        Afficher plus de composants
      </button>
    </section>
  </DataGate>
</template>
