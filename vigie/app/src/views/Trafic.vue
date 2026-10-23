<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute, type RouteLocationRaw } from 'vue-router'
import DataGate from '@/components/DataGate.vue'
import NotYet from '@/components/NotYet.vue'
import Proposal from '@/components/Proposal.vue'
import ScreenTitle from '@/components/ScreenTitle.vue'
import StateScreen from '@/components/StateScreen.vue'
import StatusChip from '@/components/StatusChip.vue'
import type { ApiError, Rule } from '@/lib/api'
import { SEVERITY_LABEL } from '@/lib/checks'
import { now } from '@/lib/clock'
import { FEATURES, type FeatureKey } from '@/lib/features'
import {
  botOptions,
  botShare,
  classLabel,
  formatService,
  hourStart,
  ipOptions,
  levelChip,
  overThreshold,
  reasonLabel,
} from '@/lib/logs'
import { accountResources, formatGb, formatLoad, formatMb, percent } from '@/lib/resources'
import { useSiteData } from '@/lib/site-data'
import type { Tone } from '@/lib/state'
import { formatHour, formatSpan, formatWhen } from '@/lib/time'

// Trafic d'un site d'après l'analyse de ses logs (#8) : Visiteurs (verdicts
// d'IP), Blocages (robots vus et règles) et, dans Santé, Ressources (charge
// horaire). Trois états : 404, pas encore disponible ; analyse `null`, en
// attente ; sinon les données. Tout texte venu des logs est interpolé, jamais
// rendu en HTML. Les actions des maquettes ne sont que des propositions.

type Screen = 'trafic' | 'blocages' | 'ressources'

const route = useRoute()
const { site, to, sites, detail } = useSiteData()

const screen = computed<Screen>(() => {
  const name = route.name
  return name === 'blocages' || name === 'ressources' ? name : 'trafic'
})

const HEADINGS: Record<Screen, { title: string; hint: string; notPaired: string }> = {
  trafic: {
    title: 'Visiteurs',
    hint: 'IP au score moyen ou élevé de la dernière analyse des logs',
    notPaired: 'Les adresses IP suspectes de la dernière analyse des logs s’affichent ici, avec leurs raisons.',
  },
  blocages: {
    title: 'Blocages',
    hint: 'Robots vus sur 24 h et règles de l’analyse des logs',
    notPaired: 'Les robots vus sur 24 h et les règles de l’analyse s’affichent ici.',
  },
  ressources: {
    title: 'Ressources',
    hint: 'Charge du site heure par heure, d’après ses logs',
    notPaired: 'La charge du site heure par heure s’affiche ici.',
  },
}
const heading = computed(() => HEADINGS[screen.value])

const feature = computed<FeatureKey>(() => route.meta.feature ?? 'visiteurs')
const featureLink = computed<RouteLocationRaw | undefined>(() => {
  const target = FEATURES[feature.value].link
  return target ? to(target.name) : undefined
})

/** Mémoire, charge et disque relevés par l'agent PHP, s'il est configuré pour. */
const account = computed(() => accountResources(detail.value?.agent?.facts))

const logs = computed(() => sites.logs[site.value]?.data)
const analysis = computed(() => logs.value?.analysis ?? null)
const ips = computed(() => sites.ips[site.value]?.data)

/** Ressource qui commande l'écran : les verdicts pour Visiteurs, l'analyse sinon. */
const source = computed(() =>
  screen.value === 'trafic'
    ? {
        ready: ips.value !== undefined,
        error: sites.errors[`ips:${site.value}`],
        pending: ips.value?.generated_at === null,
      }
    : {
        ready: logs.value !== undefined,
        error: sites.errors[`logs:${site.value}`],
        pending: logs.value?.analysis === null,
      },
)

/** 404 : site sans source de logs, ou veilleur antérieur à ces routes. */
const unavailable = computed(() => source.value.error?.kind === 'not_found')

const pendingText = computed(() =>
  screen.value === 'trafic'
    ? 'Aucune analyse de moins de 48 h : le veilleur n’en a pas encore écrit, ou les logs du site n’arrivent plus.'
    : 'La source de logs du site est déclarée, mais le veilleur n’a encore écrit aucune analyse. Elle suit l’arrivée des premiers logs.'
)

// « Afficher plus » des verdicts : un échec reste affiché, sans relance.
const busy = ref(false)
const moreError = ref<ApiError | null>(null)
const notice = computed(() => sites.notices[`ips:${site.value}`])

async function showMore(): Promise<void> {
  busy.value = true
  moreError.value = await sites.moreIps(site.value)
  if (moreError.value?.kind === 'cursor_expired') moreError.value = null
  busy.value = false
}

function ruleChip(rule: Rule): { tone: Tone; label: string } {
  if (!rule.exceeded) return { tone: 'ok', label: 'Sous le seuil' }
  return { tone: rule.severity === 'critical' ? 'danger' : 'warn', label: 'Dépassée' }
}

function ruleMeta(rule: Rule): string {
  const scope = rule.scope === 'ip' ? 'par IP' : 'sur le site'
  const ips = rule.distinct_ips === 1 ? '1 IP' : `${rule.distinct_ips} IP`
  return `${SEVERITY_LABEL[rule.severity]} · ${scope} · ${rule.count} requêtes en ${formatSpan(rule.window_secs)} (seuil ${rule.min_count}) · ${ips}`
}

const load = computed(() => analysis.value?.load ?? [])
const busiest = computed(() => Math.max(1, ...load.value.map((h) => h.requests)))
</script>

<template>
  <ScreenTitle
    :title="heading.title"
    :hint="heading.hint"
  />
  <NotYet
    v-if="unavailable"
    :feature="feature"
    :link="featureLink"
  />
  <DataGate
    v-else
    :ready="source.ready"
    :error="source.error"
    :not-paired="heading.notPaired"
  >
    <StateScreen
      v-if="source.pending"
      state="first_read"
      title="Analyse en attente"
      :text="pendingText"
      data-pending
    />

    <!-- Visiteurs : verdicts d'IP, page par page. -->
    <template v-else-if="screen === 'trafic' && ips">
      <p
        class="text-sm text-text-2"
        data-summary
      >
        Analyse <template v-if="ips.generated_at !== null">
          {{ formatWhen(ips.generated_at, now) }}
        </template><template v-if="analysis">
          · {{ analysis.scored }} IP notées, {{ analysis.unscored }} sans score fiable
        </template>
      </p>
      <p
        v-if="notice"
        role="status"
        class="rounded-control bg-info-bg px-3 py-2 text-sm text-text"
        data-list-notice
      >
        {{ notice }}
      </p>
      <ul
        v-if="ips.items.length"
        class="flex flex-col gap-2"
      >
        <li
          v-for="verdict in ips.items"
          :key="verdict.ip"
          class="flex flex-col gap-1 rounded-card border border-line bg-surface px-3.5 py-3"
          data-verdict
        >
          <div class="flex flex-wrap items-center gap-2">
            <span class="min-w-0 flex-1 break-all font-mono text-sm">{{ verdict.ip }}</span>
            <StatusChip v-bind="levelChip(verdict.level)" />
          </div>
          <p class="text-sm text-text-2">
            Score {{ verdict.score }} sur 100 · {{ classLabel(verdict.class) }}
          </p>
          <p
            v-if="verdict.reasons.length"
            class="text-sm text-text-3"
          >
            {{ verdict.reasons.map(reasonLabel).join(' · ') }}
          </p>
          <Proposal
            :site="site"
            :options="ipOptions(verdict)"
          />
        </li>
      </ul>
      <p
        v-else
        class="text-sm text-text-3"
      >
        Aucune IP au score moyen ou élevé dans la dernière analyse.
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
        v-if="ips.next_cursor"
        type="button"
        class="flex min-h-tap items-center justify-center rounded-control border border-control text-text"
        :disabled="busy"
        data-more
        @click="showMore"
      >
        Afficher plus
      </button>
    </template>

    <!-- Blocages : règles de l'analyse et robots vus sur 24 h. -->
    <template v-else-if="screen === 'blocages' && analysis">
      <p class="text-sm text-text-2">
        Analyse {{ formatWhen(analysis.generated_at, now) }}
      </p>
      <section
        aria-labelledby="regles"
        class="flex flex-col gap-1"
      >
        <h2
          id="regles"
          class="text-xs uppercase tracking-wider text-text-3"
        >
          Règles de l’analyse
        </h2>
        <ul
          v-if="analysis.rules.length"
          class="divide-y divide-line rounded-card border border-line bg-surface text-sm"
        >
          <li
            v-for="rule in analysis.rules"
            :key="rule.rule"
            class="flex flex-col gap-1 px-3.5 py-2.5"
            data-rule
          >
            <div class="flex flex-wrap items-center gap-2">
              <span class="min-w-0 flex-1 break-words font-mono">{{ rule.rule }}</span>
              <StatusChip v-bind="ruleChip(rule)" />
            </div>
            <p class="text-xs text-text-3">
              {{ ruleMeta(rule) }}
            </p>
          </li>
        </ul>
        <p
          v-else
          class="text-sm text-text-3"
        >
          Aucune règle d’analyse pour ce site.
        </p>
      </section>

      <section
        aria-labelledby="robots"
        class="flex flex-col gap-1"
      >
        <h2
          id="robots"
          class="text-xs uppercase tracking-wider text-text-3"
        >
          Robots vus sur 24 h
        </h2>
        <ul
          v-if="analysis.bots.length"
          class="flex flex-col gap-2"
        >
          <li
            v-for="bot in analysis.bots"
            :key="bot.name"
            class="flex flex-col gap-1 rounded-card border border-line bg-surface px-3.5 py-3 text-sm"
            data-bot
          >
            <div class="flex flex-wrap items-center gap-2">
              <span class="min-w-0 flex-1 break-words font-semibold">{{ bot.name }}</span>
              <StatusChip
                tone="neutral"
                :label="classLabel(bot.class)"
              />
            </div>
            <p class="text-text-2">
              {{ bot.publisher }} · {{ bot.requests }} requêtes · {{ bot.honours_robots ? 'respecte robots.txt' : 'ignore robots.txt' }}
            </p>
            <p
              v-if="bot.purpose"
              class="text-text-3"
            >
              {{ bot.purpose }}
            </p>
            <p
              v-if="bot.protected"
              class="text-text-3"
              data-protected
            >
              Protégé : jamais visé par une règle robots.txt ou user-agent.
            </p>
            <Proposal
              v-else
              :site="site"
              :options="botOptions(bot)"
            />
          </li>
        </ul>
        <p
          v-else
          class="text-sm text-text-3"
        >
          Aucun robot du catalogue vu sur 24 h.
        </p>
      </section>
    </template>

    <!-- Ressources : charge horaire du site. -->
    <template v-else-if="screen === 'ressources' && analysis">
      <p class="text-sm text-text-2">
        Analyse {{ formatWhen(analysis.generated_at, now) }} · seuil de {{ formatService(analysis.load_threshold_us) }} de
        service par heure
      </p>
      <ul
        v-if="load.length"
        class="divide-y divide-line rounded-card border border-line bg-surface text-sm"
      >
        <li
          v-for="hour in load"
          :key="hour.hour"
          class="flex flex-col gap-1 px-3.5 py-2"
          data-hour
        >
          <div class="flex flex-wrap items-center gap-2">
            <span class="w-24 flex-none font-mono">{{ formatHour(hourStart(hour), now) }}</span>
            <span
              class="h-2 rounded-pill bg-info"
              :style="{ width: `${Math.max(2, Math.round((hour.requests / busiest) * 60))}%` }"
              aria-hidden="true"
            />
            <StatusChip
              v-if="overThreshold(hour, analysis.load_threshold_us)"
              tone="warn"
              label="Au-delà du seuil"
            />
          </div>
          <p class="text-xs text-text-3">
            {{ hour.requests }} requêtes · {{ hour.refused }} refusées · {{ botShare(hour) }} % de robots ·
            {{ hour.timed > 0 ? `${formatService(hour.service_us)} de service` : 'durées absentes des logs' }}
          </p>
        </li>
      </ul>
      <p
        v-else
        class="text-sm text-text-3"
      >
        Aucune requête sur 24 h.
      </p>
    </template>
  </DataGate>
  <NotYet
    v-if="screen === 'blocages'"
    feature="htaccess"
    compact
  />
  <section
    v-if="screen === 'ressources' && account"
    aria-labelledby="compte-title"
    class="flex flex-col gap-2 rounded-card border border-line bg-surface p-3"
    data-account
  >
    <h2
      id="compte-title"
      class="text-md font-semibold"
    >
      Ressources du compte
    </h2>
    <p class="text-xs text-text-3">
      Dernier rapport de l’agent {{ detail?.agent?.last_report_at ? formatWhen(detail.agent.last_report_at, now) : '' }}
    </p>
    <dl class="grid grid-cols-1 gap-2 text-sm">
      <div
        v-if="account.ram"
        data-resource="ram"
      >
        <dt class="text-xs uppercase tracking-wider text-text-3">
          Mémoire
        </dt>
        <dd>
          {{ formatMb(account.ram.used) }}
          <template v-if="account.ram.limit">
            sur {{ formatMb(account.ram.limit) }} ({{ percent(account.ram.used, account.ram.limit) }} %)
          </template>
          <template v-else>
            utilisés, limite non lue par l’agent
          </template>
        </dd>
      </div>
      <div
        v-if="account.load"
        data-resource="load"
      >
        <dt class="text-xs uppercase tracking-wider text-text-3">
          Charge de la machine
        </dt>
        <dd>{{ account.load.map(formatLoad).join(' · ') }} <span class="text-text-3">(1, 5 et 15 minutes, partagée avec les autres comptes)</span></dd>
      </div>
      <div
        v-if="account.disk"
        data-resource="disk"
      >
        <dt class="text-xs uppercase tracking-wider text-text-3">
          Disque
        </dt>
        <dd>{{ formatGb(account.disk.used) }} sur {{ formatGb(account.disk.total) }} ({{ percent(account.disk.used, account.disk.total) }} %)</dd>
      </div>
    </dl>
  </section>
  <NotYet
    v-else-if="screen === 'ressources'"
    feature="compte"
    compact
  />
</template>
