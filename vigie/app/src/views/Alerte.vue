<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import DataGate from '@/components/DataGate.vue'
import ScreenTitle from '@/components/ScreenTitle.vue'
import StatusChip from '@/components/StatusChip.vue'
import type { ApiError, Incident, Mail, SnoozeDuration } from '@/lib/api'
import { SEVERITY_LABEL, SEVERITY_TONE, checkLabel, factEntries } from '@/lib/checks'
import { now } from '@/lib/clock'
import { useSiteData } from '@/lib/site-data'
import type { Tone } from '@/lib/state'
import { formatWhen } from '@/lib/time'

// Détail d'un incident : état, chronologie, constat, faits de l'agent, et
// les deux écritures de la console, Acquitter et la sourdine des relances.
const route = useRoute()
const { to, sites, detail } = useSiteData()

const raw = computed(() => (typeof route.params.id === 'string' ? route.params.id : ''))
const id = computed(() => {
  const value = Number(raw.value)
  return Number.isSafeInteger(value) && value > 0 ? value : null
})

const incident = computed<Incident | undefined>(() => {
  if (id.value === null) return undefined
  return (
    sites.incidents[id.value]?.data ?? detail.value?.open_incidents.find((i) => i.id === id.value)
  )
})

const error = computed<ApiError | undefined>(() =>
  id.value === null
    ? { kind: 'not_found', message: '' }
    : sites.errors[`incident:${id.value}`],
)

const chip = computed<{ tone: Tone; label: string } | undefined>(() => {
  const i = incident.value
  if (!i) return undefined
  if (i.state === 'closed' && i.closed_at !== null) return { tone: 'ok', label: `Fermé ${formatWhen(i.closed_at, now.value)}` }
  if (i.state === 'acked' && i.acked_at !== null) return { tone: 'info', label: `Acquitté ${formatWhen(i.acked_at, now.value)}` }
  return { tone: SEVERITY_TONE[i.severity], label: 'En cours' }
})

/** Fin de la sourdine, tant qu'elle n'est pas passée. */
const snoozedUntil = computed(() => {
  const until = incident.value?.snoozed_until ?? null
  return until !== null && until > now.value ? until : null
})

const timeline = computed(() => {
  const i = incident.value
  if (!i) return []
  const steps: [label: string, at: number | null][] = [
    ['Ouvert', i.opened_at],
    ['E-mail d’ouverture', i.open_notified_at],
    ['Dernière relance', i.last_reminder_at],
    ['Acquitté', i.acked_at],
    ['Relances en sourdine jusqu’à', snoozedUntil.value],
    ['Fermé', i.closed_at],
    ['E-mail de clôture', i.close_notified_at],
  ]
  return steps
    .filter((step): step is [string, number] => step[1] !== null)
    .sort((a, b) => a[1] - b[1])
})

const MAIL_KIND: Record<Mail['kind'], string> = {
  open: 'Ouverture',
  reminder: 'Relance',
  close: 'Clôture',
}

/** E-mails réellement partis pour cet incident, du plus ancien au plus récent. */
const mails = computed<Mail[]>(() =>
  id.value === null ? [] : [...(sites.mails[id.value]?.data.mails ?? [])].sort((a, b) => a.sent_at - b.sent_at),
)

/** Faits du dernier rapport de l'agent, pour un contrôle de l'agent. */
const facts = computed(() => {
  const i = incident.value
  const agent = detail.value?.agent
  if (!i || !agent || agent.last_report_at === null) return undefined
  if (!i.check.startsWith('agent:') && i.check !== 'heartbeat') return undefined
  return { at: agent.last_report_at, entries: factEntries(agent.facts) }
})

const acking = ref(false)
const ackError = ref<string | null>(null)

watch(id, () => {
  ackError.value = null
})

const snoozing = ref(false)

const SNOOZES: { duration: SnoozeDuration; label: string }[] = [
  { duration: '24h', label: 'Sourdine 24 h' },
  { duration: '7d', label: 'Sourdine 7 jours' },
]

async function snooze(duration: SnoozeDuration): Promise<void> {
  if (id.value === null) return
  snoozing.value = true
  ackError.value = null
  const failure = await sites.snooze(id.value, duration)
  snoozing.value = false
  if (failure) ackError.value = SNOOZE_ERRORS[failure.kind] ?? `Sourdine impossible : ${failure.message}`
}

const SNOOZE_ERRORS: Partial<Record<ApiError['kind'], string>> = {
  conflict: 'Cet incident est déjà fermé : il n’y a plus de relance à faire taire.',
  offline: 'Le veilleur ne répond pas : la sourdine n’est pas posée.',
  not_found: 'Le veilleur ne connaît plus cet incident.',
}

const ACK_ERRORS: Partial<Record<ApiError['kind'], string>> = {
  conflict: 'Cet incident est déjà fermé : il n’y a plus rien à acquitter.',
  offline: 'Le veilleur ne répond pas : l’incident n’est pas acquitté.',
  not_found: 'Le veilleur ne connaît plus cet incident.',
}

async function ack(): Promise<void> {
  if (id.value === null) return
  acking.value = true
  ackError.value = null
  const failure = await sites.ack(id.value)
  acking.value = false
  if (failure) ackError.value = ACK_ERRORS[failure.kind] ?? `Acquittement impossible : ${failure.message}`
}
</script>

<template>
  <RouterLink
    :to="to('a-traiter')"
    class="flex min-h-tap items-center text-sm text-link wide:hidden"
  >
    Tous les points à traiter
  </RouterLink>
  <ScreenTitle :title="`Alerte n° ${raw}`" />
  <DataGate
    :ready="incident !== undefined"
    :error="error"
    missing="Le veilleur ne connaît pas cet incident."
    not-paired="Le détail de l’incident, sa chronologie et l’action Acquitter s’affichent ici."
  >
    <article
      v-if="incident && chip"
      class="flex flex-col gap-3"
      data-incident
    >
      <section class="flex flex-col gap-2 rounded-card border border-line bg-surface p-4">
        <div class="flex flex-wrap items-center gap-2">
          <StatusChip
            :tone="chip.tone"
            :label="chip.label"
          />
          <span class="text-xs text-text-3">{{ SEVERITY_LABEL[incident.severity] }}</span>
        </div>
        <h2 class="text-lg font-semibold">
          {{ checkLabel(incident.check) }}
        </h2>
      </section>

      <section
        aria-labelledby="quand"
        class="flex flex-col gap-1"
      >
        <h2
          id="quand"
          class="text-xs uppercase tracking-wider text-text-3"
        >
          Quand
        </h2>
        <ol class="divide-y divide-line rounded-card border border-line bg-surface text-sm">
          <li
            v-for="[label, at] in timeline"
            :key="label"
            class="flex items-baseline gap-2 px-3.5 py-2"
            data-step
          >
            <span class="flex-1">{{ label }}</span>
            <span class="text-text-2">{{ formatWhen(at, now) }}</span>
          </li>
        </ol>
      </section>

      <section
        aria-labelledby="quoi"
        class="flex flex-col gap-1"
      >
        <h2
          id="quoi"
          class="text-xs uppercase tracking-wider text-text-3"
        >
          Quoi
        </h2>
        <p class="whitespace-pre-wrap break-words rounded-card border border-line bg-surface p-3.5 text-sm">
          {{ incident.detail }}
        </p>
      </section>

      <section
        v-if="facts"
        aria-labelledby="faits"
        class="flex flex-col gap-1"
      >
        <h2
          id="faits"
          class="text-xs uppercase tracking-wider text-text-3"
        >
          Relevé de l’agent, reçu {{ formatWhen(facts.at, now) }}
        </h2>
        <dl
          v-if="facts.entries.length"
          class="divide-y divide-line rounded-card border border-line bg-surface text-sm"
        >
          <div
            v-for="[key, value] in facts.entries"
            :key="key"
            class="flex flex-wrap gap-x-3 px-3.5 py-2"
          >
            <dt class="font-mono text-text-2">
              {{ key }}
            </dt>
            <dd class="min-w-0 flex-1 break-words font-mono">
              {{ value }}
            </dd>
          </div>
        </dl>
        <p
          v-else
          class="text-sm text-text-3"
        >
          Le dernier rapport ne contient aucun fait.
        </p>
      </section>

      <section
        v-if="mails.length"
        aria-labelledby="mails"
        class="flex flex-col gap-1"
      >
        <h2
          id="mails"
          class="text-xs uppercase tracking-wider text-text-3"
        >
          E-mails envoyés
        </h2>
        <details
          v-for="mail in mails"
          :key="mail.kind + mail.sent_at"
          class="rounded-card border border-line bg-surface text-sm"
          data-sent-mail
        >
          <summary class="flex min-h-tap cursor-pointer items-baseline gap-2 px-3.5 py-2">
            <span class="flex-1">{{ MAIL_KIND[mail.kind] }}</span>
            <span class="text-text-2">{{ formatWhen(mail.sent_at, now) }}</span>
          </summary>
          <div class="flex flex-col gap-2 border-t border-line px-3.5 py-3">
            <p class="break-words font-semibold">
              {{ mail.subject }}
            </p>
            <pre class="whitespace-pre-wrap break-words font-mono text-xs">{{ mail.body }}</pre>
          </div>
        </details>
        <p class="text-xs text-text-3">
          Texte recomposé à partir de l’état actuel de l’incident, tel que le veilleur l’enverrait aujourd’hui.
        </p>
      </section>

      <button
        v-if="incident.state === 'open'"
        type="button"
        class="flex min-h-[48px] items-center justify-center rounded-control bg-primary font-semibold text-primary-on disabled:opacity-60"
        :disabled="acking"
        @click="ack"
      >
        {{ acking ? 'Acquittement…' : 'Acquitter' }}
      </button>
      <p
        v-if="incident.state === 'open'"
        class="text-xs text-text-3"
      >
        Acquitter arrête les relances ; l’incident reste listé jusqu’à sa fermeture par le veilleur.
      </p>
      <div
        v-if="incident.state === 'open'"
        class="grid grid-cols-2 gap-2"
      >
        <button
          v-for="option in SNOOZES"
          :key="option.duration"
          type="button"
          :data-snooze="option.duration"
          class="flex min-h-[48px] items-center justify-center rounded-control border border-line font-semibold text-text-2 disabled:opacity-60"
          :disabled="snoozing"
          @click="snooze(option.duration)"
        >
          {{ option.label }}
        </button>
      </div>
      <p
        v-if="incident.state === 'open'"
        class="text-xs text-text-3"
      >
        La sourdine ne fait taire que les relances ; les e-mails d’ouverture et de clôture partent toujours.
      </p>
      <p
        v-if="ackError"
        role="alert"
        class="text-sm text-danger-text"
      >
        {{ ackError }}
      </p>
    </article>
  </DataGate>
</template>
