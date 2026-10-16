<script setup lang="ts">
import { computed } from 'vue'
import DataGate from '@/components/DataGate.vue'
import ScreenTitle from '@/components/ScreenTitle.vue'
import { checkLabel } from '@/lib/checks'
import { useSiteData } from '@/lib/site-data'
import { formatSpan } from '@/lib/time'

// Paramètres du site, en lecture : chaque changement se fait sur le VPS, et
// l'écran cite la commande.
const { site, sites, detail, error, missing } = useSiteData()

const config = computed(() => sites.settings?.data.sites.find((s) => s.id === site.value))

const KINDS: Record<string, string> = { generic: 'Générique', wordpress: 'WordPress', prestashop: 'PrestaShop' }

const rows = computed(() => {
  const d = detail.value
  if (!d) return []
  return [
    ['Adresse', d.url],
    ['Type', KINDS[d.kind] ?? d.kind],
    ['Passage des contrôles', `toutes les ${formatSpan(d.interval)}`],
    ['Agent', d.agent ? `déclaré, silence toléré ${formatSpan(d.agent_silence)}` : 'aucun agent déclaré'],
  ]
})

const checks = computed(() => Object.entries(config.value?.checks ?? {}))

const commands = computed(() => {
  const id = site.value
  const hasAgent = detail.value?.agent !== null && detail.value?.agent !== undefined
  const list: [string, string][] = hasAgent
    ? [
        ['Remplacer la clé de l’agent', `vigie site rotate-key ${id} --pubkey <clé>`],
        ['Accepter les fichiers modifiés volontairement', `vigie site accept ${id}`],
        ['Retirer l’agent', `vigie site remove ${id}`],
      ]
    : [['Déclarer l’agent du site', `vigie site add ${id} --pubkey <clé>`]]
  return [
    ['Changer l’adresse, le type ou les intervalles', 'config.toml sur le VPS'],
    ...list,
    ['Lancer les contrôles sans rien enregistrer', `vigie check ${id} --once`],
  ]
})
</script>

<template>
  <ScreenTitle
    title="Paramètres du site"
    hint="En lecture : les changements se font en CLI sur le VPS"
  />
  <DataGate
    :ready="detail !== undefined"
    :error="error"
    :missing="missing"
    not-paired="L’adresse, le type de site, l’agent et les contrôles actifs s’affichent ici."
  >
    <dl
      class="divide-y divide-line rounded-card border border-line bg-surface text-sm"
      data-settings
    >
      <div
        v-for="[label, value] in rows"
        :key="label"
        class="flex flex-wrap gap-x-3 px-3.5 py-2.5"
      >
        <dt class="w-44 flex-none text-text-2">
          {{ label }}
        </dt>
        <dd class="min-w-0 flex-1 break-words">
          {{ value }}
        </dd>
      </div>
    </dl>

    <section
      v-if="checks.length"
      aria-labelledby="actifs"
      class="flex flex-col gap-1"
    >
      <h2
        id="actifs"
        class="text-xs uppercase tracking-wider text-text-3"
      >
        Contrôles actifs
      </h2>
      <ul class="divide-y divide-line rounded-card border border-line bg-surface text-sm">
        <li
          v-for="[name, interval] in checks"
          :key="name"
          class="flex gap-2 px-3.5 py-2"
        >
          <span class="flex-1">{{ checkLabel(name) }}</span>
          <span class="text-text-3">toutes les {{ formatSpan(interval) }}</span>
        </li>
      </ul>
    </section>

    <section
      aria-labelledby="cli"
      class="flex flex-col gap-1"
    >
      <h2
        id="cli"
        class="text-xs uppercase tracking-wider text-text-3"
      >
        Sur le VPS
      </h2>
      <ul class="flex flex-col gap-2 rounded-card border border-line bg-surface p-3.5 text-sm">
        <li
          v-for="[label, command] in commands"
          :key="label"
          class="flex flex-col gap-1"
          data-command
        >
          <span class="text-text-2">{{ label }}</span>
          <code class="overflow-x-auto rounded-control bg-code px-2 py-1 font-mono">{{ command }}</code>
        </li>
      </ul>
    </section>
  </DataGate>
</template>
