<script setup lang="ts">
import { computed } from 'vue'
import DataGate from '@/components/DataGate.vue'
import ScreenTitle from '@/components/ScreenTitle.vue'
import SiteRow from '@/components/SiteRow.vue'
import StateScreen from '@/components/StateScreen.vue'
import type { OverviewSite } from '@/lib/api'
import { now } from '@/lib/clock'
import { readAgo } from '@/lib/time'
import { useSites } from '@/stores/sites'

// Mes sites : l'ordre est celui du veilleur (le plus urgent d'abord).
const sites = useSites()
const list = computed(() => sites.overview?.data.sites ?? [])

const host = (site: OverviewSite): string => {
  try {
    return new URL(site.url).host
  } catch {
    return site.id
  }
}

function todo(site: OverviewSite): string | undefined {
  if (site.worst) return site.worst.detail
  if (site.state === 'first_read') return 'Rien n’est encore lu sur ce site.'
  return undefined
}

const fresh = (site: OverviewSite): string =>
  site.last_read === null ? 'jamais lu' : readAgo(site.last_read, now.value)
</script>

<template>
  <ScreenTitle
    title="Mes sites"
    hint="Les plus urgents d’abord"
  />
  <DataGate
    :ready="sites.overview !== null"
    :error="sites.errors.overview"
    not-paired="Les sites surveillés s’affichent ici, avec l’heure de leur dernière lecture."
  >
    <ul
      v-if="list.length"
      class="flex flex-col gap-2"
    >
      <li
        v-for="site in list"
        :key="site.id"
      >
        <SiteRow
          :to="{ name: 'a-traiter', params: { site: site.id } }"
          :host="host(site)"
          :state="site.state"
          :todo="todo(site)"
          :fresh="fresh(site)"
        />
      </li>
    </ul>
    <StateScreen
      v-else
      state="first_read"
      title="Aucun site surveillé"
      text="Le veilleur n’a aucun site dans sa configuration."
    />
  </DataGate>
  <RouterLink
    :to="{ name: 'ajouter' }"
    class="flex min-h-[48px] items-center justify-center rounded-card border border-dashed border-control text-text"
  >
    Ajouter un site
  </RouterLink>
</template>
