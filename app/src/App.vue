<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter, type RouteLocationRaw } from 'vue-router'
import AppHeader from '@/components/AppHeader.vue'
import BottomNav from '@/components/BottomNav.vue'
import SegmentedNav from '@/components/SegmentedNav.vue'
import SideNav from '@/components/SideNav.vue'
import { siteBadges } from '@/lib/checks'
import { now, startClock, stopClock } from '@/lib/clock'
import { useSiteLinks } from '@/lib/links'
import type { NavBadges } from '@/lib/nav'
import { formatDay, formatWhen, readAgo } from '@/lib/time'
import { useConnection } from '@/stores/connection'
import { useSites } from '@/stores/sites'

// Coquille : colonne à gauche au-delà de 900 px, sinon en-tête collant,
// contenu et barre du bas d'un site. Elle lit ce que l'écran courant
// affiche, et le relit sur « Relire ».
const route = useRoute()
const router = useRouter()
const { site, settings, settingsBack } = useSiteLinks()
const connection = useConnection()
const sites = useSites()

const inSite = computed(() => route.meta.site === true)
const routeName = computed(() => (typeof route.name === 'string' ? route.name : ''))

/** Heure de la lecture des données de l'écran courant. */
const readAt = computed<number | undefined>(() => {
  if (routeName.value === 'sites') return sites.overview?.at
  if (inSite.value) return sites.details[site.value]?.at
  if (routeName.value === 'reglages') return sites.settings?.at
  if (routeName.value === 'sources-failles') return sites.vulnSources?.at
  return undefined
})

const subtitle = computed(() => {
  const fresh = readAt.value === undefined ? undefined : readAgo(readAt.value, now.value)
  if (routeName.value === 'sites') return [formatDay(now.value), fresh].filter(Boolean).join(' · ')
  return fresh
})

const header = computed(() => {
  if (inSite.value) {
    const inSettings = routeName.value === 'parametres'
    return {
      title: site.value,
      mono: true,
      back: inSettings ? settingsBack.value : ({ name: 'sites' } as RouteLocationRaw),
      backLabel: inSettings ? 'Retour à l’écran précédent' : 'Retour à mes sites',
      settings: inSettings ? undefined : settings.value,
      settingsLabel: 'Paramètres du site',
      reloadLabel: 'Relire maintenant',
    }
  }
  if (routeName.value === 'sites') {
    return {
      title: 'Vigie',
      brand: true,
      settings: { name: 'reglages' } as RouteLocationRaw,
      settingsLabel: 'Réglages globaux',
      settingsIcon: 'gear' as const,
      reloadLabel: 'Tout relire maintenant',
    }
  }
  return {
    title: route.meta.title ?? 'Vigie',
    back: { name: route.meta.back ?? 'sites' } as RouteLocationRaw,
    reloadLabel: ['reglages', 'sources-failles'].includes(routeName.value) ? 'Relire maintenant' : undefined,
  }
})

const global = computed(() => {
  if (routeName.value === 'sites') return 'sites'
  if (['reglages', 'sources-failles'].includes(routeName.value)) return 'reglages'
  return undefined
})

const badges = computed<NavBadges>(() => {
  const detail = sites.details[site.value]
  return detail ? siteBadges(detail.data) : {}
})

const banner = computed(() => {
  if (connection.paired !== true || connection.trouble === null) return undefined
  const cause =
    connection.trouble === 'offline'
      ? 'Hors ligne : le veilleur ne répond pas.'
      : 'Le veilleur répond en erreur.'
  const last = connection.lastOk === null ? '' : ` Dernières données lues ${formatWhen(connection.lastOk, now.value)}.`
  return cause + last
})

const reloads = ref(0)

const DETAIL_SCREENS = new Set(['a-traiter', 'alerte', 'sante'])
/** Écrans alimentés par l'analyse des logs (Trafic, Ressources). */
const LOG_SCREENS = new Set(['trafic', 'blocages', 'ressources'])

/** Lit les données de l'écran courant ; un échec garde les précédentes. */
async function load(): Promise<void> {
  if (connection.paired !== true) return
  const name = routeName.value
  if (name === 'sites') {
    await sites.loadOverview()
    return
  }
  if (name === 'reglages') {
    await sites.loadSettings()
    return
  }
  if (name === 'sources-failles') {
    await sites.loadVulnSources()
    return
  }
  if (!inSite.value || !site.value) return
  const jobs: Promise<boolean>[] = [sites.loadSite(site.value)]
  if (DETAIL_SCREENS.has(name)) jobs.push(sites.loadHistory(site.value))
  if (LOG_SCREENS.has(name)) jobs.push(sites.loadLogs(site.value))
  if (name === 'trafic') jobs.push(sites.loadIps(site.value))
  if (name === 'erreurs') jobs.push(sites.loadErrors(site.value))
  if (name === 'failles') jobs.push(sites.loadVulns(site.value), sites.loadComponents(site.value))
  if (name === 'alerte') {
    const id = Number(route.params.id)
    if (Number.isSafeInteger(id) && id > 0) jobs.push(sites.loadIncident(id), sites.loadMails(id))
  }
  if (name === 'parametres') jobs.push(sites.loadSettings())
  await Promise.all(jobs)
}

watch([routeName, site, () => route.params.id, () => connection.paired, reloads], () => void load())

// Appareil révoqué ou retiré : on oublie ses données et on revient à Appairage.
watch(
  () => connection.paired,
  (paired, before) => {
    if (paired === false && before === true) {
      sites.clear()
      void router.push({ name: 'appairage' })
    }
  },
)

function reload(): void {
  reloads.value += 1
}

onMounted(() => {
  startClock()
  void connection.init()
})
onBeforeUnmount(stopClock)
</script>

<template>
  <div class="flex min-h-screen bg-bg pl-[env(safe-area-inset-left)] pr-[env(safe-area-inset-right)] text-text">
    <SideNav
      :in-site="inSite"
      :active="route.meta.nav"
      :badges="badges"
      :global="global"
    />
    <div class="flex min-w-0 flex-1 flex-col">
      <AppHeader
        v-bind="header"
        :subtitle="subtitle"
        @reload="reload"
      />
      <p
        v-if="banner"
        role="status"
        class="border-b border-line bg-warn-bg px-gutter py-2 text-sm text-text"
        data-offline
      >
        {{ banner }}
      </p>
      <main class="flex w-full flex-1 flex-col gap-3 p-gutter pb-8 wide:mx-auto wide:max-w-5xl">
        <SegmentedNav
          v-if="route.meta.segments"
          :group="route.meta.segments"
          :active="routeName"
        />
        <RouterView />
      </main>
      <BottomNav
        v-if="inSite"
        :active="route.meta.nav"
        :badges="badges"
      />
    </div>
  </div>
</template>
