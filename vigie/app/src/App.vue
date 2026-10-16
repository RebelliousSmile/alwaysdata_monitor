<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, type RouteLocationRaw } from 'vue-router'
import AppHeader from '@/components/AppHeader.vue'
import BottomNav from '@/components/BottomNav.vue'
import SegmentedNav from '@/components/SegmentedNav.vue'
import SideNav from '@/components/SideNav.vue'
import { useSiteLinks } from '@/lib/links'

// Coquille : colonne à gauche au-delà de 900 px, sinon en-tête collant,
// contenu et barre du bas d'un site.
const route = useRoute()
const { site, settings, settingsBack } = useSiteLinks()

const inSite = computed(() => route.meta.site === true)
const routeName = computed(() => (typeof route.name === 'string' ? route.name : ''))

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
      reloadLabel: 'Tout relire maintenant',
    }
  }
  return {
    title: route.meta.title ?? 'Vigie',
    back: { name: route.meta.back ?? 'sites' } as RouteLocationRaw,
  }
})

const global = computed(() => {
  if (routeName.value === 'sites') return 'sites'
  if (routeName.value === 'reglages' || routeName.value === 'emails') return 'reglages'
  return undefined
})

// « Relire » rechargera la vue courante quand les stores existeront (phase 4).
function reload(): void {}
</script>

<template>
  <div class="flex min-h-screen bg-bg text-text">
    <SideNav
      :in-site="inSite"
      :active="route.meta.nav"
      :global="global"
    />
    <div class="flex min-w-0 flex-1 flex-col">
      <AppHeader
        v-bind="header"
        @reload="reload"
      />
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
      />
    </div>
  </div>
</template>
