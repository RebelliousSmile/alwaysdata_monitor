<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, type RouteLocationRaw } from 'vue-router'
import NotYet from '@/components/NotYet.vue'
import { FEATURES } from '@/lib/features'
import { useSiteLinks } from '@/lib/links'

// Écran d'une fonctionnalité sans source : Journal, Ajouter un site.
// Visiteurs, Blocages et Ressources passent par Trafic.
const route = useRoute()
const { to } = useSiteLinks()

const feature = computed(() => route.meta.feature ?? 'visiteurs')
const link = computed<RouteLocationRaw | undefined>(() => {
  const target = FEATURES[feature.value].link
  if (!target) return undefined
  return route.meta.site ? to(target.name) : { name: target.name }
})
</script>

<template>
  <h1 class="sr-only">
    {{ FEATURES[feature].title }}
  </h1>
  <NotYet
    :feature="feature"
    :link="link"
  />
</template>
