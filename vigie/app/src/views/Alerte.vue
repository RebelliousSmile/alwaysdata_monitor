<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import NotPaired from '@/components/NotPaired.vue'
import NotYet from '@/components/NotYet.vue'
import ScreenTitle from '@/components/ScreenTitle.vue'
import { useSiteLinks } from '@/lib/links'

const route = useRoute()
const { to } = useSiteLinks()
const id = computed(() => (typeof route.params.id === 'string' ? route.params.id : ''))
</script>

<template>
  <RouterLink
    :to="to('a-traiter')"
    class="flex min-h-tap items-center text-sm text-link wide:hidden"
  >
    Tous les points à traiter
  </RouterLink>
  <ScreenTitle :title="`Alerte n° ${id}`" />
  <NotPaired text="Le détail de l’incident, sa chronologie et l’action Acquitter s’affichent ici." />
  <NotYet
    feature="sourdine"
    compact
  />
</template>
