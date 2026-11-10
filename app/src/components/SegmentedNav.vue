<script setup lang="ts">
import { useSiteLinks } from '@/lib/links'
import { SEGMENTS } from '@/lib/nav'
import type { SegmentGroup } from '@/router'

// Sélecteur à trois segments de Trafic et de Santé. Chaque segment est un
// lien qui garde le contexte (jour, fenêtre, sources, filtre).
defineProps<{ group: SegmentGroup; active: string }>()
const { to } = useSiteLinks()
</script>

<template>
  <nav
    :aria-label="group === 'sante' ? 'Vues de la santé' : 'Vues du trafic'"
    class="grid grid-cols-3 rounded-control border border-line bg-surface p-[3px]"
  >
    <RouterLink
      v-for="segment in SEGMENTS[group]"
      :key="segment.name"
      :to="to(segment.name)"
      :aria-current="segment.name === active ? 'page' : undefined"
      class="flex min-h-tap items-center justify-center rounded-sym text-md"
      :class="segment.name === active ? 'bg-surface-3 font-semibold text-text' : 'text-text-2'"
    >
      {{ segment.label }}
    </RouterLink>
  </nav>
</template>
