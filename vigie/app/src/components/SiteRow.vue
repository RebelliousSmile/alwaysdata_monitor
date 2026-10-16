<script setup lang="ts">
import { computed } from 'vue'
import type { RouteLocationRaw } from 'vue-router'
import AppIcon from '@/components/AppIcon.vue'
import StateSymbol from '@/components/StateSymbol.vue'
import { STATES, type State } from '@/lib/state'

// Ligne de Mes sites : état, hôte, constat, heure de la dernière lecture.
const props = defineProps<{
  to: RouteLocationRaw
  host: string
  state: State
  /** Constat, absent quand tout va bien. */
  todo?: string
  /** « lu il y a 2 min » : une donnée porte toujours son heure. */
  fresh: string
}>()

const border = computed(() => STATES[props.state].border)
</script>

<template>
  <RouterLink
    :to="to"
    class="flex min-h-[72px] items-center gap-3 rounded-card border bg-surface px-3.5 py-3 text-text"
    :class="border"
  >
    <StateSymbol :state="state" />
    <span class="min-w-0 flex-1">
      <span class="block truncate font-mono text-md">{{ host }}</span>
      <span
        v-if="todo"
        class="block text-sm"
        :class="state === 'non_compliant' ? 'text-danger-text' : 'text-text'"
      >{{ todo }}</span>
      <span class="block text-xs text-text-3">{{ fresh }}</span>
    </span>
    <span class="text-text-3"><AppIcon
      name="next"
      :size="18"
    /></span>
  </RouterLink>
</template>
