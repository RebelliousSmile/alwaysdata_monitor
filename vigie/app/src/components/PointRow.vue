<script setup lang="ts">
import type { RouteLocationRaw } from 'vue-router'
import AppIcon from '@/components/AppIcon.vue'
import StateSymbol from '@/components/StateSymbol.vue'
import type { State } from '@/lib/state'

// Point ouvert d'À traiter : constat, fait daté, écran où le voir.
defineProps<{
  to: RouteLocationRaw
  state: State
  title: string
  fact: string
  where?: string
  /** Point choisi, affiché dans le détail en vue large. */
  selected?: boolean
}>()
</script>

<template>
  <RouterLink
    :to="to"
    :aria-current="selected ? 'true' : undefined"
    class="flex min-h-tap items-start gap-3 px-3.5 py-3 text-text"
    :class="selected ? 'bg-surface-2' : ''"
  >
    <StateSymbol :state="state" />
    <span class="min-w-0 flex-1">
      <span class="block font-semibold">{{ title }}</span>
      <span class="block text-sm text-text-2">{{ fact }}</span>
      <span
        v-if="where"
        class="block text-xs text-text-3"
      >{{ where }}</span>
    </span>
    <span class="self-center text-text-3"><AppIcon
      name="next"
      :size="18"
    /></span>
  </RouterLink>
</template>
