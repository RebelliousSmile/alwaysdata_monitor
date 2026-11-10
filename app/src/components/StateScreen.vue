<script setup lang="ts">
import StateSymbol from '@/components/StateSymbol.vue'
import type { State } from '@/lib/state'

// Écran d'état de la maquette Etats (aveugle, première lecture, vide,
// non appairé…). Les actions passent par le slot.
withDefaults(defineProps<{ state?: State; title: string; text?: string }>(), {
  state: 'first_read',
  text: undefined,
})
</script>

<template>
  <section
    class="flex flex-col items-center gap-2 rounded-card border border-line bg-surface px-3.5 py-6 text-center"
    data-state-screen
  >
    <StateSymbol :state="state" />
    <h2 class="text-md font-semibold">
      {{ title }}
    </h2>
    <p
      v-if="text"
      class="text-sm text-text-3"
    >
      {{ text }}
    </p>
    <div
      v-if="$slots.default"
      class="mt-2 flex w-full flex-col gap-2"
    >
      <slot />
    </div>
  </section>
</template>
