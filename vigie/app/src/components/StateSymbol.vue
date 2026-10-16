<script setup lang="ts">
import { computed } from 'vue'
import { STATES, type State } from '@/lib/state'

// Symbole d'état de la maquette Systeme. Le libellé est toujours dans le DOM :
// visible avec `labelled`, sinon réservé aux lecteurs d'écran.
const props = defineProps<{ state: State; labelled?: boolean }>()
const meta = computed(() => STATES[props.state])
</script>

<template>
  <span
    class="inline-flex items-center gap-2"
    :data-state="state"
  >
    <span
      class="flex h-7 w-7 flex-none items-center justify-center rounded-sym text-md font-bold"
      :class="meta.tone"
      aria-hidden="true"
    >{{ meta.symbol }}</span>
    <span :class="labelled ? 'text-sm text-text-2' : 'sr-only'">{{ meta.label }}</span>
  </span>
</template>
