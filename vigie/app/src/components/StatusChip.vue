<script setup lang="ts">
import { computed } from 'vue'
import { TONES, type Tone } from '@/lib/state'

// Puce d'état : symbole et libellé, jamais la couleur seule.
const props = defineProps<{ tone: Tone; label: string }>()
const meta = computed(() => TONES[props.tone])
</script>

<template>
  <span
    class="inline-flex items-center gap-1 rounded-pill px-2 py-0.5 text-xs font-semibold"
    :class="meta.classes"
    :data-tone="tone"
  >
    <span aria-hidden="true">{{ meta.symbol }}</span>
    <span>{{ label }}</span>
  </span>
</template>
