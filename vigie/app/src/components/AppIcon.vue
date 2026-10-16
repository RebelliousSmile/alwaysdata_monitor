<script setup lang="ts">
import { ICON_KNOBS, ICON_PATHS, type IconName } from '@/lib/icons'

withDefaults(defineProps<{ name: IconName; size?: number }>(), { size: 22 })
</script>

<template>
  <svg
    :width="size"
    :height="size"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    stroke-width="2"
    stroke-linecap="round"
    stroke-linejoin="round"
    aria-hidden="true"
  >
    <path
      v-for="d in ICON_PATHS[name]"
      :key="d"
      :d="d"
    />
    <circle
      v-for="[cx, cy] in ICON_KNOBS[name] ?? []"
      :key="`${cx}-${cy}`"
      :cx="cx"
      :cy="cy"
      r="2"
    />
  </svg>
</template>
