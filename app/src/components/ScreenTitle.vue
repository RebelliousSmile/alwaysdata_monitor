<script setup lang="ts">
// Titre d'écran (22 / 600) et sa ligne d'aide.
defineProps<{ title: string; hint?: string }>()
</script>

<template>
  <div>
    <h1 class="text-xl font-semibold">
      {{ title }}
    </h1>
    <p
      v-if="hint"
      class="text-sm text-text-3"
    >
      {{ hint }}
    </p>
  </div>
</template>
