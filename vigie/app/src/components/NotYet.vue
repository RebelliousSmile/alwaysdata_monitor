<script setup lang="ts">
import { computed } from 'vue'
import type { RouteLocationRaw } from 'vue-router'
import { FEATURES, type FeatureKey } from '@/lib/features'

// Fonctionnalité prévue sans source de données : nommée, décrite, sans
// aucune donnée d'exemple. `compact` pour une ligne dans un écran alimenté.
const props = defineProps<{ feature: FeatureKey; link?: RouteLocationRaw; compact?: boolean }>()
const meta = computed(() => FEATURES[props.feature])
</script>

<template>
  <section
    :aria-labelledby="`notyet-${feature}`"
    class="flex flex-col gap-2 rounded-card border border-line bg-surface"
    :class="compact ? 'p-3' : 'p-4'"
    data-notyet
  >
    <div class="flex flex-wrap items-center gap-2">
      <h2
        :id="`notyet-${feature}`"
        class="font-semibold"
        :class="compact ? 'text-md' : 'text-lg'"
      >
        {{ meta.title }}
      </h2>
      <span class="inline-flex items-center gap-1 rounded-pill bg-surface-3 px-2 py-0.5 text-xs font-semibold text-text">
        <span aria-hidden="true">i</span>
        Pas encore disponible
      </span>
    </div>
    <p class="text-md text-text">
      {{ meta.shows }}
    </p>
    <div class="text-sm text-text-2">
      <span class="text-xs uppercase tracking-wider text-text-3">Ce qui manque</span>
      <p>{{ meta.missing }}</p>
    </div>
    <RouterLink
      v-if="link && meta.link"
      :to="link"
      class="mt-1 flex min-h-tap items-center justify-center rounded-control border border-control text-text"
    >
      {{ meta.link.label }}
    </RouterLink>
  </section>
</template>
