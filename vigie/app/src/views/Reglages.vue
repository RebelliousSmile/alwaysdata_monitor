<script setup lang="ts">
import AppIcon from '@/components/AppIcon.vue'
import NotPaired from '@/components/NotPaired.vue'
import NotYet from '@/components/NotYet.vue'
</script>

<template>
  <h1 class="sr-only">
    Réglages
  </h1>
  <NotPaired text="Le destinataire des alertes et les appareils appairés s’affichent ici." />
  <RouterLink
    :to="{ name: 'emails' }"
    class="flex min-h-tap items-center gap-3 rounded-card border border-line bg-surface px-3.5 py-3 text-text"
  >
    <span class="flex-1">Modèles d’e-mail</span>
    <span class="text-text-3"><AppIcon
      name="next"
      :size="18"
    /></span>
  </RouterLink>
  <NotYet
    feature="theme"
    compact
  />
</template>
