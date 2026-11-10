<script setup lang="ts">
import StateScreen from '@/components/StateScreen.vue'

// Rien n'est lu tant que la console n'est pas liée au veilleur.
defineProps<{ text: string }>()
</script>

<template>
  <StateScreen
    state="blind"
    title="Cet appareil n’est pas appairé"
    :text="text"
  >
    <RouterLink
      :to="{ name: 'appairage' }"
      class="flex min-h-[48px] items-center justify-center rounded-control bg-primary font-semibold text-primary-on"
    >
      Appairer cet appareil
    </RouterLink>
  </StateScreen>
</template>
