<script setup lang="ts">
import NotPaired from '@/components/NotPaired.vue'
import ScreenTitle from '@/components/ScreenTitle.vue'
</script>

<template>
  <ScreenTitle
    title="Mes sites"
    hint="Les plus urgents d’abord"
  />
  <NotPaired text="Les sites surveillés s’affichent ici, avec l’heure de leur dernière lecture." />
  <RouterLink
    :to="{ name: 'ajouter' }"
    class="flex min-h-[48px] items-center justify-center rounded-card border border-dashed border-control text-text"
  >
    Ajouter un site
  </RouterLink>
</template>
