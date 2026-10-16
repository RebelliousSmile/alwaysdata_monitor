<script setup lang="ts">
import NotPaired from '@/components/NotPaired.vue'
import ScreenTitle from '@/components/ScreenTitle.vue'
</script>

<template>
  <ScreenTitle
    title="Disponibilité"
    hint="Contrôles externes, incidents des 30 jours, certificat"
  />
  <NotPaired text="Les contrôles externes du site, avec leur durée et leur heure, s’affichent ici." />
</template>
