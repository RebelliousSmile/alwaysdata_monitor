<script setup lang="ts">
import NotPaired from '@/components/NotPaired.vue'
import ScreenTitle from '@/components/ScreenTitle.vue'
</script>

<template>
  <ScreenTitle
    title="Paramètres du site"
    hint="En lecture : les changements se font en CLI sur le VPS"
  />
  <NotPaired text="L’adresse, le type de site, l’agent et les contrôles actifs s’affichent ici." />
</template>
