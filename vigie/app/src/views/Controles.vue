<script setup lang="ts">
import NotPaired from '@/components/NotPaired.vue'
import NotYet from '@/components/NotYet.vue'
import ScreenTitle from '@/components/ScreenTitle.vue'
</script>

<template>
  <ScreenTitle
    title="Contrôles"
    hint="Contrôles externes et contrôles de l’agent"
  />
  <NotPaired text="Chaque contrôle s’affiche ici avec son dernier résultat et son heure." />
  <NotYet
    feature="file"
    compact
  />
</template>
