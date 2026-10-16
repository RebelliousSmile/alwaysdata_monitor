<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import NotPaired from '@/components/NotPaired.vue'
import ScreenTitle from '@/components/ScreenTitle.vue'

// Liste des points ouverts et détail d'une alerte : côte à côte au-delà de
// 900 px, l'un ou l'autre sur mobile.
const route = useRoute()
const detailOpen = computed(() => route.name === 'alerte')
</script>

<template>
  <div
    class="flex flex-col gap-3 wide:grid wide:grid-cols-[minmax(0,2fr)_minmax(0,3fr)] wide:items-start wide:gap-4"
    data-list-detail
  >
    <section
      class="flex-col gap-3"
      :class="detailOpen ? 'hidden wide:flex' : 'flex'"
      data-list
    >
      <ScreenTitle
        title="À traiter"
        hint="Du plus grave au moins grave"
      />
      <NotPaired text="Les points ouverts du site, les alertes envoyées et ce qui va bien s’affichent ici." />
    </section>
    <section
      class="flex-col gap-3"
      :class="detailOpen ? 'flex' : 'hidden wide:flex'"
      data-detail
    >
      <RouterView />
    </section>
  </div>
</template>
