<script setup lang="ts">
import { computed } from 'vue'
import NotPaired from '@/components/NotPaired.vue'
import StateScreen from '@/components/StateScreen.vue'
import type { ApiError } from '@/lib/api'
import type { State } from '@/lib/state'
import { useConnection } from '@/stores/connection'

// Garde d'un écran alimenté : le contenu s'il y a des données, même
// anciennes ; sinon l'état qui explique pourquoi il n'y en a pas.
const props = defineProps<{
  /** Une réponse du veilleur est disponible. */
  ready: boolean
  /** Dernier échec de lecture de cette ressource. */
  error?: ApiError
  /** Ce que l'écran affichera une fois l'appareil appairé. */
  notPaired: string
  /** Ce qui manque quand le veilleur répond 404. */
  missing?: string
}>()

const connection = useConnection()

const empty = computed<{ state: State; title: string; text: string }>(() => {
  switch (props.error?.kind) {
    case 'not_found':
      return { state: 'blind', title: 'Introuvable', text: props.missing ?? 'Le veilleur ne connaît pas cette ressource.' }
    case 'offline':
      return {
        state: 'blind',
        title: 'Hors ligne',
        text: 'Le veilleur ne répond pas et rien n’a encore été lu. « Relire » réessaie.',
      }
    case undefined:
      return { state: 'first_read', title: 'Lecture en cours', text: 'Lecture du veilleur…' }
    default:
      return { state: 'to_check', title: 'Lecture impossible', text: props.error?.message ?? '' }
  }
})
</script>

<template>
  <NotPaired
    v-if="connection.paired === false"
    :text="notPaired"
  />
  <slot v-else-if="ready" />
  <StateScreen
    v-else-if="connection.paired === true"
    :state="empty.state"
    :title="empty.title"
    :text="empty.text"
  />
</template>
