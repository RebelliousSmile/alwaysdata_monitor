<script setup lang="ts">
import type { RouteLocationRaw } from 'vue-router'
import AppIcon from '@/components/AppIcon.vue'
import type { IconName } from '@/lib/icons'

// En-tête collant. « Relire » reste toujours à la même place, juste avant
// l'accès aux réglages ou aux paramètres. Sous Android, l'app s'affiche bord
// à bord : l'en-tête s'étend sous la barre d'état et décale son contenu.
defineProps<{
  title: string
  subtitle?: string
  /** Titre en mono : un hôte vient du serveur. */
  mono?: boolean
  back?: RouteLocationRaw
  backLabel?: string
  settings?: RouteLocationRaw
  settingsLabel?: string
  /** Engrenage pour les réglages globaux, curseurs pour ceux d'un site. */
  settingsIcon?: IconName
  reloadLabel?: string
  /** Logo de Vigie à la place du retour (Mes sites). */
  brand?: boolean
}>()

defineEmits<{ reload: [] }>()
</script>

<template>
  <header class="sticky top-0 z-20 flex items-center gap-1 border-b border-line bg-header p-2 pt-[calc(0.5rem_+_env(safe-area-inset-top))]">
    <RouterLink
      v-if="back"
      :to="back"
      :aria-label="backLabel ?? 'Retour'"
      class="flex h-tap w-tap flex-none items-center justify-center text-text-2"
    >
      <AppIcon name="back" />
    </RouterLink>
    <span
      v-else-if="brand"
      class="flex h-tap w-tap flex-none items-center justify-center text-primary"
    >
      <AppIcon name="shield" />
    </span>
    <div class="min-w-0 flex-1">
      <div
        class="truncate"
        :class="mono ? 'font-mono text-md' : 'text-lg font-semibold'"
      >
        {{ title }}
      </div>
      <div
        v-if="subtitle"
        class="text-xs text-text-3"
      >
        {{ subtitle }}
      </div>
    </div>
    <button
      v-if="reloadLabel"
      type="button"
      :aria-label="reloadLabel"
      class="flex h-tap w-tap flex-none items-center justify-center text-ok"
      @click="$emit('reload')"
    >
      <AppIcon name="reload" />
    </button>
    <RouterLink
      v-if="settings"
      :to="settings"
      :aria-label="settingsLabel ?? 'Paramètres'"
      class="flex h-tap w-tap flex-none items-center justify-center text-text-2"
    >
      <AppIcon :name="settingsIcon ?? 'settings'" />
    </RouterLink>
  </header>
</template>
