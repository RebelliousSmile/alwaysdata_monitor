<script setup lang="ts">
import AppIcon from '@/components/AppIcon.vue'
import { useSiteLinks } from '@/lib/links'
import { SITE_NAV, badgeOf, type NavBadges } from '@/lib/nav'
import type { NavKey } from '@/router'

// Colonne de gauche au-delà de 900 px : onglets du site s'il y en a un,
// puis Mes sites et Réglages.
withDefaults(
  defineProps<{ inSite?: boolean; active?: NavKey; badges?: NavBadges; global?: 'sites' | 'reglages' }>(),
  { inSite: false, active: undefined, badges: () => ({}), global: undefined },
)
const { to } = useSiteLinks()

const item = 'relative flex min-h-tap items-center gap-3 rounded-control px-3 text-md'
const idle = 'text-text-2'
const current = 'bg-surface-3 font-semibold text-text'
</script>

<template>
  <nav
    aria-label="Navigation principale"
    class="sticky top-0 hidden h-screen w-56 flex-none flex-col gap-1 border-r border-line bg-header p-3 pt-[calc(0.75rem_+_env(safe-area-inset-top))] wide:flex"
  >
    <div class="mb-3 flex min-h-tap items-center gap-2 px-2">
      <span class="text-primary"><AppIcon name="shield" /></span>
      <span class="text-lg font-semibold">Vigie</span>
    </div>
    <template v-if="inSite">
      <RouterLink
        v-for="tab in SITE_NAV"
        :key="tab.key"
        :to="to(tab.name)"
        :aria-current="tab.key === active ? 'page' : undefined"
        :class="[item, tab.key === active ? current : idle]"
      >
        <AppIcon :name="tab.icon" />
        <span class="flex-1">{{ tab.label }}</span>
        <span
          v-if="badgeOf(badges, tab.key) !== undefined"
          class="h-5 min-w-[20px] rounded-pill bg-danger px-1.5 text-center text-xs font-semibold leading-5 text-bg"
          data-badge
        >{{ badgeOf(badges, tab.key) }}</span>
      </RouterLink>
      <hr class="my-2 border-line">
    </template>
    <RouterLink
      :to="{ name: 'sites' }"
      :aria-current="global === 'sites' ? 'page' : undefined"
      :class="[item, global === 'sites' ? current : idle]"
    >
      <AppIcon name="sites" />
      Mes sites
    </RouterLink>
    <RouterLink
      :to="{ name: 'reglages' }"
      :aria-current="global === 'reglages' ? 'page' : undefined"
      :class="[item, global === 'reglages' ? current : idle]"
    >
      <AppIcon name="settings" />
      Réglages
    </RouterLink>
  </nav>
</template>
