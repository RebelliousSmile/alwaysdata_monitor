<script setup lang="ts">
import AppIcon from '@/components/AppIcon.vue'
import { useSiteLinks } from '@/lib/links'
import { SITE_NAV, badgeOf, type NavBadges } from '@/lib/nav'
import type { NavKey } from '@/router'

// Barre du bas d'un site, sur mobile. Au-delà de 900 px, SideNav la remplace.
withDefaults(defineProps<{ active?: NavKey; badges?: NavBadges }>(), { active: undefined, badges: () => ({}) })
const { to } = useSiteLinks()
</script>

<template>
  <nav
    aria-label="Navigation du site"
    class="sticky bottom-0 z-20 grid grid-cols-4 border-t border-line bg-header px-1 pb-4 pt-1 wide:hidden"
  >
    <RouterLink
      v-for="item in SITE_NAV"
      :key="item.key"
      :to="to(item.name)"
      :aria-current="item.key === active ? 'page' : undefined"
      class="relative flex min-h-[56px] flex-col items-center justify-center gap-0.5 text-xs"
      :class="item.key === active ? 'font-semibold text-ok' : 'text-text-2'"
    >
      <AppIcon :name="item.icon" />
      {{ item.label }}
      <span
        v-if="badgeOf(badges, item.key) !== undefined"
        class="absolute left-[52%] top-0.5 h-5 min-w-[20px] rounded-pill bg-danger px-1.5 text-center text-xs font-semibold leading-5 text-bg"
        data-badge
      >{{ badgeOf(badges, item.key) }}</span>
    </RouterLink>
  </nav>
</template>
