<script setup lang="ts">
import { computed } from 'vue'
import DataGate from '@/components/DataGate.vue'
import ScreenTitle from '@/components/ScreenTitle.vue'
import type { ErrorGroup } from '@/lib/api'
import { now } from '@/lib/clock'
import { useSiteData } from '@/lib/site-data'
import { formatWhen } from '@/lib/time'

// Erreurs du site (#52), en lecture seule : groupes de messages normalisés
// des 14 derniers jours, du plus fréquent au moins fréquent. Le message vient
// des logs d'erreurs du site : il est interpolé, jamais rendu en HTML. Une
// liste vide est un état à part de l'échec de lecture : le veilleur n'a
// reçu aucune erreur (le silence de l'agent a son propre constat).

const { site, sites } = useSiteData()

// 404 : site absent de la configuration, ou veilleur antérieur à cette route.
const missing = 'Le veilleur n’a pas ce site dans sa configuration, ou ne sert pas encore les erreurs.'

const errors = computed(() => sites.siteErrors[site.value]?.data)
const error = computed(() => sites.errors[`errors:${site.value}`])

const count = new Intl.NumberFormat('fr-FR')

function occurrences(group: ErrorGroup): string {
  return group.count === 1 ? '1 occurrence' : `${count.format(group.count)} occurrences`
}

function days(group: ErrorGroup, window: number): string {
  return `vu ${group.days_seen === 1 ? '1 jour' : `${group.days_seen} jours`} sur ${window}`
}
</script>

<template>
  <ScreenTitle
    title="Erreurs"
    hint="Erreurs du site regroupées par message, sur les derniers jours"
  />
  <DataGate
    :ready="errors !== undefined"
    :error="error"
    :missing="missing"
    not-paired="Les erreurs du site, regroupées par message avec leur nombre et leurs dates, s’affichent ici."
  >
    <template v-if="errors">
      <p
        v-if="!errors.groups.length"
        class="text-sm text-text-3"
        data-empty
      >
        Aucune erreur reçue sur les {{ errors.days }} derniers jours. Si l’agent se tait, le veilleur le signale à part, dans
        les points à traiter.
      </p>
      <template v-else>
        <p
          class="text-sm text-text-2"
          data-reminder
        >
          Lecture seule. Les messages sont normalisés : un nombre y est masqué par « # », et aucune adresse IP, aucun
          chemin ni aucune requête n’est conservé.
        </p>
        <ul class="flex flex-col gap-2">
          <li
            v-for="group in errors.groups"
            :key="group.message"
            class="flex flex-col gap-1 rounded-card border border-line bg-surface px-3.5 py-3"
            data-group
          >
            <p
              class="break-words font-mono text-sm font-semibold"
              data-message
            >
              {{ group.message }}
            </p>
            <p
              class="text-sm text-text"
              data-count
            >
              {{ occurrences(group) }} · {{ days(group, errors.days) }}
            </p>
            <p
              class="text-xs text-text-3"
              data-seen
            >
              Première vue {{ formatWhen(group.first_seen, now) }} · dernière {{ formatWhen(group.last_seen, now) }}
            </p>
          </li>
        </ul>
      </template>
    </template>
  </DataGate>
</template>
