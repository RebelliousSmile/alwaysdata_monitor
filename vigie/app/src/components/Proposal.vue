<script setup lang="ts">
import { computed } from 'vue'
import { recommendCommand, type Option } from '@/lib/logs'

// Actions d'écriture des maquettes (« Bloquer cette IP », « Autoriser »…),
// rendues en propositions : aucun bouton, la console n'applique rien. Le
// texte de la commande à passer sur le VPS suffit.
const props = defineProps<{ site: string; options: Option[] }>()
const command = computed(() => recommendCommand(props.site))
</script>

<template>
  <details
    class="text-sm"
    data-proposal
  >
    <summary class="flex min-h-tap cursor-pointer items-center text-link">
      Décider…
    </summary>
    <div class="flex flex-col gap-2 pt-1">
      <ul class="flex flex-col gap-1.5">
        <li
          v-for="option in options"
          :key="option.label"
          class="rounded-control border border-line px-3 py-2"
          data-option
        >
          <span class="font-semibold">{{ option.label }}</span>
          <span class="text-text-2"> · {{ option.effect }}</span>
        </li>
      </ul>
      <p class="text-text-2">
        Proposition seulement : la console n’écrit rien sur le site. Sur le VPS, la commande vérifie et calcule les
        changements à appliquer.
      </p>
      <code
        class="overflow-x-auto rounded-control bg-code px-2 py-1 font-mono"
        data-command
      >{{ command }}</code>
    </div>
  </details>
</template>
