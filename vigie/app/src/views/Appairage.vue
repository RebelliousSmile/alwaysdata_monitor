<script setup lang="ts">
import ScreenTitle from '@/components/ScreenTitle.vue'
</script>

<template>
  <ScreenTitle title="Appairer cet appareil" />
  <section class="flex flex-col gap-2 rounded-card border border-line bg-surface p-4">
    <p>Sur le VPS, créez un code d’appairage valable 10 minutes :</p>
    <pre class="overflow-x-auto rounded-control bg-code p-3 font-mono text-sm">vigie device pair --name téléphone</pre>
    <p class="text-sm text-text-2">
      La commande affiche un QR code et un lien. Le scan du QR code et la saisie du lien
      ne sont pas encore branchés dans cette version de la console.
    </p>
  </section>
</template>
