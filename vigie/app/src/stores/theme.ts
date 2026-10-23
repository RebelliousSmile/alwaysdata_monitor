import { defineStore } from 'pinia'
import { ref } from 'vue'
import { applyTheme, readTheme, saveTheme, type Theme } from '@/lib/theme'

// Thème d'affichage de la console (sombre ou clair), mémorisé sur l'appareil.
export const useTheme = defineStore('theme', () => {
  const theme = ref<Theme>(readTheme())

  function set(next: Theme): void {
    theme.value = next
    applyTheme(next)
    saveTheme(next)
  }

  return { theme, set }
})
