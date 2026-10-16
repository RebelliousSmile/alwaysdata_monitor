import { ref } from 'vue'

// Heure courante en secondes Unix, partagée par les écrans : les « lu il y
// a » avancent sans relecture. Démarrée et arrêtée par la coquille.

export const now = ref(Math.floor(Date.now() / 1000))

let timer: ReturnType<typeof setInterval> | undefined

export function startClock(): void {
  stopClock()
  now.value = Math.floor(Date.now() / 1000)
  timer = setInterval(() => {
    now.value = Math.floor(Date.now() / 1000)
  }, 30_000)
}

export function stopClock(): void {
  if (timer !== undefined) clearInterval(timer)
  timer = undefined
}
