import { computed } from 'vue'
import { useSiteLinks } from '@/lib/links'
import { useSites } from '@/stores/sites'

/** Données lues du site de la route courante. */
export function useSiteData() {
  const { site, to } = useSiteLinks()
  const sites = useSites()
  const detail = computed(() => sites.details[site.value]?.data)
  const error = computed(() => sites.errors[`site:${site.value}`])
  const history = computed(() => sites.history[site.value]?.data)
  const missing = 'Le veilleur n’a pas ce site dans sa configuration.'
  return { site, to, sites, detail, error, history, missing }
}
