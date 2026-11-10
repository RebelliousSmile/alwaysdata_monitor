import { computed } from 'vue'
import { useRoute, useRouter, type RouteLocationRaw } from 'vue-router'
import { pickContext } from '@/lib/context'
import { SITE_SCREENS } from '@/router'

/** Liens internes d'un site, qui transmettent toujours le contexte. */
export function useSiteLinks() {
  const route = useRoute()
  const router = useRouter()
  const site = computed(() => {
    const value = route.params.site
    return typeof value === 'string' ? value : ''
  })

  function to(name: string, params: Record<string, string> = {}): RouteLocationRaw {
    return { name, params: { site: site.value, ...params }, query: pickContext(route.query) }
  }

  /** Paramètres, avec l'écran courant comme écran de retour. */
  const settings = computed<RouteLocationRaw>(() => ({
    name: 'parametres',
    params: { site: site.value },
    query: { ...pickContext(route.query), depuis: route.fullPath },
  }))

  /**
   * Retour depuis Paramètres : l'écran d'origine s'il appartient au même
   * site, sinon « À traiter ». `depuis` n'est jamais suivi tel quel.
   */
  const settingsBack = computed<RouteLocationRaw>(() => {
    const from = route.query.depuis
    if (typeof from === 'string' && from.startsWith('/')) {
      const target = router.resolve(from)
      const name = typeof target.name === 'string' ? target.name : ''
      if (SITE_SCREENS.includes(name) && target.params.site === site.value) {
        return target.fullPath
      }
    }
    return to('a-traiter')
  })

  return { site, to, settings, settingsBack }
}
