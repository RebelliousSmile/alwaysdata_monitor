import { defineStore } from 'pinia'
import { ref } from 'vue'
import {
  api,
  type ApiError,
  type Incident,
  type LogIps,
  type Mails,
  type Overview,
  type Settings,
  type SiteDetail,
  type SiteComponents,
  type SiteIncidents,
  type SiteLogs,
  type SiteVulns,
  type SnoozeDuration,
  type VulnSources,
} from '@/lib/api'
import { asApiError, useConnection } from '@/stores/connection'

// Dernières réponses du veilleur, chacune avec l'heure de sa lecture. Un
// échec garde la réponse précédente : l'écran l'affiche avec son heure.

export interface Dated<T> {
  data: T
  /** Heure de la lecture, en secondes Unix. */
  at: number
}

const nowSeconds = (): number => Math.floor(Date.now() / 1000)

export const useSites = defineStore('sites', () => {
  const overview = ref<Dated<Overview> | null>(null)
  const details = ref<Record<string, Dated<SiteDetail>>>({})
  const history = ref<Record<string, Dated<SiteIncidents>>>({})
  const incidents = ref<Record<number, Dated<Incident>>>({})
  /** E-mails déjà partis, par incident. */
  const mails = ref<Record<number, Dated<Mails>>>({})
  /** Dernière analyse des logs, par site. */
  const logs = ref<Record<string, Dated<SiteLogs>>>({})
  /** Verdicts d'IP déjà lus, pages mises bout à bout, par site. */
  const ips = ref<Record<string, Dated<LogIps>>>({})
  /** Composants rapprochés (#21), pages mises bout à bout, par site. */
  const components = ref<Record<string, Dated<SiteComponents>>>({})
  /** Failles des composants (#21), pages mises bout à bout, par site. */
  const vulns = ref<Record<string, Dated<SiteVulns>>>({})
  /** Sources de failles du veilleur. */
  const vulnSources = ref<Dated<VulnSources> | null>(null)
  const settings = ref<Dated<Settings> | null>(null)
  /** Dernier échec par ressource (`site:<id>`, `incident:<id>`…), effacé au succès. */
  const errors = ref<Record<string, ApiError>>({})
  /**
   * Avis d'une liste paginée (`history:<id>`, `ips:<id>`) : reprise au début
   * après un curseur expiré. Effacé à la lecture suivante.
   */
  const notices = ref<Record<string, string>>({})

  async function read<T>(key: string, fetch: () => Promise<T>, keep: (value: Dated<T>) => void): Promise<boolean> {
    const connection = useConnection()
    try {
      const data = await fetch()
      keep({ data, at: nowSeconds() })
      delete errors.value[key]
      connection.ok()
      return true
    } catch (err) {
      const error = asApiError(err)
      errors.value[key] = error
      connection.fail(error)
      return false
    }
  }

  const loadOverview = () =>
    read('overview', api.overview, (value) => {
      overview.value = value
    })

  const loadSite = (id: string) =>
    read(`site:${id}`, () => api.site(id), (value) => {
      details.value[id] = value
    })

  const loadHistory = (id: string) => {
    delete notices.value[`history:${id}`]
    return read(`history:${id}`, () => api.incidents(id), (value) => {
      history.value[id] = value
    })
  }

  const loadLogs = (id: string) =>
    read(`logs:${id}`, () => api.logs(id), (value) => {
      logs.value[id] = value
    })

  const loadIps = (id: string) => {
    delete notices.value[`ips:${id}`]
    return read(`ips:${id}`, () => api.logIps(id), (value) => {
      ips.value[id] = value
    })
  }

  /**
   * Page suivante d'une liste, ajoutée au bout de celle déjà lue. Un échec
   * est rendu à l'écran, sans relance : un 429 dit quand réessayer. Un
   * curseur expiré fait relire la première page, avec un avis.
   */
  async function more<T extends { next_cursor: string | null }>(
    key: string,
    held: Dated<T> | undefined,
    fetch: (cursor: string) => Promise<T>,
    append: (held: T, page: T) => void,
    restart: () => Promise<boolean>,
  ): Promise<ApiError | null> {
    const cursor = held?.data.next_cursor
    if (!held || !cursor) return null
    const connection = useConnection()
    try {
      const page = await fetch(cursor)
      append(held.data, page)
      held.data.next_cursor = page.next_cursor
      connection.ok()
      return null
    } catch (err) {
      const error = asApiError(err)
      connection.fail(error)
      if (error.kind === 'cursor_expired') {
        await restart()
        notices.value[key] = 'La liste a changé depuis sa première page : elle reprend au début.'
      }
      return error
    }
  }

  const moreHistory = (id: string) =>
    more(
      `history:${id}`,
      history.value[id],
      (cursor) => api.incidents(id, cursor),
      (held, page) => {
        const seen = new Set(held.incidents.map((i) => i.id))
        held.incidents.push(...page.incidents.filter((i) => !seen.has(i.id)))
      },
      () => loadHistory(id),
    )

  const moreIps = (id: string) =>
    more(
      `ips:${id}`,
      ips.value[id],
      (cursor) => api.logIps(id, cursor),
      (held, page) => {
        const seen = new Set(held.items.map((v) => v.ip))
        held.items.push(...page.items.filter((v) => !seen.has(v.ip)))
      },
      () => loadIps(id),
    )

  const loadComponents = (id: string) => {
    delete notices.value[`components:${id}`]
    return read(`components:${id}`, () => api.components(id), (value) => {
      components.value[id] = value
    })
  }

  const loadVulns = (id: string) => {
    delete notices.value[`vulns:${id}`]
    return read(`vulns:${id}`, () => api.vulns(id), (value) => {
      vulns.value[id] = value
    })
  }

  /** Les pages se suivent sur les mêmes runs : un rang suffit à dédoublonner. */
  const moreComponents = (id: string) =>
    more(
      `components:${id}`,
      components.value[id],
      (cursor) => api.components(id, cursor),
      (held, page) => {
        held.items.push(...page.items)
      },
      () => loadComponents(id),
    )

  const moreVulns = (id: string) =>
    more(
      `vulns:${id}`,
      vulns.value[id],
      (cursor) => api.vulns(id, cursor),
      (held, page) => {
        const seen = new Set(held.items.map((v) => `${v.component} ${v.group}`))
        held.items.push(...page.items.filter((v) => !seen.has(`${v.component} ${v.group}`)))
      },
      () => loadVulns(id),
    )

  const loadVulnSources = () =>
    read('vuln-sources', api.vulnSources, (value) => {
      vulnSources.value = value
    })

  const loadIncident = (id: number) =>
    read(`incident:${id}`, () => api.incident(id), (value) => {
      incidents.value[id] = value
    })

  const loadMails = (id: number) =>
    read(`mails:${id}`, () => api.incidentMails(id), (value) => {
      mails.value[id] = value
    })

  const loadSettings = () =>
    read('settings', api.settings, (value) => {
      settings.value = value
    })

  /** Remplace un incident partout où il est affiché. */
  function keepIncident(incident: Incident, at: number): void {
    incidents.value[incident.id] = { data: incident, at }
    const detail = details.value[incident.site]
    if (detail) {
      detail.data.open_incidents = detail.data.open_incidents.map((i) => (i.id === incident.id ? incident : i))
    }
  }

  /** Acquitte un incident ; renvoie l'échec pour l'écran, `null` si réussi. */
  async function ack(id: number): Promise<ApiError | null> {
    const connection = useConnection()
    try {
      const incident = await api.ack(id)
      keepIncident(incident, nowSeconds())
      connection.ok()
      return null
    } catch (err) {
      const error = asApiError(err)
      connection.fail(error)
      // 409 : l'incident a été fermé entre-temps, on relit son état.
      if (error.kind === 'conflict') await loadIncident(id)
      return error
    }
  }

  /** Fait taire les relances d'un incident ouvert ; renvoie l'échec, `null` si réussi. */
  async function snooze(id: number, duration: SnoozeDuration): Promise<ApiError | null> {
    const connection = useConnection()
    try {
      const incident = await api.snooze(id, duration)
      keepIncident(incident, nowSeconds())
      connection.ok()
      return null
    } catch (err) {
      const error = asApiError(err)
      connection.fail(error)
      if (error.kind === 'conflict') await loadIncident(id)
      return error
    }
  }

  /** Oublie tout ce qui a été lu, au retrait ou à la révocation de l'appareil. */
  function clear(): void {
    overview.value = null
    details.value = {}
    history.value = {}
    incidents.value = {}
    mails.value = {}
    logs.value = {}
    ips.value = {}
    components.value = {}
    vulns.value = {}
    vulnSources.value = null
    settings.value = null
    errors.value = {}
    notices.value = {}
  }

  return {
    overview,
    details,
    history,
    incidents,
    mails,
    logs,
    ips,
    components,
    vulns,
    vulnSources,
    settings,
    errors,
    notices,
    loadOverview,
    loadSite,
    loadHistory,
    moreHistory,
    loadLogs,
    loadIps,
    moreIps,
    loadComponents,
    moreComponents,
    loadVulns,
    moreVulns,
    loadVulnSources,
    loadIncident,
    loadMails,
    loadSettings,
    ack,
    snooze,
    clear,
  }
})
