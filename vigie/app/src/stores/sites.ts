import { defineStore } from 'pinia'
import { ref } from 'vue'
import {
  api,
  type ApiError,
  type Incident,
  type Overview,
  type Settings,
  type SiteDetail,
  type SiteIncidents,
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
  const settings = ref<Dated<Settings> | null>(null)
  /** Dernier échec par ressource (`site:<id>`, `incident:<id>`…), effacé au succès. */
  const errors = ref<Record<string, ApiError>>({})

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

  const loadHistory = (id: string) =>
    read(`history:${id}`, () => api.incidents(id), (value) => {
      history.value[id] = value
    })

  const loadIncident = (id: number) =>
    read(`incident:${id}`, () => api.incident(id), (value) => {
      incidents.value[id] = value
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

  /** Oublie tout ce qui a été lu, au retrait ou à la révocation de l'appareil. */
  function clear(): void {
    overview.value = null
    details.value = {}
    history.value = {}
    incidents.value = {}
    settings.value = null
    errors.value = {}
  }

  return {
    overview,
    details,
    history,
    incidents,
    settings,
    errors,
    loadOverview,
    loadSite,
    loadHistory,
    loadIncident,
    loadSettings,
    ack,
    clear,
  }
})
