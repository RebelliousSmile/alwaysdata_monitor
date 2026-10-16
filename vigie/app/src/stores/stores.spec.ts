import { clearMocks } from '@tauri-apps/api/mocks'
import { createPinia, setActivePinia } from 'pinia'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useConnection } from '@/stores/connection'
import { useSites } from '@/stores/sites'
import { MIN, NOW, mockVeilleur } from '@/test/veilleur'

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] })
  vi.setSystemTime(NOW * 1000)
  setActivePinia(createPinia())
})

afterEach(() => {
  clearMocks()
  vi.useRealTimers()
})

describe('useConnection', () => {
  it('lit la session enregistrée au démarrage', async () => {
    mockVeilleur(true)
    const connection = useConnection()
    expect(connection.paired).toBeNull()
    await connection.init()
    expect(connection.paired).toBe(true)
    expect(connection.device?.name).toBe('poste de test')
  })

  it('sans session, l’appareil n’est pas appairé', async () => {
    mockVeilleur(false)
    const connection = useConnection()
    await connection.init()
    expect(connection.paired).toBe(false)
  })

  it('retrait, veilleur joignable : notice de révocation', async () => {
    mockVeilleur(true)
    const connection = useConnection()
    await connection.init()
    await connection.unpair()
    expect(connection.paired).toBe(false)
    expect(connection.notice).toMatch(/révoqué son jeton/)
  })

  it('retrait, veilleur injoignable : la notice cite la commande à lancer', async () => {
    const veilleur = mockVeilleur(true)
    veilleur.offline = true
    const connection = useConnection()
    await connection.init()
    await connection.unpair()
    expect(connection.paired).toBe(false)
    expect(connection.notice).toMatch(/vigie device revoke 3$/)
  })
})

describe('useSites', () => {
  it('date chaque lecture', async () => {
    mockVeilleur(true)
    const sites = useSites()
    expect(await sites.loadOverview()).toBe(true)
    expect(sites.overview?.at).toBe(NOW)
    expect(sites.overview?.data.sites.map((s) => s.id)).toEqual(['site-a', 'site-b'])
    expect(useConnection().lastOk).toBe(NOW)
  })

  it('hors ligne : garde les données et leur heure, signale la panne', async () => {
    const veilleur = mockVeilleur(true)
    const sites = useSites()
    const connection = useConnection()
    await connection.init()
    await sites.loadOverview()
    vi.setSystemTime((NOW + 5 * MIN) * 1000)
    veilleur.offline = true
    expect(await sites.loadOverview()).toBe(false)
    expect(sites.overview?.at).toBe(NOW)
    expect(sites.overview?.data.sites).toHaveLength(2)
    expect(sites.errors.overview?.kind).toBe('offline')
    expect(connection.trouble).toBe('offline')
    expect(connection.lastOk).toBe(NOW)

    veilleur.offline = false
    await sites.loadOverview()
    expect(connection.trouble).toBeNull()
    expect(sites.errors.overview).toBeUndefined()
    expect(sites.overview?.at).toBe(NOW + 5 * MIN)
  })

  it('jeton révoqué : l’appareil est oublié avec une notice', async () => {
    const veilleur = mockVeilleur(true)
    const sites = useSites()
    const connection = useConnection()
    await connection.init()
    veilleur.revoked = true
    await sites.loadSite('site-a')
    expect(connection.paired).toBe(false)
    expect(connection.device).toBeNull()
    expect(connection.notice).toMatch(/révoqué/)
  })

  it('acquitter met à jour l’incident et le détail du site', async () => {
    mockVeilleur(true)
    const sites = useSites()
    await sites.loadSite('site-a')
    expect(await sites.ack(12)).toBeNull()
    expect(sites.incidents[12]?.data).toMatchObject({ state: 'acked', acked_at: NOW })
    const listed = sites.details['site-a']?.data.open_incidents.find((i) => i.id === 12)
    expect(listed).toMatchObject({ state: 'acked', acked_at: NOW })
    expect(sites.details['site-a']?.data.open_incidents).toHaveLength(3)
  })

  it('acquitter un incident fermé : conflit, puis relecture de son état', async () => {
    const veilleur = mockVeilleur(true)
    const sites = useSites()
    expect((await sites.ack(9))?.kind).toBe('conflict')
    expect(veilleur.calls).toEqual(['ack', 'incident'])
    expect(sites.incidents[9]?.data.state).toBe('closed')
  })

  it('clear oublie tout', async () => {
    mockVeilleur(true)
    const sites = useSites()
    await sites.loadOverview()
    await sites.loadSettings()
    sites.clear()
    expect(sites.overview).toBeNull()
    expect(sites.settings).toBeNull()
  })
})
