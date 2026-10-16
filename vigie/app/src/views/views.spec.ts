import { clearMocks, mockIPC } from '@tauri-apps/api/mocks'
import { flushPromises, type VueWrapper } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Router } from 'vue-router'
import { now } from '@/lib/clock'
import { mountAt } from '@/test/mount'
import { CODE, MIN, NOW, PAIR_LINK, TOKEN, mockVeilleur } from '@/test/veilleur'

// Écrans alimentés par le faux veilleur (`@/test/veilleur`), heure figée au
// vendredi 16 octobre 2026, 10:00 à Paris.

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] })
  vi.setSystemTime(NOW * 1000)
  localStorage.clear()
  sessionStorage.clear()
})

afterEach(() => {
  clearMocks()
  vi.useRealTimers()
})

/** Les vues sont chargées à la demande : la navigation prend un vrai délai. */
async function arrivedAt(router: Router, name: string): Promise<void> {
  await vi.waitFor(() => expect(router.currentRoute.value.name).toBe(name))
  await settle()
}

/** Lectures en chaîne : session, puis données de l'écran. */
async function settle(): Promise<void> {
  for (let i = 0; i < 3; i += 1) await flushPromises()
}

async function open(target: Parameters<typeof mountAt>[0]) {
  const mounted = await mountAt(target)
  await settle()
  return mounted
}

async function reload(wrapper: VueWrapper, label: string): Promise<void> {
  await wrapper.get(`button[aria-label="${label}"]`).trigger('click')
  await settle()
}

const buttonNamed = (wrapper: VueWrapper, text: string) => {
  const button = wrapper.findAll('button').find((b) => b.text() === text)
  if (!button) throw new Error(`bouton « ${text} » absent`)
  return button
}

describe('Mes sites', () => {
  it('liste les sites dans l’ordre du veilleur, avec constat et fraîcheur', async () => {
    mockVeilleur()
    const { wrapper } = await open('/')
    const rows = wrapper.findAll('main li a')
    expect(rows.map((r) => r.find('.font-mono').text())).toEqual(['site-a.example.org', 'site-b.example.org'])
    expect(rows[0]?.text()).toContain('Fichier du cœur modifié')
    expect(rows[0]?.text()).toContain('lu il y a 2 min')
    expect(rows[1]?.text()).toContain('lu il y a 1 min')
    expect(wrapper.get('header').text()).toContain('vendredi 16 octobre · lu à l’instant')
  })

  it('au premier lancement, invite à appairer sans rien lire', async () => {
    const veilleur = mockVeilleur(false)
    const { wrapper } = await open('/')
    expect(wrapper.text()).toContain('Les sites surveillés s’affichent ici')
    expect(wrapper.find('a[href="/appairage"]').exists()).toBe(true)
    expect(veilleur.calls).toEqual(['status'])
  })
})

describe('badges de la barre', () => {
  it('correspondent aux incidents ouverts renvoyés par l’API', async () => {
    const veilleur = mockVeilleur()
    const { wrapper } = await open('/s/site-a')
    const expected = String(veilleur.data.overview.sites[0]?.open_count)
    const badges = wrapper.findAll('[data-badge]').map((b) => b.text())
    // À traiter et Santé, dans la colonne et dans la barre du bas.
    expect(badges).toEqual([expected, expected, expected, expected])
  })

  it('aucun badge sur un site sans incident', async () => {
    mockVeilleur()
    const { wrapper } = await open('/s/site-b')
    expect(wrapper.findAll('[data-badge]')).toHaveLength(0)
  })
})

describe('À traiter', () => {
  it('points du plus grave au moins grave, le reste et les e-mails envoyés', async () => {
    mockVeilleur()
    const { wrapper } = await open('/s/site-a')
    const points = wrapper.findAll('[data-point]').map((p) => p.text())
    expect(points).toHaveLength(3)
    expect(points[0]).toMatch(/Critique.*Fichier du cœur modifié.*ouvert à 09:00.*Santé › Contrôles/s)
    expect(points[1]).toMatch(/Avertissement.*Content-Security-Policy.*Santé › Disponibilité/s)
    expect(points[2]).toContain('Information')
    expect(wrapper.findAll('[data-fine]').map((f) => f.text())).toEqual([
      expect.stringContaining('Contenu de la page'),
      expect.stringContaining('Installeur exposé'),
      expect.stringContaining('Fichiers exposés'),
      expect.stringContaining('Silence de l’agent'),
    ])
    const mails = wrapper.findAll('[data-mail]').map((m) => m.text())
    expect(mails[0]).toMatch(/Relance.*n° 13.*à 09:30/s)
    expect(mails[mails.length - 1]).toMatch(/Ouverture.*n° 9.*le 14 oct\. à 10:01/s)
    expect(wrapper.get('header').text()).toContain('lu à l’instant')
  })
})

describe('Alerte', () => {
  it('Acquitter passe la puce à « Acquitté à HH:MM » et l’incident reste listé', async () => {
    vi.setSystemTime((NOW - 5 * MIN) * 1000)
    mockVeilleur()
    const { wrapper } = await open('/s/site-a/alerte/12')
    const detail = wrapper.get('[data-incident]')
    expect(detail.text()).toContain('En cours')
    expect(detail.findAll('[data-step]').map((s) => s.text())).toEqual([
      expect.stringMatching(/Ouvert.*à 09:00/s),
      expect.stringMatching(/E-mail d’ouverture.*à 09:01/s),
    ])
    expect(detail.text()).toContain('8.3.12')

    vi.setSystemTime((NOW + 2 * MIN) * 1000)
    await buttonNamed(wrapper, 'Acquitter').trigger('click')
    await settle()
    expect(wrapper.get('[data-incident]').text()).toContain('Acquitté à 10:02')
    expect(wrapper.findAll('button').some((b) => b.text() === 'Acquitter')).toBe(false)
    expect(wrapper.findAll('[data-point]')).toHaveLength(3)
    expect(wrapper.findAll('[data-point]')[0]?.text()).toContain('acquitté à 10:02')
  })

  it('un incident inconnu est dit introuvable', async () => {
    mockVeilleur()
    const { wrapper } = await open('/s/site-a/alerte/99')
    expect(wrapper.get('[data-detail]').text()).toContain('Introuvable')
  })
})

describe('Santé', () => {
  it('Disponibilité : contrôles externes, certificat et incidents fermés', async () => {
    mockVeilleur()
    const { wrapper } = await open('/s/site-a/sante')
    expect(wrapper.findAll('[data-check]')).toHaveLength(5)
    expect(wrapper.get('[data-certificate]').text()).toMatch(/Valide jusqu’au .*encore 25 jours/s)
    expect(wrapper.findAll('[data-closed]')).toHaveLength(1)
  })

  it('Contrôles : chaque contrôle avec son état et son heure', async () => {
    mockVeilleur()
    const { wrapper } = await open('/s/site-a/sante/controles')
    const checks = wrapper.findAll('[data-check]').map((c) => c.text())
    expect(checks).toHaveLength(7)
    expect(checks.find((c) => c.startsWith('Agent · core'))).toMatch(/Critique.*Passé à 09:40.*à chaque rapport/s)
    expect(checks.find((c) => c.startsWith('Silence de l’agent'))).toContain('silence toléré 2 h')
  })
})

describe('Paramètres et Réglages', () => {
  it('Paramètres cite les commandes de la CLI pour ce site', async () => {
    mockVeilleur()
    const { wrapper } = await open('/s/site-a/parametres')
    const commands = wrapper.findAll('[data-command] code').map((c) => c.text())
    expect(commands).toContain('vigie site rotate-key site-a --pubkey <clé>')
    expect(commands).toContain('vigie check site-a --once')
    expect(wrapper.get('[data-settings]').text()).toContain('https://site-a.example.org')
  })

  it('Réglages : destinataire, appareils et version de la console', async () => {
    mockVeilleur()
    const { wrapper } = await open('/reglages')
    expect(wrapper.get('[data-recipient]').text()).toBe('a…@example.org')
    expect(wrapper.get('[data-device]').text()).toMatch(/poste de test.*cet appareil.*Actif/s)
    expect(wrapper.get('[data-version]').text()).toBe('Console Vigie 0.1.0')
  })
})

describe('connexion au veilleur', () => {
  it('hors ligne, Relire garde les données et affiche le bandeau', async () => {
    const veilleur = mockVeilleur()
    const { wrapper } = await open('/')
    expect(wrapper.find('[data-offline]').exists()).toBe(false)
    vi.setSystemTime((NOW + 5 * MIN) * 1000)
    // Le tic de l'horloge partagée, toutes les 30 s dans l'application.
    now.value = NOW + 5 * MIN
    veilleur.offline = true
    await reload(wrapper, 'Tout relire maintenant')
    expect(wrapper.get('[data-offline]').text()).toBe(
      'Hors ligne : le veilleur ne répond pas. Dernières données lues à 10:00.',
    )
    expect(wrapper.findAll('main li a')).toHaveLength(2)
    expect(wrapper.get('header').text()).toContain('lu il y a 5 min')

    veilleur.offline = false
    await reload(wrapper, 'Tout relire maintenant')
    expect(wrapper.find('[data-offline]').exists()).toBe(false)
  })

  it('un appareil révoqué revient à Appairage au premier rechargement', async () => {
    const veilleur = mockVeilleur()
    const { wrapper, router } = await open('/s/site-a')
    veilleur.revoked = true
    await reload(wrapper, 'Relire maintenant')
    await arrivedAt(router, 'appairage')
    expect(wrapper.get('[data-notice]').text()).toMatch(/révoqué/)
  })
})

describe('Appairage', () => {
  async function submit(wrapper: VueWrapper, text: string): Promise<void> {
    await wrapper.get('#pair-link').setValue(text)
    await wrapper.get('form').trigger('submit')
    await settle()
  }

  it('refuse une adresse en http hors boucle locale sans appeler le veilleur', async () => {
    const veilleur = mockVeilleur(false)
    const { wrapper, router } = await open('/appairage')
    await submit(wrapper, `vigie://pair?u=http://192.0.2.10&c=${CODE}`)
    expect(wrapper.get('[data-failure]').text()).toBe('Adresse du veilleur refusée : https exigé.')
    expect(veilleur.calls).not.toContain('pair')
    expect(router.currentRoute.value.name).toBe('appairage')
  })

  it('un lien valide mène à Mes sites, sans jeton dans le stockage du webview', async () => {
    const veilleur = mockVeilleur(false)
    const { wrapper, router } = await open('/appairage')
    expect(wrapper.find('[data-scan]').exists()).toBe(false)
    await submit(wrapper, PAIR_LINK)
    expect(veilleur.calls).toContain('pair')
    await arrivedAt(router, 'sites')
    expect(wrapper.findAll('main li a')).toHaveLength(2)

    const stored = [localStorage, sessionStorage].flatMap((storage) =>
      Array.from({ length: storage.length }, (_, i) => {
        const key = storage.key(i) ?? ''
        return `${key}=${storage.getItem(key) ?? ''}`
      }),
    )
    for (const entry of stored) {
      expect(entry).not.toContain(TOKEN)
      expect(entry).not.toContain(CODE)
    }
    expect(wrapper.html()).not.toContain(TOKEN)
  })

  it('un code refusé par le veilleur est expliqué', async () => {
    mockVeilleur(false)
    const { wrapper } = await open('/appairage')
    // Le faux veilleur accepte tout code : refus de la commande Rust `pair`.
    mockIPC((cmd) => {
      if (cmd === 'pair') throw { kind: 'unauthorized', message: 'code refusé' }
      return null
    })
    await submit(wrapper, PAIR_LINK)
    expect(wrapper.get('[data-failure]').text()).toMatch(/Code refusé : expiré/)
  })
})

describe('Retirer cet appareil', () => {
  it('veilleur injoignable : retour à Appairage, la notice cite vigie device revoke', async () => {
    const veilleur = mockVeilleur()
    const { wrapper, router } = await open('/reglages')
    veilleur.offline = true
    await buttonNamed(wrapper, 'Retirer cet appareil').trigger('click')
    await buttonNamed(wrapper, 'Confirmer le retrait').trigger('click')
    await arrivedAt(router, 'appairage')
    expect(wrapper.get('[data-notice]').text()).toContain('Sur le VPS : vigie device revoke 3')
  })

  it('veilleur joignable : l’appareil est révoqué', async () => {
    mockVeilleur()
    const { wrapper, router } = await open('/reglages')
    await buttonNamed(wrapper, 'Retirer cet appareil').trigger('click')
    await buttonNamed(wrapper, 'Confirmer le retrait').trigger('click')
    await arrivedAt(router, 'appairage')
    expect(wrapper.get('[data-notice]').text()).toMatch(/révoqué son jeton/)
  })
})

describe('aucune valeur d’exemple des maquettes', () => {
  // Valeurs propres aux maquettes de aidd_docs/design/vigie-design.
  const SAMPLES = [
    '[client-',
    '[site-perso]',
    'PrestaShop 8',
    'erreurs fatales',
    'getId() on null',
    'OrderController',
    'mercredi 14 octobre',
    '21:02',
    '19:40',
    'dans 83 jours',
    '05/01/2027',
    'vigie_ed25519',
  ]

  it.each([
    '/',
    '/s/site-a',
    '/s/site-a/alerte/12',
    '/s/site-a/sante',
    '/s/site-a/sante/controles',
    '/s/site-a/parametres',
    '/reglages',
  ])('%s', async (path) => {
    mockVeilleur()
    const { wrapper } = await open(path)
    const text = wrapper.text()
    for (const sample of SAMPLES) expect(text).not.toContain(sample)
  })
})
