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

  it('Sourdine 7 jours fait taire les relances : la date est posée, l’incident reste ouvert', async () => {
    vi.setSystemTime((NOW - 5 * MIN) * 1000)
    mockVeilleur()
    const { wrapper } = await open('/s/site-a/alerte/12')
    expect(wrapper.get('[data-incident]').text()).not.toContain('Relances en sourdine')

    await wrapper.get('[data-snooze="7d"]').trigger('click')
    await settle()
    const detail = wrapper.get('[data-incident]')
    expect(detail.text()).toContain('En cours')
    expect(detail.findAll('[data-step]').map((s) => s.text())).toContainEqual(
      expect.stringMatching(/Relances en sourdine jusqu’à/),
    )
    expect(wrapper.find('[data-snooze="24h"]').exists()).toBe(true)
  })

  it('E-mails envoyés : l’e-mail d’ouverture parti est relisible, sans écran de modèles', async () => {
    vi.setSystemTime((NOW - 5 * MIN) * 1000)
    mockVeilleur()
    const { wrapper } = await open('/s/site-a/alerte/12')
    const sent = wrapper.findAll('[data-sent-mail]')
    expect(sent).toHaveLength(1)
    expect(sent[0]!.text()).toContain('Ouverture')
    expect(sent[0]!.text()).toContain('[Vigie] open n° 12')
    expect(sent[0]!.text()).toContain('Corps fictif du message open.')
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

describe('Disponibilité, incidents clos par pages', () => {
  it('« Afficher plus » ajoute la page suivante, puis disparaît', async () => {
    const veilleur = mockVeilleur()
    const first = veilleur.data.history['site-a']
    first.next_cursor = 'hist-2'
    veilleur.data.moreHistory['hist-2'] = {
      ...first,
      incidents: [{ ...first.incidents[0]!, id: 8, detail: 'Constat plus ancien' }],
      next_cursor: null,
    }
    const { wrapper } = await open('/s/site-a/sante')
    expect(wrapper.findAll('[data-closed]')).toHaveLength(1)
    await wrapper.get('[data-more]').trigger('click')
    await settle()
    expect(wrapper.findAll('[data-closed]').map((c) => c.text())).toEqual([
      expect.stringContaining('Texte attendu absent'),
      expect.stringContaining('Constat plus ancien'),
    ])
    expect(wrapper.find('[data-more]').exists()).toBe(false)
  })
})

describe('Trafic', () => {
  it('Visiteurs : verdicts d’IP, « Afficher plus » et propositions sans écriture', async () => {
    const veilleur = mockVeilleur()
    const { wrapper } = await open('/s/site-a/trafic')
    expect(wrapper.find('h1').text()).toBe('Visiteurs')
    expect(wrapper.get('[data-summary]').text()).toMatch(/à 09:55.*31 IP notées, 2 sans score fiable/s)
    let verdicts = wrapper.findAll('[data-verdict]').map((v) => v.text())
    expect(verdicts).toHaveLength(2)
    expect(verdicts[0]).toMatch(/192\.0\.2\.10.*Élevé.*Score 85 sur 100.*Outil.*beaucoup de pages à facettes/s)
    expect(verdicts[1]).toContain('autre raison')

    await wrapper.get('[data-more]').trigger('click')
    await settle()
    verdicts = wrapper.findAll('[data-verdict]').map((v) => v.text())
    expect(verdicts).toHaveLength(3)
    expect(verdicts[2]).toContain('198.51.100.7')
    expect(wrapper.find('[data-more]').exists()).toBe(false)

    // IPv4 : bloquer ou autoriser ; IPv6 : l'abonnement (/64) en plus.
    const proposals = wrapper.findAll('[data-proposal]')
    expect(proposals[0]?.findAll('[data-option]').map((o) => o.find('span').text())).toEqual([
      'Bloquer cette IP',
      'Autoriser',
    ])
    expect(proposals[1]?.text()).toContain('Bloquer l’abonnement (/64)')
    for (const proposal of proposals) {
      expect(proposal.get('[data-command]').text()).toBe('vigie site recommend site-a')
      expect(proposal.findAll('button')).toHaveLength(0)
    }
    // Aucune commande d'écriture : seulement des lectures.
    expect(veilleur.calls.filter((c) => !['status', 'site', 'logs', 'log_ips'].includes(c))).toEqual([])
  })

  it('Visiteurs : un curseur expiré fait reprendre la liste au début, avec un avis', async () => {
    const veilleur = mockVeilleur()
    const { wrapper } = await open('/s/site-a/trafic')
    veilleur.expired = true
    await wrapper.get('[data-more]').trigger('click')
    await settle()
    expect(wrapper.findAll('[data-verdict]')).toHaveLength(2)
    expect(wrapper.get('[data-list-notice]').text()).toContain('reprend au début')
    expect(wrapper.find('[data-more-error]').exists()).toBe(false)
  })

  it('Visiteurs : 429 dit quand réessayer, sans relance automatique', async () => {
    const veilleur = mockVeilleur()
    const { wrapper } = await open('/s/site-a/trafic')
    veilleur.limited = true
    const before = veilleur.calls.length
    await wrapper.get('[data-more]').trigger('click')
    await settle()
    expect(wrapper.get('[data-more-error]').text()).toBe('trop de requêtes, réessayer dans 12 s')
    expect(veilleur.calls.length - before).toBe(1)
    expect(wrapper.findAll('[data-verdict]')).toHaveLength(2)
  })

  it('Blocages : règles et robots ; un robot protégé n’a pas de proposition', async () => {
    mockVeilleur()
    const { wrapper } = await open('/s/site-a/trafic/blocages')
    const rules = wrapper.findAll('[data-rule]').map((r) => r.text())
    expect(rules[0]).toMatch(/spike-404.*Dépassée.*sur le site · 140 requêtes en 5 min \(seuil 100\)/s)
    expect(rules[1]).toMatch(/login-burst.*Sous le seuil.*par IP/s)
    const bots = wrapper.findAll('[data-bot]')
    expect(bots[0]?.text()).toMatch(/GPTBot.*Robot IA.*OpenAI · 42 requêtes · respecte robots.txt/s)
    expect(bots[0]?.find('[data-proposal]').exists()).toBe(true)
    expect(bots[1]?.find('[data-protected]').exists()).toBe(true)
    expect(bots[1]?.find('[data-proposal]').exists()).toBe(false)
  })

  it('un nom de robot ou une métadonnée en HTML s’affichent en texte', async () => {
    const veilleur = mockVeilleur()
    const hostile = '<img src=x onerror=alert(1)>'
    const analysis = veilleur.data.logs['site-a']!.analysis!
    analysis.bots[0] = { ...analysis.bots[0]!, name: hostile, publisher: hostile, purpose: hostile, class: hostile }
    analysis.rules[0] = { ...analysis.rules[0]!, rule: hostile }
    veilleur.data.ips['site-a']!.items[0] = { ...veilleur.data.ips['site-a']!.items[0]!, ip: hostile, reasons: [hostile], class: hostile }
    for (const path of ['/s/site-a/trafic/blocages', '/s/site-a/trafic']) {
      const { wrapper } = await open(path)
      expect(wrapper.find('img').exists()).toBe(false)
      expect(wrapper.text()).toContain(hostile)
      expect(wrapper.html()).toContain('&lt;img src=x onerror=alert(1)&gt;')
      wrapper.unmount()
    }
  })

  it('Ressources : charge par heure et heures au-delà du seuil', async () => {
    mockVeilleur()
    const { wrapper } = await open('/s/site-a/sante/ressources')
    const hours = wrapper.findAll('[data-hour]').map((h) => h.text())
    expect(hours).toHaveLength(3)
    expect(hours[0]).toMatch(/08:00.*300 requêtes · 4 refusées · 10 % de robots · 120 s de service/s)
    expect(hours[1]).toMatch(/09:00.*Au-delà du seuil.*2\s000 s de service/s)
    expect(hours[0]).not.toContain('Au-delà du seuil')
    expect(hours[2]).toContain('durées absentes des logs')
    expect(wrapper.text()).toContain('Ressources du compte')
  })

  it('Ressources du compte : relevé de l’agent quand il y en a un, sinon pas encore disponible', async () => {
    const veilleur = mockVeilleur()
    const agent = veilleur.data.sites['site-a']?.agent
    if (!agent) throw new Error('agent de site-a attendu')
    agent.facts = {
      php: '8.3.12',
      ram_used_mb: 512,
      ram_limit_mb: 2048,
      load_1: 0.5,
      load_5: 1,
      load_15: 1.5,
      disk_used_gb: 12.5,
      disk_total_gb: 50,
    }
    const { wrapper } = await open('/s/site-a/sante/ressources')
    const account = wrapper.get('[data-account]').text()
    expect(account).toContain('Ressources du compte')
    expect(wrapper.get('[data-resource="ram"]').text()).toMatch(/512 Mo\s+sur 2 Go \(25 %\)/)
    expect(wrapper.get('[data-resource="load"]').text()).toContain('0,5 · 1 · 1,5')
    expect(wrapper.get('[data-resource="disk"]').text()).toMatch(/12,5 Go\s+sur 50 Go \(25 %\)/)
    expect(wrapper.find('[data-notyet]').exists()).toBe(false)
  })

  it.each(['/s/site-b/trafic', '/s/site-b/trafic/blocages', '/s/site-b/sante/ressources'])(
    'site sans source de logs (404) : %s pas encore disponible',
    async (path) => {
      mockVeilleur()
      const { wrapper } = await open(path)
      const notYet = wrapper.get('[data-notyet]')
      expect(notYet.text()).toContain('Pas encore disponible')
      expect(notYet.text()).toContain('[sites.logs]')
      expect(wrapper.find('[data-state-screen]').exists()).toBe(false)
    },
  )

  it('analyse pas encore écrite : « analyse en attente »', async () => {
    const veilleur = mockVeilleur()
    veilleur.data.logs['site-a'] = { analysis: null }
    veilleur.data.ips['site-a'] = { site: 'site-a', generated_at: null, items: [], next_cursor: null }
    for (const path of ['/s/site-a/trafic', '/s/site-a/trafic/blocages', '/s/site-a/sante/ressources']) {
      const { wrapper } = await open(path)
      expect(wrapper.get('[data-pending]').text()).toContain('Analyse en attente')
      expect(wrapper.find('[data-verdict], [data-rule], [data-hour]').exists()).toBe(false)
      wrapper.unmount()
    }
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
    const storage = wrapper.get('[data-token-storage]')
    expect(storage.text()).toContain('Trousseau du système')
    expect(storage.get('[data-tone]').attributes('data-tone')).toBe('ok')
  })

  it('Réglages : un jeton resté dans l’ancien fichier est signalé', async () => {
    const veilleur = mockVeilleur()
    veilleur.status.token_storage = 'file_legacy'
    const { wrapper } = await open('/reglages')
    const storage = wrapper.get('[data-token-storage]')
    expect(storage.text()).toContain('Ancien fichier')
    expect(storage.text()).toContain('Nouvel essai au prochain lancement')
    expect(storage.get('[data-tone]').attributes('data-tone')).toBe('warn')
    expect(wrapper.html()).not.toContain(TOKEN)
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

describe('Thème', () => {
  afterEach(() => {
    document.documentElement.removeAttribute('data-theme')
  })

  it('sombre par défaut, sans l’encart « pas encore disponible »', async () => {
    mockVeilleur()
    const { wrapper } = await open('/reglages')
    const choice = wrapper.get('[data-theme-choice]')
    expect(choice.findAll('input[type="radio"]').map((r) => (r.element as HTMLInputElement).checked)).toEqual([true, false])
    expect(wrapper.text()).not.toContain('Thème clair')
    expect(wrapper.find('[data-notyet]').exists() && wrapper.get('[data-notyet]').text().includes('Thème')).toBe(false)
  })

  it('choisir Clair applique le thème et le mémorise sur l’appareil', async () => {
    mockVeilleur()
    const { wrapper } = await open('/reglages')
    await wrapper.get('[data-theme-choice] input[value="light"]').setValue(true)
    expect(document.documentElement.dataset.theme).toBe('light')
    expect(localStorage.getItem('vigie.theme')).toBe('light')
    await wrapper.get('[data-theme-choice] input[value="dark"]').setValue(true)
    expect(document.documentElement.dataset.theme).toBe('dark')
    expect(localStorage.getItem('vigie.theme')).toBe('dark')
  })

  it('relit un choix clair déjà mémorisé', async () => {
    localStorage.setItem('vigie.theme', 'light')
    mockVeilleur()
    const { wrapper } = await open('/reglages')
    const radios = wrapper.get('[data-theme-choice]').findAll('input[type="radio"]')
    expect(radios.map((r) => (r.element as HTMLInputElement).checked)).toEqual([false, true])
  })

  it('le groupe est étiqueté et chaque choix a un libellé visible', async () => {
    mockVeilleur()
    const { wrapper } = await open('/reglages')
    const group = wrapper.get('[role="radiogroup"]')
    expect(group.attributes('aria-labelledby')).toBe('theme')
    expect(wrapper.get('#theme').text()).toBe('Thème')
    expect(group.findAll('label').map((l) => l.text())).toEqual(['Sombre', 'Clair'])
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

describe('Failles', () => {
  it('composants du plus grave au moins grave, failles, versions par source, attributions', async () => {
    const veilleur = mockVeilleur()
    const { wrapper } = await open('/s/site-a/failles')
    expect(wrapper.find('h1').text()).toBe('Failles')
    const components = wrapper.findAll('[data-component]')
    expect(components.map((c) => c.get('h2').text())).toEqual([
      'pkg:wordpress/plugin/exemple-plugin',
      'pkg:composer/exemple/paquet',
      'pkg:npm/%40exemple/paquet',
    ])
    const plugin = components[0]!
    expect(plugin.text()).toMatch(/Critique.*1 faille\(s\) · correction disponible/s)
    const first = plugin.get('[data-vuln]').text()
    expect(first).toMatch(/CVE-2099-0002.*Critique · Touché.*WF-2099-0002/s)
    expect(first).toContain('agent 1.2.3 · ci 1.2.4 · corrigée en 1.2.4')
    expect(first).toContain('Règle : exploitée (CISA KEV) · CVSS 9,8 · EPSS 12,3 %')
    expect(plugin.get('[data-kev]').text()).toContain('2099-01-10')
    expect(plugin.get('[data-redistribution]').text()).toContain('Usage interne')
    expect(plugin.get('[data-link]').text()).toBe('wordfence : https://example.org/avis/WF-2099-0002')
    expect(plugin.get('[data-attribution]').text()).toContain('Exemple Intelligence SARL')
    // Chaque faille porte ses attributions.
    for (const v of wrapper.findAll('[data-vuln]')) expect(v.findAll('[data-attribution]').length).toBeGreaterThan(0)

    const paquet = components[1]!
    expect(paquet.get('[data-redistribution]').text()).toContain('Faits seulement')
    expect(paquet.get('[data-waiver]').text()).toMatch(/Sous dérogation \(agent\) jusqu’au .*: valide/)
    // Version inconnue : libellé dédié, jamais « aucune faille ».
    expect(components[2]!.text()).toContain('Information · Version inconnue')
    expect(components[2]!.text()).toContain('ci version inconnue')
    // Lecture seule : aucun bouton hors pagination, aucune écriture.
    const buttons = wrapper.get('main').findAll('button').map((b) => b.text())
    expect(buttons.every((b) => b.startsWith('Afficher plus'))).toBe(true)
    expect(wrapper.get('[data-reminder]').text()).toContain('mettre à jour un composant se fait sur le site')
    expect(veilleur.calls.filter((c) => !['status', 'site', 'vulns', 'components'].includes(c))).toEqual([])
  })

  it('« Afficher plus » ajoute la page suivante ; un 409 reprend au début', async () => {
    const veilleur = mockVeilleur()
    const { wrapper } = await open('/s/site-a/failles')
    await wrapper.get('[data-more]').trigger('click')
    await settle()
    expect(wrapper.findAll('[data-vuln]')).toHaveLength(4)
    expect(wrapper.text()).toContain('Avertissement · Plage inconnue')
    expect(wrapper.find('[data-more]').exists()).toBe(false)
    await wrapper.get('[data-more-components]').trigger('click')
    await settle()
    expect(wrapper.findAll('[data-row]')).toHaveLength(3)

    const again = await open('/s/site-a/failles')
    veilleur.expired = true
    await again.wrapper.get('[data-more]').trigger('click')
    await settle()
    expect(again.wrapper.findAll('[data-vuln]')).toHaveLength(3)
    expect(again.wrapper.get('[data-list-notice]').text()).toContain('reprend au début')
  })

  it('un site sans inventaire (404) dit ce qui manque, sans donnée d’exemple', async () => {
    mockVeilleur()
    const { wrapper } = await open('/s/site-b/failles')
    expect(wrapper.get('[data-notyet] h2').text()).toBe('Failles des composants')
    expect(wrapper.text()).toContain('[sites.inventory]')
    expect(wrapper.find('[data-vuln]').exists()).toBe(false)
  })

  it('une attribution en HTML s’affiche en texte', async () => {
    mockVeilleur()
    const { wrapper } = await open('/s/site-a/failles')
    expect(wrapper.find('[data-attribution] b').exists()).toBe(false)
    expect(wrapper.text()).toContain('<b>Attribution</b> \ufffd fictive')
  })
})

describe('Sources de failles', () => {
  it('âge, issue, attributions et constat vulns-sync ouvert', async () => {
    mockVeilleur()
    const { wrapper } = await open('/reglages/sources')
    expect(wrapper.find('h1').text()).toBe('Sources de failles')
    const sources = wrapper.findAll('[data-source]').map((s) => s.text())
    expect(sources).toHaveLength(4)
    expect(sources[0]).toMatch(/osv-packagist.*synchronisée à 07:00.*chargée.*1200 entrée\(s\)/s)
    expect(sources[1]).toContain('Exemple Intelligence SARL')
    expect(sources[1]).toContain('Usage interne')
    expect(sources[2]).toContain('Jeu 2099.01.15')
    expect(sources[3]).toContain('jamais synchronisée')
    const link = wrapper.get('[data-incident]')
    expect(link.attributes('href')).toBe('/s/_veilleur/alerte/21')
    expect(link.text()).toContain('Incident n° 21')
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
    '/s/site-a/trafic',
    '/s/site-a/trafic/blocages',
    '/s/site-a/sante/ressources',
    '/s/site-a/parametres',
    '/s/site-a/failles',
    '/reglages',
    '/reglages/sources',
  ])('%s', async (path) => {
    mockVeilleur()
    const { wrapper } = await open(path)
    const text = wrapper.text()
    for (const sample of SAMPLES) expect(text).not.toContain(sample)
  })
})
