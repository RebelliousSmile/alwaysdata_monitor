import { describe, expect, it } from 'vitest'
import { mountAt } from '@/test/mount'

// Un site fictif : le dépôt est public.
const SITE = '/s/site-a'

const SCREENS: [path: string, name: string, heading: string, notYet: boolean][] = [
  ['/', 'sites', 'Mes sites', false],
  [SITE, 'a-traiter', 'À traiter', false],
  [`${SITE}/alerte/12`, 'alerte', 'Alerte n° 12', false],
  [`${SITE}/trafic`, 'trafic', 'Visiteurs automatisés', true],
  [`${SITE}/trafic/journal`, 'journal', 'Journal des requêtes', true],
  [`${SITE}/trafic/blocages`, 'blocages', 'Blocages', true],
  [`${SITE}/erreurs`, 'erreurs', 'Erreurs', true],
  [`${SITE}/sante`, 'sante', 'Disponibilité', false],
  [`${SITE}/sante/ressources`, 'ressources', 'Ressources du compte', true],
  [`${SITE}/sante/controles`, 'controles', 'Contrôles', false],
  [`${SITE}/parametres`, 'parametres', 'Paramètres du site', false],
  ['/reglages', 'reglages', 'Réglages', false],
  ['/reglages/emails', 'emails', 'Modèles d’e-mail', true],
  ['/ajouter', 'ajouter', 'Ajouter un site', true],
  ['/appairage', 'appairage', 'Appairer cet appareil', false],
]

const CONTEXT = { date: '2026-10-14', de: '08:00', a: '12:00', src: 'agent', q: 'wp-login' }

describe('routes du HANDOFF', () => {
  it.each(SCREENS)('%s rend sa vue', async (path, name, heading, notYet) => {
    const { wrapper, router } = await mountAt(path)
    expect(router.currentRoute.value.name).toBe(name)
    const headings = wrapper.findAll('h1').map((h) => h.text())
    expect(headings).toContain(heading)
    const unavailable = wrapper.findAll('[data-notyet] h2').map((h) => h.text())
    expect(unavailable.includes(heading)).toBe(notYet)
  })

  it('renvoie une adresse inconnue vers Mes sites', async () => {
    const { router } = await mountAt('/nulle-part')
    expect(router.currentRoute.value.name).toBe('sites')
  })

  it('ouvre l’alerte dans le détail, à côté de la liste', async () => {
    const { wrapper } = await mountAt(`${SITE}/alerte/12`)
    expect(wrapper.find('[data-list] h1').text()).toBe('À traiter')
    expect(wrapper.find('[data-detail] h1').text()).toBe('Alerte n° 12')
  })
})

describe('contexte des liens internes', () => {
  it('les segments et la barre gardent date, fenêtre, sources et filtre', async () => {
    const { wrapper, router } = await mountAt({
      path: `${SITE}/sante`,
      query: { ...CONTEXT, autre: 'perdu' },
    })
    const links = wrapper.findAll('nav a').filter((a) => a.attributes('href')?.startsWith(SITE))
    expect(links.length).toBeGreaterThan(0)
    for (const link of links) {
      const target = router.resolve(link.attributes('href') ?? '')
      expect(target.query).toEqual(CONTEXT)
    }
    const controles = links.find((a) => a.text() === 'Contrôles')
    expect(router.resolve(controles?.attributes('href') ?? '').name).toBe('controles')
  })

  it('Trafic ouvre un écran qui nomme la fonctionnalité', async () => {
    const { wrapper, router } = await mountAt(`${SITE}/sante`)
    const trafic = wrapper.findAll('nav a').find((a) => a.text() === 'Trafic')
    await router.push(trafic?.attributes('href') ?? '')
    await new Promise((resolve) => setTimeout(resolve))
    expect(router.currentRoute.value.name).toBe('trafic')
  })
})

describe('retour depuis Paramètres', () => {
  const backOf = async (depuis: string) => {
    const { wrapper, router } = await mountAt({
      name: 'parametres',
      params: { site: 'site-a' },
      query: { depuis, date: CONTEXT.date },
    })
    const back = wrapper.get('header a[aria-label="Retour à l’écran précédent"]')
    return router.resolve(back.attributes('href') ?? '')
  }

  it('le lien Paramètres emporte l’écran courant', async () => {
    const { wrapper, router } = await mountAt({ path: `${SITE}/trafic`, query: { date: CONTEXT.date } })
    const settings = wrapper.get('header a[aria-label="Paramètres du site"]')
    const target = router.resolve(settings.attributes('href') ?? '')
    expect(target.name).toBe('parametres')
    expect(target.query).toEqual({ date: CONTEXT.date, depuis: `${SITE}/trafic?date=${CONTEXT.date}` })
  })

  it('ramène à l’écran d’origine du même site', async () => {
    const target = await backOf(`${SITE}/sante/controles?date=${CONTEXT.date}`)
    expect(target.name).toBe('controles')
    expect(target.query).toEqual({ date: CONTEXT.date })
  })

  it.each([
    ['une adresse externe', 'https://site-b.example.org/'],
    ['une adresse sans schéma', '//site-b.example.org/'],
    ['un autre site', '/s/site-b/trafic'],
    ['un écran global', '/reglages'],
  ])('refuse %s et revient à À traiter', async (_label, depuis) => {
    const target = await backOf(depuis)
    expect(target.name).toBe('a-traiter')
    expect(target.params.site).toBe('site-a')
    expect(target.query).toEqual({ date: CONTEXT.date })
  })
})
