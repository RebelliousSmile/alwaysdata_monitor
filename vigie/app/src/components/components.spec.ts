import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import BottomNav from '@/components/BottomNav.vue'
import NotYet from '@/components/NotYet.vue'
import SideNav from '@/components/SideNav.vue'
import StateSymbol from '@/components/StateSymbol.vue'
import StatusChip from '@/components/StatusChip.vue'
import { FEATURES, type FeatureKey } from '@/lib/features'
import { badgeOf, type NavBadges } from '@/lib/nav'
import { STATES, TONES, type State, type Tone } from '@/lib/state'
import { mountAt } from '@/test/mount'

describe('jamais la couleur seule', () => {
  it.each(Object.keys(STATES) as State[])('l’état %s a son symbole et son libellé', (state) => {
    const wrapper = mount(StateSymbol, { props: { state } })
    expect(wrapper.text()).toContain(STATES[state].symbol)
    expect(wrapper.text()).toContain(STATES[state].label)
    expect(wrapper.get('.sr-only').text()).toBe(STATES[state].label)
  })

  it('affiche le libellé quand on le demande', () => {
    const wrapper = mount(StateSymbol, { props: { state: 'blind', labelled: true } })
    expect(wrapper.find('.sr-only').exists()).toBe(false)
    expect(wrapper.text()).toContain('Aveugle')
  })

  it.each(Object.keys(TONES) as Tone[])('la puce %s a son symbole', (tone) => {
    const wrapper = mount(StatusChip, { props: { tone, label: 'Libellé' } })
    expect(wrapper.text()).toBe(`${TONES[tone].symbol}Libellé`)
  })
})

describe('badges de la barre', () => {
  it('n’existent pas pour Trafic et Erreurs, ni pour zéro', () => {
    const all = { 'a-traiter': 2, sante: 0, trafic: 5, erreurs: 7 } as NavBadges
    expect(badgeOf(all, 'a-traiter')).toBe(2)
    expect(badgeOf(all, 'sante')).toBeUndefined()
    expect(badgeOf(all, 'trafic')).toBeUndefined()
    expect(badgeOf(all, 'erreurs')).toBeUndefined()
  })

  it.each([BottomNav, SideNav])('seul le badge non nul est rendu', async (nav) => {
    const props = { inSite: true, badges: { 'a-traiter': 3, sante: 0 } }
    const { wrapper } = await mountAt('/s/site-a', nav, nav === SideNav ? props : { badges: props.badges })
    const badges = wrapper.findAll('[data-badge]')
    expect(badges.map((b) => b.text())).toEqual(['3'])
    expect(wrapper.text()).not.toMatch(/\b0\b/)
  })
})

// Écrans dessinés sans source dans le veilleur : aucun chiffre d'exemple.
const WITHOUT_SOURCE: FeatureKey[] = ['visiteurs', 'journal', 'blocages', 'erreurs', 'ressources', 'ajouter', 'emails']

describe('NotYet', () => {
  it.each(WITHOUT_SOURCE)('%s nomme la fonctionnalité et ce qui manque, sans chiffre', (feature) => {
    const wrapper = mount(NotYet, { props: { feature } })
    expect(wrapper.get('h2').text()).toBe(FEATURES[feature].title)
    expect(wrapper.text()).toContain('Pas encore disponible')
    expect(wrapper.text()).toContain(FEATURES[feature].missing)
    expect(wrapper.text()).not.toMatch(/\d/)
  })

  it('chaque écran sans source renvoie vers un écran alimenté', () => {
    for (const feature of WITHOUT_SOURCE) expect(FEATURES[feature].link).toBeDefined()
  })
})
