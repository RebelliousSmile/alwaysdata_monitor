import { describe, expect, it } from 'vitest'
import { bySeverity, mailEvents, resultChip, siteBadges, tlsNotAfter } from '@/lib/checks'
import type { Check } from '@/lib/api'
import { DAY, NOW, fixture } from '@/test/veilleur'

const siteA = () => fixture().sites['site-a']

function named(name: string): Check {
  const found = siteA().checks.find((c) => c.name === name)
  if (!found) throw new Error(`contrôle ${name} absent de la fixture`)
  return found
}

describe('siteBadges', () => {
  it('compte les incidents ouverts hors information', () => {
    expect(siteBadges(siteA())).toEqual({ 'a-traiter': 2, sante: 2 })
  })

  it('Santé ne compte que les incidents dont le contrôle est listé', () => {
    const detail = siteA()
    detail.checks = detail.checks.filter((c) => c.name !== 'headers')
    expect(siteBadges(detail)).toEqual({ 'a-traiter': 2, sante: 1 })
  })

  it('rien d’ouvert, rien à compter', () => {
    expect(siteBadges(fixture().sites['site-b'])).toEqual({ 'a-traiter': 0, sante: 0 })
  })
})

describe('bySeverity', () => {
  it('du plus grave au moins grave', () => {
    const order = [...siteA().open_incidents].sort(bySeverity).map((i) => i.severity)
    expect(order).toEqual(['critical', 'warning', 'info'])
  })
})

describe('mailEvents', () => {
  it('ouverture, relance et clôture, du plus récent au plus ancien, sans doublon', () => {
    const data = fixture()
    const open = data.sites['site-a'].open_incidents
    const events = mailEvents([...open, ...open, ...data.history['site-a'].incidents])
    expect(events.map((e) => [e.kind, e.incident.id])).toEqual([
      ['Relance', 13],
      ['Ouverture', 12],
      ['Ouverture', 13],
      ['Clôture', 9],
      ['Ouverture', 9],
    ])
  })
})

describe('tlsNotAfter', () => {
  it('lit la date relevée par le contrôle tls', () => {
    expect(tlsNotAfter(siteA().checks)).toBe(NOW + 25 * DAY)
  })

  it('null sans relevé exploitable', () => {
    const checks = siteA().checks.map((c) => (c.name === 'tls' ? { ...c, observed: { tls_not_after: 'demain' } } : c))
    expect(tlsNotAfter(checks)).toBeNull()
    expect(tlsNotAfter([])).toBeNull()
  })
})

describe('resultChip', () => {
  it('nomme la gravité d’un constat, et un contrôle jamais passé', () => {
    const content = named('content')
    const [tls, headers] = [named('tls'), named('headers')]
    expect(resultChip(content).label).toBe('Rien à signaler')
    expect(resultChip(tls).label).toBe('Information')
    expect(resultChip(headers).label).toBe('Avertissement')
    expect(resultChip({ ...content, result: null }).label).toBe('Jamais passé')
    expect(resultChip({ ...content, result: 'error' }).label).toBe('Non concluant')
  })
})
