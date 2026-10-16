import { describe, expect, it } from 'vitest'
import { formatClock, formatDay, formatSpan, formatWhen, parisDate, readAgo } from '@/lib/time'

const at = (iso: string): number => Date.parse(iso) / 1000

describe('heures en Europe/Paris', () => {
  it('ajoute deux heures en été et une en hiver', () => {
    expect(formatClock(at('2026-07-15T19:50:00Z'))).toBe('21:50')
    expect(formatClock(at('2026-01-15T20:50:00Z'))).toBe('21:50')
  })

  it('suit le passage à l’heure d’hiver du 25 octobre 2026', () => {
    expect(formatClock(at('2026-10-25T00:30:00Z'))).toBe('02:30')
    expect(formatClock(at('2026-10-25T01:30:00Z'))).toBe('02:30')
    expect(formatClock(at('2026-10-25T02:30:00Z'))).toBe('03:30')
  })

  it('donne le jour civil de Paris, pas celui de l’appareil', () => {
    expect(parisDate(at('2026-10-14T22:30:00Z'))).toBe('2026-10-15')
    expect(parisDate(at('2026-01-14T22:30:00Z'))).toBe('2026-01-14')
    expect(formatDay(at('2026-10-14T10:00:00Z'))).toBe('mercredi 14 octobre')
  })
})

describe('readAgo', () => {
  const now = at('2026-10-14T12:00:00Z')

  it('dit « à l’instant » sous une minute, et pour une horloge en avance', () => {
    expect(readAgo(now - 30, now)).toBe('lu à l’instant')
    expect(readAgo(now + 30, now)).toBe('lu à l’instant')
  })

  it('compte les minutes puis les heures dans la même journée', () => {
    expect(readAgo(now - 120, now)).toBe('lu il y a 2 min')
    expect(readAgo(now - 3 * 3600 - 59, now)).toBe('lu il y a 3 h')
  })

  it('donne la date et l’heure dès que le jour civil change', () => {
    // 23:30 le 14 puis 00:30 le 15 à Paris : une heure, mais pas le même jour.
    const read = at('2026-10-14T21:30:00Z')
    expect(readAgo(read, read + 3600)).toMatch(/^lu le 14 oct\.? à 23:30$/)
  })

  it('donne la date au-delà d’un jour', () => {
    expect(readAgo(now - 2 * 86400, now)).toMatch(/^lu le 12 oct\.? à 14:00$/)
  })
})

describe('formatWhen', () => {
  const now = at('2026-10-16T08:00:00Z')

  it('donne l’heure seule le jour même à Paris', () => {
    expect(formatWhen(at('2026-10-16T06:05:00Z'), now)).toBe('à 08:05')
  })

  it('ajoute la date un autre jour civil de Paris', () => {
    expect(formatWhen(at('2026-10-14T19:50:00Z'), now)).toBe('le 14 oct. à 21:50')
    expect(formatWhen(at('2026-10-15T22:30:00Z'), now)).toBe('à 00:30')
  })
})

describe('formatSpan', () => {
  it('choisit la plus grande unité exacte', () => {
    expect(formatSpan(900)).toBe('15 min')
    expect(formatSpan(7200)).toBe('2 h')
    expect(formatSpan(86400)).toBe('1 j')
    expect(formatSpan(90)).toBe('90 s')
  })
})
