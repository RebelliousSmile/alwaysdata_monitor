import { describe, expect, it } from 'vitest'
import { parsePairLink } from '@/lib/pairing'

// Adresses fictives : domaine et IP réservés à la documentation.
const CODE = 'AbCdEfGhIjKlMnOpQrSt_-'
const link = (u: string, c = CODE): string => `vigie://pair?u=${encodeURIComponent(u)}&c=${c}`

describe('parsePairLink', () => {
  it('accepte une adresse https et retire la barre finale', () => {
    expect(parsePairLink(` ${link('https://vigie.example.org/')} `, false)).toEqual({
      ok: true,
      link: { url: 'https://vigie.example.org', code: CODE },
    })
  })

  it('refuse http hors de la boucle locale, même en debug', () => {
    for (const allowLoopback of [false, true]) {
      const check = parsePairLink(link('http://192.0.2.10:8080'), allowLoopback)
      expect(check).toEqual({ ok: false, message: 'Adresse du veilleur refusée : https exigé.' })
    }
  })

  it('n’admet la boucle locale en http qu’en build de debug', () => {
    for (const host of ['127.0.0.1:8080', 'localhost', '[::1]:8080']) {
      expect(parsePairLink(link(`http://${host}`), true).ok).toBe(true)
      const release = parsePairLink(link(`http://${host}`), false)
      expect(release.ok).toBe(false)
      expect(!release.ok && release.message).toMatch(/build de debug/)
    }
  })

  it('refuse un code mal formé ou absent', () => {
    expect(parsePairLink(link('https://vigie.example.org', 'trop-court'), false)).toEqual({
      ok: false,
      message: 'Code d’appairage mal formé.',
    })
    expect(parsePairLink(link('https://vigie.example.org', `${CODE}=`), false).ok).toBe(false)
    expect(parsePairLink('vigie://pair?u=https://vigie.example.org', false).ok).toBe(false)
  })

  it('refuse ce qui n’est pas un lien vigie://pair', () => {
    expect(parsePairLink('https://vigie.example.org/pair', false).ok).toBe(false)
    expect(parsePairLink(`vigie://autre?u=https://vigie.example.org&c=${CODE}`, false).ok).toBe(false)
    expect(parsePairLink('pas un lien', false).ok).toBe(false)
    expect(parsePairLink(`vigie://pair?c=${CODE}`, false).ok).toBe(false)
  })
})
