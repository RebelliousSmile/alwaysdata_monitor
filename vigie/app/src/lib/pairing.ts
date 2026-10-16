// Lecture du lien `vigie://pair?u=<adresse>&c=<code>` affiché par
// `vigie device pair`, pour un refus immédiat à l'écran. La commande Rust
// `pair` refait la même validation et fait foi.

export interface PairLink {
  /** Adresse publique du veilleur, sans barre finale. */
  url: string
  code: string
}

export type PairCheck = { ok: true; link: PairLink } | { ok: false; message: string }

/** 16 octets en base64url sans remplissage. */
const CODE = /^[A-Za-z0-9_-]{22}$/

const LOOPBACK = new Set(['127.0.0.1', '[::1]', 'localhost'])

/**
 * L'adresse doit être en https ; http n'est admis que sur la boucle locale,
 * et seulement si `allowLoopback` (build de debug).
 */
export function parsePairLink(text: string, allowLoopback: boolean): PairCheck {
  const fail = (message: string): PairCheck => ({ ok: false, message })
  let link: URL
  try {
    link = new URL(text.trim())
  } catch {
    return fail('Lien d’appairage illisible.')
  }
  if (link.protocol !== 'vigie:' || link.host !== 'pair') {
    return fail('Ce n’est pas un lien vigie://pair.')
  }
  const u = link.searchParams.get('u')
  const c = link.searchParams.get('c')
  if (!u) return fail('Adresse du veilleur absente du lien.')
  if (!c) return fail('Code absent du lien.')
  if (!CODE.test(c)) return fail('Code d’appairage mal formé.')
  let url: URL
  try {
    url = new URL(u)
  } catch {
    return fail('Adresse du veilleur illisible.')
  }
  const loopback = LOOPBACK.has(url.hostname.toLowerCase())
  if (url.protocol === 'http:' && loopback && !allowLoopback) {
    return fail('Adresse en http refusée : la boucle locale n’est admise qu’en build de debug.')
  }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
    return fail('Adresse du veilleur refusée : https exigé.')
  }
  return { ok: true, link: { url: u.replace(/\/+$/, ''), code: c } }
}
