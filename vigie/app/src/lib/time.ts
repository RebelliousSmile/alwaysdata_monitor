// Heures affichées en Europe/Paris, quel que soit le fuseau de l'appareil
// (HANDOFF §4). Les instants viennent du veilleur en secondes Unix.

const ZONE = 'Europe/Paris'

const clock = new Intl.DateTimeFormat('fr-FR', {
  timeZone: ZONE,
  hour: '2-digit',
  minute: '2-digit',
  hourCycle: 'h23',
})

const day = new Intl.DateTimeFormat('fr-FR', {
  timeZone: ZONE,
  weekday: 'long',
  day: 'numeric',
  month: 'long',
})

const shortDay = new Intl.DateTimeFormat('fr-FR', {
  timeZone: ZONE,
  day: 'numeric',
  month: 'short',
})

const ymd = new Intl.DateTimeFormat('en-CA', {
  timeZone: ZONE,
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
})

const toDate = (seconds: number): Date => new Date(seconds * 1000)

/** « 21:50 ». */
export function formatClock(seconds: number): string {
  return clock.format(toDate(seconds))
}

/** « mercredi 14 octobre ». */
export function formatDay(seconds: number): string {
  return day.format(toDate(seconds))
}

/** Jour civil à Paris, « 2026-10-14 ». */
export function parisDate(seconds: number): string {
  return ymd.format(toDate(seconds))
}

/**
 * Fraîcheur d'une lecture : « lu à l'instant », « lu il y a 2 min »,
 * « lu il y a 3 h », puis la date et l'heure au-delà d'un jour ou d'un
 * changement de jour civil.
 */
export function readAgo(read: number, now: number): string {
  const elapsed = Math.max(0, now - read)
  if (elapsed < 60) return 'lu à l’instant'
  if (elapsed < 3600) return `lu il y a ${Math.floor(elapsed / 60)} min`
  if (elapsed < 86400 && parisDate(read) === parisDate(now)) {
    return `lu il y a ${Math.floor(elapsed / 3600)} h`
  }
  return `lu le ${shortDay.format(toDate(read))} à ${formatClock(read)}`
}

/** « à 21:50 » le jour même à Paris, sinon « le 14 oct. à 21:50 ». */
export function formatWhen(seconds: number, now: number): string {
  if (parisDate(seconds) === parisDate(now)) return `à ${formatClock(seconds)}`
  return `le ${shortDay.format(toDate(seconds))} à ${formatClock(seconds)}`
}

/** Durée lisible : « 15 min », « 2 h », « 1 j ». */
export function formatSpan(seconds: number): string {
  if (seconds % 86400 === 0) return `${seconds / 86400} j`
  if (seconds % 3600 === 0) return `${seconds / 3600} h`
  if (seconds % 60 === 0) return `${seconds / 60} min`
  return `${seconds} s`
}
