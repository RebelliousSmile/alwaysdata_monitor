import { describe, expect, it } from 'vitest'
import { accountResources, formatMb, percent } from '@/lib/resources'

describe('accountResources', () => {
  it('lit mémoire, charge et disque des facts', () => {
    expect(
      accountResources({
        php_version: '8.3.12',
        ram_used_mb: 512,
        ram_limit_mb: 2048,
        load_1: 0.5,
        load_5: 1,
        load_15: 1.5,
        disk_used_gb: 12.5,
        disk_total_gb: 50,
      }),
    ).toEqual({
      ram: { used: 512, limit: 2048 },
      load: [0.5, 1, 1.5],
      disk: { used: 12.5, total: 50 },
    })
  })

  it('ne complète rien : une limite absente reste absente, une famille incomplète est ignorée', () => {
    expect(accountResources({ ram_used_mb: 90, load_1: 1, disk_used_gb: 3 })).toEqual({
      ram: { used: 90, limit: null },
      load: null,
      disk: null,
    })
  })

  it('rend null sans aucune ressource, ou pour des facts qui n’en sont pas', () => {
    expect(accountResources({ php_version: '8.3.12' })).toBeNull()
    expect(accountResources(null)).toBeNull()
    expect(accountResources([1])).toBeNull()
    expect(accountResources({ ram_used_mb: '512', disk_total_gb: 0, disk_used_gb: 0 })).toBeNull()
  })
})

describe('formats', () => {
  it('Mo sous 1 Go, Go au-delà', () => {
    expect(formatMb(512)).toBe('512 Mo')
    expect(formatMb(2048)).toBe('2 Go')
  })
  it('pourcentage borné', () => {
    expect(percent(512, 2048)).toBe(25)
    expect(percent(3000, 2048)).toBe(100)
  })
})
