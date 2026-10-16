import { describe, expect, it } from 'vitest'
import { errorText } from '@/lib/api'

describe('errorText', () => {
  it('lit le message d’un rejet de plugin, sans « [object Object] »', () => {
    expect(errorText({ message: 'No permission to use camera.' })).toBe('No permission to use camera.')
    expect(errorText(new Error('boom'))).toBe('boom')
    expect(errorText('cancelled')).toBe('cancelled')
  })

  it('sérialise un objet sans message', () => {
    expect(errorText({ code: 3 })).toBe('{"code":3}')
    expect(errorText(42)).toBe('42')
  })
})
