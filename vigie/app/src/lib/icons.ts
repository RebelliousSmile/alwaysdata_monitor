// Icônes des maquettes, au trait (viewBox 24, trait de 2). L'engrenage reprend
// le tracé « settings » de Lucide 0.460.0 (licence ISC).
export type IconName =
  | 'back'
  | 'next'
  | 'reload'
  | 'settings'
  | 'gear'
  | 'shield'
  | 'todo'
  | 'traffic'
  | 'errors'
  | 'health'
  | 'sites'
  | 'vulns'
  | 'sources'

export const ICON_PATHS: Record<IconName, string[]> = {
  back: ['M15 18l-6-6 6-6'],
  next: ['M9 18l6-6-6-6'],
  reload: ['M21 12a9 9 0 1 1-2.6-6.4', 'M21 3v6h-6'],
  settings: ['M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12'],
  gear: [
    'M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z',
    'M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0z',
  ],
  shield: ['M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z', 'M9 12l2 2 4-4'],
  todo: ['M9 11l3 3 8-8', 'M20 12v7a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h9'],
  traffic: ['M3 12h4l3-8 4 16 3-8h4'],
  errors: ['M12 3l9.5 17h-19z', 'M12 10v4M12 17v.5'],
  health: ['M20.8 5.6a5.5 5.5 0 0 0-7.8 0L12 6.6l-1-1a5.5 5.5 0 0 0-7.8 7.8L12 22l8.8-8.6a5.5 5.5 0 0 0 0-7.8z'],
  sites: ['M4 5h16v5H4zM4 14h16v5H4z'],
  vulns: ['M21 8l-9-5-9 5 9 5 9-5z', 'M3 8v8l9 5 9-5V8', 'M12 13v8'],
  sources: [
    'M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3z',
    'M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6',
    'M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3',
  ],
}

/** Curseurs de l'icône Paramètres. */
export const ICON_KNOBS: Partial<Record<IconName, [number, number][]>> = {
  settings: [
    [16, 6],
    [10, 12],
    [18, 18],
  ],
}
