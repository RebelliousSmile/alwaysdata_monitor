// Icônes des maquettes, au trait (viewBox 24, trait de 2).
export type IconName =
  | 'back'
  | 'next'
  | 'reload'
  | 'settings'
  | 'shield'
  | 'todo'
  | 'traffic'
  | 'errors'
  | 'health'
  | 'sites'

export const ICON_PATHS: Record<IconName, string[]> = {
  back: ['M15 18l-6-6 6-6'],
  next: ['M9 18l6-6-6-6'],
  reload: ['M21 12a9 9 0 1 1-2.6-6.4', 'M21 3v6h-6'],
  settings: ['M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12'],
  shield: ['M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z', 'M9 12l2 2 4-4'],
  todo: ['M9 11l3 3 8-8', 'M20 12v7a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h9'],
  traffic: ['M3 12h4l3-8 4 16 3-8h4'],
  errors: ['M12 3l9.5 17h-19z', 'M12 10v4M12 17v.5'],
  health: ['M20.8 5.6a5.5 5.5 0 0 0-7.8 0L12 6.6l-1-1a5.5 5.5 0 0 0-7.8 7.8L12 22l8.8-8.6a5.5 5.5 0 0 0 0-7.8z'],
  sites: ['M4 5h16v5H4zM4 14h16v5H4z'],
}

/** Curseurs de l'icône Paramètres. */
export const ICON_KNOBS: Partial<Record<IconName, [number, number][]>> = {
  settings: [
    [16, 6],
    [10, 12],
    [18, 18],
  ],
}
