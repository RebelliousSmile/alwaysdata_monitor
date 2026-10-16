// Jetons de tokens.css projetés dans Tailwind : une vue n'emploie que ces
// noms, jamais une couleur codée en dur.
const v = (name) => `var(--vg-${name})`

/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{vue,ts}'],
  theme: {
    colors: {
      transparent: 'transparent',
      current: 'currentColor',
      bg: v('bg'),
      surface: { DEFAULT: v('surface'), 2: v('surface-2'), 3: v('surface-3') },
      header: v('header'),
      code: v('code'),
      line: { DEFAULT: v('line'), soft: v('line-soft') },
      control: v('control'),
      'switch-off': v('switch-off'),
      text: { DEFAULT: v('text'), 2: v('text-2'), 3: v('text-3') },
      link: v('link'),
      primary: { DEFAULT: v('primary'), on: v('on-primary') },
      ok: { DEFAULT: v('ok'), bg: v('ok-bg') },
      danger: { DEFAULT: v('danger'), bg: v('danger-bg'), line: v('danger-line'), text: v('danger-text') },
      warn: { DEFAULT: v('warn'), bg: v('warn-bg') },
      info: { DEFAULT: v('info'), bg: v('info-bg') },
      ia: { DEFAULT: v('ia'), bg: v('ia-bg') },
      neutral: { DEFAULT: v('neutral'), bg: v('neutral-bg') },
    },
    fontFamily: {
      sans: v('font'),
      mono: v('mono'),
    },
    // Cinq tailles seulement.
    fontSize: {
      xs: [v('fs-xs'), '1.45'],
      sm: [v('fs-sm'), '1.45'],
      md: [v('fs-md'), '1.45'],
      lg: [v('fs-lg'), '1.35'],
      xl: [v('fs-xl'), '1.25'],
    },
    borderRadius: {
      none: '0',
      sym: '8px',
      control: v('radius-control'),
      card: v('radius-card'),
      pill: v('radius-pill'),
      full: '50%',
    },
    extend: {
      spacing: { tap: v('tap'), gutter: v('gutter') },
      minHeight: { tap: v('tap') },
      minWidth: { tap: v('tap') },
      screens: { wide: '901px' },
    },
  },
  plugins: [],
}
