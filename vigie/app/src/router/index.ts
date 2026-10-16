import {
  createRouter,
  createWebHistory,
  type RouteRecordRaw,
  type RouterHistory,
} from 'vue-router'
import type { FeatureKey } from '@/lib/features'

// Écrans du HANDOFF §3, plus /appairage et /reglages/emails.

export type NavKey = 'a-traiter' | 'trafic' | 'erreurs' | 'sante'
export type SegmentGroup = 'trafic' | 'sante'

declare module 'vue-router' {
  interface RouteMeta {
    /** Écran d'un site : en-tête du site et barre de navigation. */
    site?: boolean
    /** Onglet actif de la barre du site. */
    nav?: NavKey
    /** Sélecteur à trois segments affiché au-dessus du contenu. */
    segments?: SegmentGroup
    /** Fonctionnalité sans source, rendue par NotYet. */
    feature?: FeatureKey
    /** Titre d'un écran global. */
    title?: string
    /** Écran global dont l'en-tête revient à cette route. */
    back?: string
  }
}

const NotYetView = () => import('@/views/NotYetView.vue')

export const routes: RouteRecordRaw[] = [
  { path: '/', name: 'sites', component: () => import('@/views/Main.vue') },
  {
    path: '/s/:site',
    component: () => import('@/views/ATraiter.vue'),
    meta: { site: true, nav: 'a-traiter' },
    children: [
      { path: '', name: 'a-traiter', component: () => import('@/views/AlerteVide.vue') },
      { path: 'alerte/:id', name: 'alerte', component: () => import('@/views/Alerte.vue') },
    ],
  },
  {
    path: '/s/:site/trafic',
    name: 'trafic',
    component: NotYetView,
    meta: { site: true, nav: 'trafic', segments: 'trafic', feature: 'visiteurs' },
  },
  {
    path: '/s/:site/trafic/journal',
    name: 'journal',
    component: NotYetView,
    meta: { site: true, nav: 'trafic', segments: 'trafic', feature: 'journal' },
  },
  {
    path: '/s/:site/trafic/blocages',
    name: 'blocages',
    component: NotYetView,
    meta: { site: true, nav: 'trafic', segments: 'trafic', feature: 'blocages' },
  },
  {
    path: '/s/:site/erreurs',
    name: 'erreurs',
    component: NotYetView,
    meta: { site: true, nav: 'erreurs', feature: 'erreurs' },
  },
  {
    path: '/s/:site/sante',
    name: 'sante',
    component: () => import('@/views/Dispo.vue'),
    meta: { site: true, nav: 'sante', segments: 'sante' },
  },
  {
    path: '/s/:site/sante/ressources',
    name: 'ressources',
    component: NotYetView,
    meta: { site: true, nav: 'sante', segments: 'sante', feature: 'ressources' },
  },
  {
    path: '/s/:site/sante/controles',
    name: 'controles',
    component: () => import('@/views/Controles.vue'),
    meta: { site: true, nav: 'sante', segments: 'sante' },
  },
  {
    path: '/s/:site/parametres',
    name: 'parametres',
    component: () => import('@/views/Parametres.vue'),
    meta: { site: true },
  },
  {
    path: '/reglages',
    name: 'reglages',
    component: () => import('@/views/Reglages.vue'),
    meta: { title: 'Réglages', back: 'sites' },
  },
  {
    path: '/reglages/emails',
    name: 'emails',
    component: NotYetView,
    meta: { title: 'E-mails', back: 'reglages', feature: 'emails' },
  },
  {
    path: '/ajouter',
    name: 'ajouter',
    component: NotYetView,
    meta: { title: 'Ajouter un site', back: 'sites', feature: 'ajouter' },
  },
  {
    path: '/appairage',
    name: 'appairage',
    component: () => import('@/views/Appairage.vue'),
    meta: { title: 'Appairage', back: 'sites' },
  },
  { path: '/:rest(.*)*', redirect: { name: 'sites' } },
]

/** Écrans d'un site vers lesquels Paramètres peut revenir. */
export const SITE_SCREENS: readonly string[] = [
  'a-traiter',
  'alerte',
  'trafic',
  'journal',
  'blocages',
  'erreurs',
  'sante',
  'ressources',
  'controles',
]

export function makeRouter(history: RouterHistory = createWebHistory()) {
  return createRouter({ history, routes })
}
