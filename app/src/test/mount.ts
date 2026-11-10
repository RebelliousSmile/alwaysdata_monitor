import { flushPromises, mount } from '@vue/test-utils'
import { createPinia } from 'pinia'
import type { Component } from 'vue'
import { createMemoryHistory, type RouteLocationRaw } from 'vue-router'
import App from '@/App.vue'
import { makeRouter } from '@/router'

/** Monte un composant (la coquille par défaut) sur une route donnée. */
export async function mountAt(
  target: RouteLocationRaw,
  component: Component = App,
  props: Record<string, unknown> = {},
) {
  const router = makeRouter(createMemoryHistory())
  await router.push(target)
  await router.isReady()
  const wrapper = mount(component, { props, global: { plugins: [createPinia(), router] } })
  await flushPromises()
  return { wrapper, router }
}
