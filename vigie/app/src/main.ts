import { createPinia } from 'pinia'
import { createApp } from 'vue'
import App from '@/App.vue'
import { makeRouter } from '@/router'
// Polices embarquées : aucune requête externe (CSP 'self').
import '@fontsource/ibm-plex-sans/400.css'
import '@fontsource/ibm-plex-sans/500.css'
import '@fontsource/ibm-plex-sans/600.css'
import '@fontsource/ibm-plex-mono/400.css'
import '@fontsource/ibm-plex-mono/500.css'
import '@/styles/main.css'

createApp(App).use(createPinia()).use(makeRouter()).mount('#app')
