import { defineConfig } from 'vitepress'

// https://vitepress.dev/reference/site-config
export default defineConfig({
    title: "EthBFT",
    description: "BFT consensus adapter for Ethereum Execution Layer clients",
    base: '/ethbft/',
    ignoreDeadLinks: true,
    themeConfig: {
        // https://vitepress.dev/reference/default-theme-config
        nav: [
            { text: 'Home', link: '/' },
            { text: 'Guide', link: '/guide/introduction' }
        ],

        sidebar: [
            {
                text: 'Guide',
                items: [
                    { text: 'Introduction', link: '/guide/introduction' },
                    { text: 'Getting Started', link: '/guide/getting-started' },
                    { text: 'Architecture', link: '/guide/architecture' }
                ]
            },
            {
                text: 'RFCs',
                items: [
                    { text: 'RFC 0001: Execution Payload Consensus', link: '/rfc/0001-execution-payload-consensus' }
                ]
            }
        ],

        socialLinks: [
            { icon: 'github', link: 'https://github.com/smallyunet/ethbft' }
        ],

        footer: {
            message: 'Released under the MIT License.',
            copyright: 'Copyright © 2024-present Smallyu'
        },

        editLink: {
            pattern: 'https://github.com/smallyunet/ethbft/edit/main/docs/:path',
            text: 'Edit this page on GitHub'
        }
    },
    head: [
        ['link', { rel: 'icon', href: '/favicon.ico' }]
    ]
})
