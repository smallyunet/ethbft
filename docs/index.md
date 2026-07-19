---
layout: home

hero:
  name: "EthBFT"
  text: "BFT Ethereum Execution"
  tagline: "A thin consensus adapter between CometBFT and the Engine API"
  image:
    src: https://vitepress.dev/vitepress-logo-large.png
    alt: EthBFT Logo
  actions:
    - theme: brand
      text: Get Started
      link: /guide/introduction
    - theme: alt
      text: View on GitHub
      link: https://github.com/smallyunet/ethbft

features:
  - title: Payload Consensus
    details: CometBFT decides complete, ordered Ethereum execution payloads.
    icon: 🚀
  - title: Independent Validation
    details: Every validator requires its dedicated Geth to return VALID.
    icon: 🔌
  - title: Thin Adapter
    details: CometBFT handles BFT, Geth handles EVM execution, and EthBFT binds them.
    icon: ⚡
  - title: MVP Network
    details: One-command Docker deployment with commit recovery and execution-path E2E tests.
    icon: 🐳
---

<style>
:root {
  --vp-home-hero-name-color: transparent;
  --vp-home-hero-name-background: -webkit-linear-gradient(120deg, #bd34fe 30%, #41d1ff);
}
</style>
