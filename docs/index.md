---
layout: home

hero:
  name: "EthBFT"
  text: "Ethereum ↔ CometBFT"
  tagline: "Minimal Bridge for Engine API Orchestration"
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
  - title: Engine API Loop
    details: Forkchoice plus payload production orchestrated by CometBFT height signals.
    icon: 🚀
  - title: Seamless Integration
    details: Works with Go-Ethereum (Geth) via standard Engine API and JWT authentication.
    icon: 🔌
  - title: High Performance
    details: Lightweight and experimental, focusing on the core orchestration loop.
    icon: ⚡
  - title: Ready for Demo
    details: One-command deployment with Docker Compose for local development and testing.
    icon: 🐳
---

<style>
:root {
  --vp-home-hero-name-color: transparent;
  --vp-home-hero-name-background: -webkit-linear-gradient(120deg, #bd34fe 30%, #41d1ff);
}
</style>
