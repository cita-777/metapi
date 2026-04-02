---
layout: home

hero:
  name: "Metapi 文档中心"
  text: "中转站的中转站"
  tagline: "将分散的 AI 中转站聚合为一个统一网关"
  image:
    src: /logos/logo-full.png
    alt: Metapi
  actions:
    - theme: brand
      text: 10 分钟快速上手
      link: /getting-started
    - theme: alt
      text: 上游接入
      link: /upstream-integration
    - theme: alt
      text: 常见问题 FAQ
      link: /faq

features:
  - title: 快速上手
    details: 从部署到第一条请求，按步骤完成最小可用环境搭建。
    link: /getting-started
  - title: 上游接入
    details: 按平台类型、官方预设和 AI 请求地址池的现状，快速判断站点该怎么接。
    link: /upstream-integration
  - title: OAuth 管理
    details: 直接接入 Codex、Claude、Gemini CLI、Antigravity 等 provider 授权账号。
    link: /oauth
  - title: 问题排查
    details: 汇总高频报错、根因定位和标准修复路径，降低重复沟通成本。
    link: /faq
---

## 项目架构

<div class="home-architecture">
  <img
    src="./screenshots/metapi-architecture.png"
    alt="Metapi Federated AI Model Aggregation Gateway Architecture"
  />
</div>

## 项目界面预览

<div class="home-carousel" aria-label="项目界面自动轮播预览">
  <button class="home-carousel-nav home-carousel-prev" type="button" aria-label="上一张">
    <span aria-hidden="true">‹</span>
  </button>
  <button class="home-carousel-nav home-carousel-next" type="button" aria-label="下一张">
    <span aria-hidden="true">›</span>
  </button>
  <div class="home-carousel-track">
    <figure class="home-carousel-slide">
      <img src="./screenshots/dashboard.png" alt="仪表盘" />
      <figcaption>仪表盘</figcaption>
    </figure>
    <figure class="home-carousel-slide">
      <img src="./screenshots/model-marketplace.png" alt="模型广场" />
      <figcaption>模型广场</figcaption>
    </figure>
    <figure class="home-carousel-slide">
      <img src="./screenshots/routes.png" alt="智能路由" />
      <figcaption>智能路由</figcaption>
    </figure>
    <figure class="home-carousel-slide">
      <img src="./screenshots/accounts.png" alt="账号管理" />
      <figcaption>账号管理</figcaption>
    </figure>
    <figure class="home-carousel-slide">
      <img src="./screenshots/sites.png" alt="站点管理" />
      <figcaption>站点管理</figcaption>
    </figure>
    <figure class="home-carousel-slide">
      <img src="./screenshots/tokens.png" alt="令牌管理" />
      <figcaption>令牌管理</figcaption>
    </figure>
    <figure class="home-carousel-slide">
      <img src="./screenshots/playground.png" alt="模型操练场" />
      <figcaption>模型操练场</figcaption>
    </figure>
    <figure class="home-carousel-slide">
      <img src="./screenshots/monitor.png" alt="可用性监控" />
      <figcaption>可用性监控</figcaption>
    </figure>
  </div>
</div>

<style>
.home-architecture {
  max-width: 800px;
  margin: 0 auto;
}

.home-architecture img {
  width: 100%;
  border-radius: 16px;
  border: 1px solid var(--vp-c-divider);
  box-shadow: 0 12px 28px rgba(2, 8, 20, 0.08);
}

.home-carousel {
  position: relative;
  width: 100%;
  margin: 0;
  overflow: hidden;
  border: 1px solid var(--vp-c-divider);
  border-radius: 16px;
  background: var(--vp-c-bg-soft);
  box-shadow: 0 10px 24px rgba(2, 8, 20, 0.06);
}

.home-carousel-track {
  display: flex;
  width: 100%;
  transform: translateX(0%);
  transition: transform 420ms ease;
  will-change: transform;
}

.home-carousel-slide {
  flex: 0 0 100%;
  margin: 0;
}

.home-carousel-slide img {
  display: block;
  width: 100%;
  height: auto;
  max-height: min(78vh, 980px);
  object-fit: contain;
  background: var(--vp-c-bg);
}

.home-carousel-slide figcaption {
  padding: 12px 14px;
  font-size: 22px;
  line-height: 1.2;
  font-weight: 600;
  color: var(--vp-c-text-1);
}

.home-carousel-nav {
  position: absolute;
  top: 0;
  bottom: 0;
  width: 14%;
  border: 0;
  background: transparent;
  color: #fff;
  z-index: 2;
  display: flex;
  align-items: center;
  opacity: 0;
  transition: opacity 0.2s ease;
  cursor: pointer;
}

.home-carousel-nav span {
  display: inline-flex;
  width: 40px;
  height: 40px;
  border-radius: 999px;
  align-items: center;
  justify-content: center;
  background: rgba(17, 24, 39, 0.56);
  font-size: 28px;
  line-height: 1;
  user-select: none;
}

.home-carousel:hover .home-carousel-nav {
  opacity: 1;
}

.home-carousel-prev {
  left: 0;
  justify-content: flex-start;
  padding-left: 12px;
  background: linear-gradient(90deg, rgba(15, 23, 42, 0.2), transparent);
}

.home-carousel-next {
  right: 0;
  justify-content: flex-end;
  padding-right: 12px;
  background: linear-gradient(270deg, rgba(15, 23, 42, 0.2), transparent);
}

@media (max-width: 640px) {
  .home-carousel-slide figcaption {
    font-size: 18px;
    padding: 10px 12px;
  }

  .home-carousel-nav {
    opacity: 1;
    width: 18%;
  }

  .home-carousel-nav span {
    width: 34px;
    height: 34px;
    font-size: 24px;
  }
}
</style>

<script setup>
import { onBeforeUnmount, onMounted } from 'vue';

let disposeCarousel = null;

onMounted(() => {
  const root = document.querySelector('.home-carousel');
  if (!root) return;

  const track = root.querySelector('.home-carousel-track');
  const slides = root.querySelectorAll('.home-carousel-slide');
  const prevBtn = root.querySelector('.home-carousel-prev');
  const nextBtn = root.querySelector('.home-carousel-next');

  if (!track || slides.length === 0) return;

  const total = slides.length;
  let index = 0;
  let timerId = null;

  const render = () => {
    track.style.transform = `translateX(-${index * 100}%)`;
  };

  const goNext = () => {
    index = (index + 1) % total;
    render();
  };

  const goPrev = () => {
    index = (index - 1 + total) % total;
    render();
  };

  const stopAutoPlay = () => {
    if (timerId !== null) {
      window.clearInterval(timerId);
      timerId = null;
    }
  };

  const startAutoPlay = () => {
    stopAutoPlay();
    timerId = window.setInterval(goNext, 3000);
  };

  const onMouseEnter = () => stopAutoPlay();
  const onMouseLeave = () => startAutoPlay();
  const onPrevClick = () => {
    goPrev();
    startAutoPlay();
  };
  const onNextClick = () => {
    goNext();
    startAutoPlay();
  };

  root.addEventListener('mouseenter', onMouseEnter);
  root.addEventListener('mouseleave', onMouseLeave);
  prevBtn?.addEventListener('click', onPrevClick);
  nextBtn?.addEventListener('click', onNextClick);

  render();
  startAutoPlay();

  disposeCarousel = () => {
    stopAutoPlay();
    root.removeEventListener('mouseenter', onMouseEnter);
    root.removeEventListener('mouseleave', onMouseLeave);
    prevBtn?.removeEventListener('click', onPrevClick);
    nextBtn?.removeEventListener('click', onNextClick);
  };
});

onBeforeUnmount(() => {
  if (typeof disposeCarousel === 'function') {
    disposeCarousel();
  }
});
</script>

## 从这里开始

- 初次部署或首次接入：从 [快速上手](/getting-started) 开始，先跑通最小可用链路。
- 不确定上游平台该怎么选：先看 [上游接入](/upstream-integration)，再决定走 `账号管理` 还是 `API Key管理`。
- 准备上线或升级回滚：查看 [部署指南](/deployment) 与 [运维手册](/operations)。
- 需要补齐环境变量或路由参数：直接查 [配置说明](/configuration)。
- 正在处理客户端或第三方工具接入：优先看 [客户端接入](/client-integration)。
- 遇到高频报错或异常表现：去 [常见问题 FAQ](/faq) 快速定位根因。

## 文档维护入口

- `/` 保持为面向所有读者的公开落地页，不再承担维护说明或贡献说明的二次首页职责。
- 维护文档站、梳理导航、补充内容地图时，请进入 [文档维护与贡献](/README)。
- 新增 FAQ 或教程前，请先阅读 [FAQ/教程贡献规范](/community/faq-tutorial-guidelines)。
