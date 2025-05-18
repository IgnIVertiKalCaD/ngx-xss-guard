# ngx-xss-guard

[![npm version](https://badge.fury.io/js/ngx-xss-guard.svg)](https://www.npmjs.com/package/ngx-xss-guard)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![codecov](https://codecov.io/gh/<your-github-username>/ngx-xss-guard/branch/main/graph/badge.svg?token=<your-codecov-token>)](https://codecov.io/gh/<your-github-username>/ngx-xss-guard)
[![CI](https://github.com/<your-github-username>/ngx-xss-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/<your-github-username>/ngx-xss-guard/actions/workflows/ci.yml)

Angular-библиотека `ngx-xss-guard` предназначена для комплексной защиты Angular-приложений от атак Cross-Site Scripting (XSS). Она предоставляет инструменты для безопасной обработки HTML, URL и других потенциально опасных данных, интегрируясь с нативными механизмами безопасности Angular, а также с передовыми техниками, такими как DOMPurify, Content Security Policy (CSP) и Trusted Types.

## Угрозы XSS

Cross-Site Scripting (XSS) — это тип уязвимости веб-безопасности, который позволяет злоумышленникам внедрять вредоносный код на веб-страницы, просматриваемые другими пользователями. Это может привести к краже учетных данных, перенаправлению на вредоносные сайты, изменению содержимого страницы и другим опасным последствиям.

## Установка

```bash
npm install ngx-xss-guard
```
