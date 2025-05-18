import { Inject, Injectable, SecurityContext } from '@angular/core';
import { DomSanitizer, SafeHtml, SafeResourceUrl, SafeScript, SafeStyle, SafeUrl } from '@angular/platform-browser';
// В зависимости от выбора:
// Вариант с allowSyntheticDefaultImports:
import DOMPurify from 'dompurify';
// Вариант без allowSyntheticDefaultImports:
// import * as DOMPurify from "dompurify";

import { XssSanitizerConfig } from './xss-sanitizer.config';
import { CspService } from './csp.service';
import { TrustedTypesService } from './trusted-types.service';

/**
 * Сервис для безопасной обработки HTML, URL, стилей и скриптов с защитой от XSS.
 */
@Injectable({
  providedIn: 'root',
})
export class XssSanitizerService {
  private readonly domPurifyConfig: DOMPurify.Config | undefined;
  private readonly cspEnabled: boolean;
  private readonly trustedTypesEnabled: boolean;
  private readonly trustedTypesPolicyName: string | undefined;

  constructor(
    private readonly sanitizer: DomSanitizer,
    @Inject(XssSanitizerConfig) config: XssSanitizerConfig,
    private readonly cspService: CspService,
    private readonly trustedTypesService: TrustedTypesService,
  ) {
    this.cspEnabled = config.cspEnabled ?? false;
    this.trustedTypesEnabled = config.trustedTypesEnabled ?? false;
    this.trustedTypesPolicyName = config.trustedTypesPolicyName;

    if (this.cspEnabled) {
      this.cspService.generateNonce();
    }

    // Здесь typeof window.trustedTypes, а не просто trustedTypes
    if (this.trustedTypesEnabled && typeof window.trustedTypes !== 'undefined') {
      this.trustedTypesService.createPolicy(this.trustedTypesPolicyName);
    }
  }

  /**
   * Очищает HTML-фрагмент от потенциально опасного кода, используя DOMPurify, и возвращает SafeHtml.
   * @param html Небезопасный HTML.
   * @returns Безопасный HTML.
   */
  sanitizeHtml(html: string): SafeHtml {
    const sanitizedHtml = DOMPurify.sanitize(html, this.domPurifyConfig) as string;
    return this.bypassSecurityTrustHtml(sanitizedHtml);
  }

  /**
   * Очищает URL от потенциально опасного кода и возвращает SafeUrl.
   * @param url Небезопасный URL.
   * @returns Безопасный URL.
   */
  sanitizeUrl(url: string): SafeUrl {
    return this.sanitizer.sanitize(SecurityContext.URL, url) ?? '';
  }

  /**
   * Очищает стиль от потенциально опасного кода и возвращает SafeStyle.
   * @param style Небезопасный стиль.
   * @returns Безопасный стиль.
   */
  sanitizeStyle(style: string): SafeStyle {
    return this.sanitizer.sanitize(SecurityContext.STYLE, style) ?? '';
  }

  /**
   * Очищает скрипт от потенциально опасного кода и возвращает SafeScript.
   * @param script Небезопасный скрипт.
   * @returns Безопасный скрипт.
   */
  sanitizeScript(script: string): SafeScript {
    return this.sanitizer.sanitize(SecurityContext.SCRIPT, script) ?? '';
  }

  /**
   * Очищает URL ресурса от потенциально опасного кода и возвращает SafeResourceUrl.
   * @param url Небезопасный URL ресурса.
   * @returns Безопасный URL ресурса.
   */
  sanitizeResourceUrl(url: string): SafeResourceUrl {
    return this.sanitizer.sanitize(SecurityContext.RESOURCE_URL, url) ?? '';
  }

  /**
   * Позволяет Angular обойти встроенную защиту и воспринимать HTML как безопасный.
   * **Внимание: используйте с осторожностью после тщательной очистки.**
   * @param html Очищенный HTML.
   * @returns SafeHtml.
   */
  bypassSecurityTrustHtml(html: string): SafeHtml {
    return this.sanitizer.bypassSecurityTrustHtml(html);
  }

  /**
   * Позволяет Angular обойти встроенную защиту и воспринимать URL как безопасный.
   * **Внимание: используйте с осторожностью после тщательной очистки.**
   * @param url Очищенный URL.
   * @returns SafeUrl.
   */
  bypassSecurityTrustUrl(url: string): SafeUrl {
    return this.sanitizer.bypassSecurityTrustUrl(url);
  }

  /**
   * Возвращает текущий nonce для Content Security Policy.
   * @returns Nonce.
   */
  getCspNonce(): string | null {
    return this.cspService.nonce;
  }

  /**
   * Создает Trusted Types значение HTML.
   * @param html Безопасный HTML.
   * @returns TrustedHTML или null, если Trusted Types не поддерживаются.
   */
  createTrustedHtml(html: string): TrustedHTML | null {
    return this.trustedTypesEnabled &&
      typeof window.trustedTypes !== 'undefined' && // Здесь typeof window.trustedTypes
      this.trustedTypesService.policy
      ? this.trustedTypesService.policy.createHTML(html)
      : null;
  }

  /**
   * Создает Trusted Types значение URL.
   * @param url Безопасный URL.
   * @returns TrustedScriptURL или null, если Trusted Types не поддерживаются.
   */
  createTrustedUrl(url: string): TrustedScriptURL | null {
    // Изменили TrustedURL на TrustedScriptURL
    return this.trustedTypesEnabled &&
      typeof window.trustedTypes !== 'undefined' && // Здесь typeof window.trustedTypes
      this.trustedTypesService.policy
      ? this.trustedTypesService.policy.createScriptURL(url) // Изменили createURL на createScriptURL
      : null;
  }
}
