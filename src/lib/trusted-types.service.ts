import { Inject, Injectable } from '@angular/core';
import { XssSanitizerConfig } from './xss-sanitizer.config';

// Удалены пользовательские declare global

/**
 * Сервис для взаимодействия с Trusted Types API.
 */
@Injectable({
  providedIn: 'root',
})
export class TrustedTypesService {
  policy: TrustedTypePolicy | null = null;
  private readonly trustedTypesEnabled: boolean;

  constructor(@Inject(XssSanitizerConfig) private readonly config: XssSanitizerConfig) {
    this.trustedTypesEnabled = config.trustedTypesEnabled ?? false;
  }

  /**
   * Создает политику Trusted Types, если API поддерживается и включен в конфигурации.
   * @param policyName Необязательное имя политики. Если не указано, используется имя по умолчанию.
   */
  createPolicy(policyName?: string): void {
    // Проверяем, включены ли Trusted Types в конфигурации и доступен ли API в окне
    if (this.trustedTypesEnabled && typeof window.trustedTypes !== 'undefined' && !this.policy) {
      try {
        // Создаем политику. Функции в опциях должны возвращать string.
        this.policy =
          window.trustedTypes.createPolicy(policyName || 'ngx-xss-guard', {
            createHTML: (input: string) => input, // Возвращаем просто string
            createScriptURL: (input: string) => input, // Возвращаем просто string
            createScript: (input: string) => input, // Возвращаем просто string
          }) || null;
      } catch (e) {
        console.warn('Trusted Types policy creation failed.', e);
      }
    }
  }

  /**
   * Создает Trusted Types значение HTML.
   * @param html Безопасный HTML.
   * @returns TrustedHTML или null, если Trusted Types не поддерживаются.
   */
  createTrustedHtml(html: string): TrustedHTML | null {
    return this.trustedTypesEnabled && typeof window.trustedTypes !== 'undefined' && this.policy
      ? this.policy.createHTML(html)
      : null;
  }

  /**
   * Создает Trusted Types значение URL.
   * @param url Безопасный URL.
   * @returns TrustedScriptURL или null, если Trusted Types не поддерживаются или не включены.
   */
  createTrustedUrl(url: string): TrustedScriptURL | null {
    // Изменен тип возвращаемого значения
    // Используем policy.createScriptURL для создания TrustedScriptURL
    return this.trustedTypesEnabled && typeof window.trustedTypes !== 'undefined' && this.policy
      ? this.policy.createScriptURL(url) // Вызываем createScriptURL
      : null;
  }
}
