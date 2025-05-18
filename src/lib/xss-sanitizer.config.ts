/**
 * Конфигурация для сервиса XssSanitizerService.
 */
export class XssSanitizerConfig {
  /**
   * Настройка DOMPurify. См. https://github.com/cure53/DOMPurify.
   */
  domPurifyConfig?: DOMPurify.Config;

  /**
   * Включена ли генерация nonce для Content Security Policy.
   */
  cspEnabled?: boolean;

  /**
   * Функция для генерации nonce.
   */
  cspNonceGenerator?: () => string;

  /**
   * Включено ли использование Trusted Types.
   */
  trustedTypesEnabled?: boolean;

  /**
   * Имя политики Trusted Types.
   */
  trustedTypesPolicyName?: string;
}
