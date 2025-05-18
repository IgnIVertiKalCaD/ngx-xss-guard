import { ModuleWithProviders, NgModule } from '@angular/core';
import { XssSanitizerService } from './xss-sanitizer.service';
import { SafeHtmlDirective } from './safe-html.directive';
import { SafeUrlDirective } from './safe-url.directive';
import { CspService } from './csp.service';
import { TrustedTypesService } from './trusted-types.service';
import { XssSanitizerConfig } from './xss-sanitizer.config';

/**
 * Конфигурация модуля защиты от XSS.
 */
export interface XssGuardConfig {
  /**
   * Настройка DOMPurify. См. https://github.com/cure53/DOMPurify.
   */
  domPurifyConfig?: DOMPurify.Config;

  /**
   * Включить генерацию nonce для Content Security Policy.
   */
  cspEnabled?: boolean;

  /**
   * Функция для генерации nonce. По умолчанию генерируется случайная строка.
   */
  cspNonceGenerator?: () => string;

  /**
   * Включить использование Trusted Types.
   */
  trustedTypesEnabled?: boolean;

  /**
   * Имя политики Trusted Types. Если не указано, используется политика по умолчанию.
   */
  trustedTypesPolicyName?: string;
}

@NgModule({
  declarations: [SafeHtmlDirective, SafeUrlDirective],
  exports: [SafeHtmlDirective, SafeUrlDirective],
})
export class XssGuardModule {
  static forRoot(config?: XssGuardConfig): ModuleWithProviders<XssGuardModule> {
    return {
      ngModule: XssGuardModule,
      providers: [
        XssSanitizerService,
        CspService,
        TrustedTypesService,
        {
          provide: XssSanitizerConfig,
          useValue: {
            domPurifyConfig: config?.domPurifyConfig,
            cspEnabled: config?.cspEnabled,
            cspNonceGenerator: config?.cspNonceGenerator,
            trustedTypesEnabled: config?.trustedTypesEnabled,
            trustedTypesPolicyName: config?.trustedTypesPolicyName,
          },
        },
      ],
    };
  }
}
