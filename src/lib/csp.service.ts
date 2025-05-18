import { Inject, Injectable } from '@angular/core';
import { XssSanitizerConfig } from './xss-sanitizer.config';

/**
 * Сервис для управления Content Security Policy (CSP).
 */
@Injectable({
  providedIn: 'root',
})
export class CspService {
  nonce: string | null = null;

  constructor(@Inject(XssSanitizerConfig) private readonly config: XssSanitizerConfig) {}

  /**
   * Генерирует случайный nonce для использования в CSP.
   */
  generateNonce(): void {
    if (this.config.cspEnabled && !this.nonce) {
      this.nonce = btoa(String.fromCharCode.apply(null, crypto.getRandomValues(new Uint8Array(16))));
    }
  }
}
