import { Injectable } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import { XSSFilterLevel, XSSFilterOptions } from '../models/xss-policy.model';

@Injectable({
  providedIn: 'root'
})
export class XSSSanitizerService {
  private defaultOptions: XSSFilterOptions = {
    level: XSSFilterLevel.STRICT,
    enableScriptFiltering: true,
    enableStyleFiltering: true,
    enableUrlFiltering: true,
    allowedTags: ['p', 'br', 'b', 'i', 'em', 'strong', 'span', 'div', 'ul', 'ol', 'li'],
    disallowedTags: ['script', 'iframe', 'object', 'embed', 'form']
  };

  private options: XSSFilterOptions;

  constructor(private sanitizer: DomSanitizer) {
    this.options = { ...this.defaultOptions };
  }

  /**
   * Конфигурирует сервис с пользовательскими настройками
   * @param options Пользовательские настройки фильтрации XSS
   */
  configure(options: Partial<XSSFilterOptions>): void {
    this.options = { ...this.defaultOptions, ...options };
  }

  /**
   * Возвращает текущие настройки фильтрации XSS
   */
  getOptions(): XSSFilterOptions {
    return { ...this.options };
  }

  /**
   * Сбрасывает настройки к значениям по умолчанию
   */
  resetToDefaults(): void {
    this.options = { ...this.defaultOptions };
  }

  /**
   * Санитизирует HTML-строку согласно настройкам
   * @param value HTML-строка для санитизации
   * @returns Очищенная строка
   */
  sanitize(value: string): string {
    if (!value) {
      return '';
    }

    let sanitizedValue = value;

    // Применяем пользовательский санитайзер, если он определен
    if (this.options.level === XSSFilterLevel.CUSTOM && this.options.customSanitizer) {
      return this.options.customSanitizer(value);
    }

    // Простая фильтрация скриптов
    if (this.options.enableScriptFiltering) {
      sanitizedValue = this.filterScripts(sanitizedValue);
    }

    // Фильтрация стилей
    if (this.options.enableStyleFiltering) {
      sanitizedValue = this.filterStyles(sanitizedValue);
    }

    // Фильтрация URL-адресов
    if (this.options.enableUrlFiltering) {
      sanitizedValue = this.filterUrls(sanitizedValue);
    }

    // Фильтрация запрещенных тегов
    sanitizedValue = this.filterDisallowedTags(sanitizedValue);

    return sanitizedValue;
  }

  /**
   * Санитизирует HTML и возвращает безопасный HTML-объект для Angular
   * @param value HTML-строка для санитизации
   * @returns SafeHtml объект для использования в шаблонах
   */
  sanitizeToSafeHtml(value: string): SafeHtml {
    const sanitizedValue = this.sanitize(value);
    return this.sanitizer.bypassSecurityTrustHtml(sanitizedValue);
  }

  /**
   * Проверяет строку на потенциальные XSS-угрозы
   * @param value Строка для проверки
   * @returns true, если обнаружены потенциальные угрозы
   */
  detectXSSThreat(value: string): boolean {
    if (!value) {
      return false;
    }

    const scriptPattern = /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi;
    const onEventPattern = /\s+on\w+\s*=\s*["']?[^"'>\s]+/gi;
    const evalPattern = /\beval\s*\(/gi;
    const dataUriPattern = /data:[^;]*;base64,[a-z0-9+\/=]/gi;
    const jsUriPattern = /javascript:/gi;

    return (
      scriptPattern.test(value) ||
      onEventPattern.test(value) ||
      evalPattern.test(value) ||
      dataUriPattern.test(value) ||
      jsUriPattern.test(value)
    );
  }

  /**
   * Фильтрует скрипты из HTML-строки
   * @private
   */
  private filterScripts(value: string): string {
    // Удаляем теги <script>
    let filtered = value.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');

    // Удаляем обработчики событий (on*)
    filtered = filtered.replace(/\s+on\w+\s*=\s*["']?[^"'>\s]+/gi, '');

    // Удаляем javascript: URL
    filtered = filtered.replace(/javascript:/gi, 'invalid:');

    return filtered;
  }

  /**
   * Фильтрует стили из HTML-строки
   * @private
   */
  private filterStyles(value: string): string {
    // В строгом режиме удаляем все стили
    if (this.options.level === XSSFilterLevel.STRICT) {
      // Удаляем теги <style>
      let filtered = value.replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '');

      // Удаляем атрибуты style
      filtered = filtered.replace(/\s+style\s*=\s*["'][^"']*["']/gi, '');

      return filtered;
    }

    // В базовом режиме удаляем только потенциально опасные стили
    // (expression, url, position: fixed и т.д.)
    return value.replace(
      /style\s*=\s*["'](.*?)(expression|javascript|url\s*\(|position\s*:\s*fixed)(.*?)["']/gi,
      'style="$1removed$3"'
    );
  }

  /**
   * Фильтрует потенциально опасные URL
   * @private
   */
  private filterUrls(value: string): string {
    // Фильтруем data: URL с base64-кодированием
    let filtered = value.replace(/data:[^;]*;base64,[a-z0-9+\/=]/gi, 'invalid:');

    // Ищем атрибуты с URL (src, href, и т.д.)
    const urlAttributes = ['src', 'href', 'action', 'formaction', 'background'];

    for (const attr of urlAttributes) {
      const regex = new RegExp(`${attr}\\s*=\\s*["'](.*?)["']`, 'gi');
      filtered = filtered.replace(regex, (match, url) => {
        // Проверяем URL на небезопасные протоколы
        if (/^(javascript|data|vbscript):/i.test(url)) {
          return `${attr}="invalid:"`;
        }
        return match;
      });
    }

    return filtered;
  }

  /**
   * Фильтрует запрещенные теги
   * @private
   */
  private filterDisallowedTags(value: string): string {
    let filtered = value;

    if (this.options.disallowedTags && this.options.disallowedTags.length > 0) {
      for (const tag of this.options.disallowedTags) {
        const regex = new RegExp(`<${tag}\\b[^<]*(?:(?!<\\/${tag}>)<[^<]*)*<\\/${tag}>`, 'gi');
        filtered = filtered.replace(regex, '');

        // Также удаляем самозакрывающиеся теги
        const selfClosingRegex = new RegExp(`<${tag}\\b[^>]*\\/?>`, 'gi');
        filtered = filtered.replace(selfClosingRegex, '');
      }
    }

    return filtered;
  }
}
