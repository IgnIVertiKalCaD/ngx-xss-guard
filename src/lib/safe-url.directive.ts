import { Directive, ElementRef, Input, OnChanges, Renderer2, SimpleChanges } from '@angular/core';
import { DomSanitizer, SafeUrl } from '@angular/platform-browser';
import { XssSanitizerService } from './xss-sanitizer.service';
// Возможно, TrustedScriptURL понадобится для типа возвращаемого значения,
// если XssSanitizerService будет изменен для возврата TrustedScriptURL напрямую
// import { TrustedScriptURL } from 'trusted-types'; // Убедись, что импортируется из @types/trusted-types

/**
 * Директива для безопасной установки URL в атрибуты элементов с защитой от XSS.
 * Использует сервис XssSanitizerService для очистки URL.
 */
@Directive({
  selector: '[safeUrl]',
})
export class SafeUrlDirective implements OnChanges {
  /**
   * URL для безопасной установки. Может быть строкой, SafeUrl или null/undefined.
   */
  @Input() safeUrl: string | SafeUrl | null | undefined; // SafeResourceUrl может быть полезен тоже

  /**
   * Атрибут элемента (например, 'src', 'href'), в который необходимо установить безопасный URL.
   */
  @Input() safeUrlAttribute: string | undefined; // Добавим undefined, т.к. он может быть не задан изначально

  constructor(
    private readonly el: ElementRef,
    private readonly renderer: Renderer2,
    // DomSanitizer здесь, возможно, не нужен, если всю санитизацию делает XssSanitizerService
    // private readonly sanitizer: DomSanitizer,
    private readonly xssSanitizer: XssSanitizerService,
  ) {}

  ngOnChanges(changes: SimpleChanges): void {
    // Проверяем, изменилось ли входное свойство safeUrl
    if (changes['safeUrl']) {
      // Вызываем приватный метод для установки URL с новым значением
      this.setUrl(this.safeUrl);
    }
  }

  private setUrl(value: string | SafeUrl | null | undefined): void {
    // Если не указан атрибут или значение null/undefined, выходим.
    // Можно также рассмотреть удаление атрибута в этом случае.
    if (!this.safeUrlAttribute || value === null || value === undefined) {
      // Optional: Remove the attribute if the value is null/undefined
      // if (this.safeUrlAttribute) {
      //   this.renderer.removeAttribute(this.el.nativeElement, this.safeUrlAttribute);
      // }
      return;
    }

    let safeValue: SafeUrl;

    // Проверяем тип входного значения
    if (typeof value === 'string') {
      // Если это строка, используем сервис для ее санитизации
      safeValue = this.xssSanitizer.sanitizeUrl(value);
    } else {
      // Если это уже SafeUrl (или другой Safe тип), используем его напрямую.
      // Предполагаем, что SafeUrl, созданные Angular'ом или твоим сервисом, безопасны.
      safeValue = value;
      // Если safeUrl может быть SafeResourceUrl, возможно, потребуется явное приведение типа или обработка
      // if (!(value instanceof SafeUrl)) {
      //   console.warn('SafeUrlDirective received a non-string, non-SafeUrl value.');
      //   return;
      // }
    }

    // Получаем строковое представление SafeUrl.
    // Важно: это не просто оригинальная строка URL, а специальный маркер Angular.
    const stringRepresentation = safeValue.toString();

    // Устанавливаем атрибут с помощью Renderer2.
    // Renderer2 ожидает строковое значение атрибута.
    // Если Trusted Types включены, Angular или браузер могут применить их здесь
    // при фактической установке свойства DOM-элемента, даже если мы передаем строку
    // Renderer2.
    this.renderer.setAttribute(
      this.el.nativeElement,
      this.safeUrlAttribute,
      stringRepresentation, // Передаем строковое представление SafeUrl
    );

    // Логика вызова this.xssSanitizer.createTrustedUrl() и использования trustedValue
    // удалена, так как она вызывала ошибку с renderer.setAttribute, ожидающим строку,
    // и дублировала потенциальную логику Trusted Types внутри XssSanitizerService.
  }
}
