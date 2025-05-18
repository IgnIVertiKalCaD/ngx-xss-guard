import {
  Directive,
  ElementRef,
  Input,
  OnChanges,
  Renderer2,
  SimpleChanges,
} from "@angular/core";
import { DomSanitizer, SafeHtml } from "@angular/platform-browser";
import { XssSanitizerService } from "./xss-sanitizer.service";

/**
 * Директива для безопасной отрисовки HTML-контента с защитой от XSS.
 * Использует сервис XssSanitizerService для очистки HTML.
 */
@Directive({
  selector: "[safeHtml]",
})
export class SafeHtmlDirective implements OnChanges {
  /**
   * HTML-контент для безопасной отрисовки.
   */
  @Input() safeHtml: string | SafeHtml | null | undefined;

  constructor(
    private readonly el: ElementRef,
    private readonly renderer: Renderer2,
    private readonly sanitizer: DomSanitizer,
    private readonly xssSanitizer: XssSanitizerService,
  ) {}

  ngOnChanges(changes: SimpleChanges): void {
    if (changes["safeHtml"]) {
      this.setHtmlContent(this.safeHtml);
    }
  }

  private setHtmlContent(value: string | SafeHtml | null | undefined): void {
    if (value === null || value === undefined) {
      this.renderer.setProperty(this.el.nativeElement, "innerHTML", "");
      return;
    }

    let safeValue: SafeHtml;
    if (typeof value === "string") {
      safeValue = this.xssSanitizer.sanitizeHtml(value);
      const trustedValue = this.xssSanitizer.createTrustedHtml(
        safeValue.toString(),
      );
      this.renderer.setProperty(
        this.el.nativeElement,
        "innerHTML",
        trustedValue ? trustedValue : safeValue,
      );
    } else {
      const trustedValue = this.xssSanitizer.createTrustedHtml(
        value.toString(),
      );
      this.renderer.setProperty(
        this.el.nativeElement,
        "innerHTML",
        trustedValue ? trustedValue : value,
      );
    }
  }
}
