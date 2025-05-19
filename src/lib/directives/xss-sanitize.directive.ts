import { Directive, ElementRef, Input, OnChanges, SimpleChanges } from '@angular/core';
import { XSSSanitizerService } from '../services/xss-sanitizer.service';
import { XSSFilterOptions } from '../models/xss-policy.model';

@Directive({
  selector: '[ngxXssSanitize]'
})
export class XssSanitizeDirective implements OnChanges {
  @Input('ngxXssSanitize') content: string = '';
  @Input() xssOptions: Partial<XSSFilterOptions> | null = null;

  constructor(
    private elementRef: ElementRef,
    private xssSanitizer: XSSSanitizerService
  ) {}

  ngOnChanges(changes: SimpleChanges): void {
    if ('content' in changes || 'xssOptions' in changes) {
      this.sanitizeContent();
    }
  }

  private sanitizeContent(): void {
    // Если есть локальные настройки, временно применяем их
    const originalOptions = this.xssSanitizer.getOptions();

    if (this.xssOptions) {
      this.xssSanitizer.configure(this.xssOptions);
    }

    // Санитизируем контент
    const sanitizedContent = this.xssSanitizer.sanitize(this.content);
    this.elementRef.nativeElement.innerHTML = sanitizedContent;

    // Восстанавливаем исходные настройки
    if (this.xssOptions) {
      this.xssSanitizer.configure(originalOptions);
    }
  }
}
