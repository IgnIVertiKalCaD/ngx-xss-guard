import { Pipe, PipeTransform } from '@angular/core';
import { XSSSanitizerService } from '../services/xss-sanitizer.service';
import { XSSFilterOptions } from '../models/xss-policy.model';
import { SafeHtml } from '@angular/platform-browser';

@Pipe({
  name: 'xssSanitize',
  pure: true
})
export class XssSanitizePipe implements PipeTransform {
  constructor(private xssSanitizer: XSSSanitizerService) {}

  transform(value: string, options?: Partial<XSSFilterOptions>): SafeHtml {
    if (!value) {
      return '';
    }

    // Если есть локальные настройки, временно применяем их
    const originalOptions = this.xssSanitizer.getOptions();

    if (options) {
      this.xssSanitizer.configure(options);
    }

    // Санитизируем и преобразуем в SafeHtml
    const safeHtml = this.xssSanitizer.sanitizeToSafeHtml(value);

    // Восстанавливаем исходные настройки
    if (options) {
      this.xssSanitizer.configure(originalOptions);
    }

    return safeHtml;
  }
}
