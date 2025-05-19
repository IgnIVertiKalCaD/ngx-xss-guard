import { NgModule, ModuleWithProviders } from '@angular/core';
import { CommonModule } from '@angular/common';
import { XSSSanitizerService } from './services/xss-sanitizer.service';
import { XssSanitizeDirective } from './directives/xss-sanitize.directive';
import { XssSanitizePipe } from './pipes/xss-sanitize.pipe';
import { XssAlertComponent } from './components/xss-alert/xss-alert.component';
import { XSSFilterOptions } from './models/xss-policy.model';

@NgModule({
  declarations: [
    XssSanitizeDirective,
    XssSanitizePipe,
    XssAlertComponent
  ],
  imports: [
    CommonModule
  ],
  exports: [
    XssSanitizeDirective,
    XssSanitizePipe,
    XssAlertComponent
  ],
  providers: [
    XSSSanitizerService
  ]
})
export class NgxXssGuardModule {
  /**
   * Предоставляет возможность глобальной конфигурации библиотеки
   * @param options Глобальные настройки XSS-фильтрации
   */
  static forRoot(options?: Partial<XSSFilterOptions>): ModuleWithProviders<NgxXssGuardModule> {
    return {
      ngModule: NgxXssGuardModule,
      providers: [
        {
          provide: 'XSS_FILTER_OPTIONS',
          useValue: options || {}
        },
        {
          provide: XSSSanitizerService,
          useFactory: (defaultOptions: Partial<XSSFilterOptions>) => {
            const service = new XSSSanitizerService(null);
            if (defaultOptions) {
              service.configure(defaultOptions);
            }
            return service;
          },
          deps: ['XSS_FILTER_OPTIONS']
        }
      ]
    };
  }
}
