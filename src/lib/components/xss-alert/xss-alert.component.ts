import { Component, Input, OnChanges, SimpleChanges } from '@angular/core';
import { XSSSanitizerService } from '../../services/xss-sanitizer.service';

@Component({
  selector: 'ngx-xss-alert',
  template: `
    <div *ngIf="showAlert" class="xss-alert" [ngClass]="{'xss-alert-critical': isCritical}">
      <div class="xss-alert-header">
        <span class="xss-alert-icon">⚠️</span>
        <span class="xss-alert-title">XSS Угроза обнаружена</span>
      </div>
      <div class="xss-alert-content">
        <p>В содержимом обнаружен потенциально опасный код.</p>
        <pre *ngIf="showDetails" class="xss-alert-details">{{ detectedContent }}</pre>
      </div>
      <div class="xss-alert-actions">
        <button (click)="close()">Закрыть</button>
        <button *ngIf="!showDetails" (click)="toggleDetails()">Показать детали</button>
        <button *ngIf="showDetails" (click)="toggleDetails()">Скрыть детали</button>
      </div>
    </div>
  `,
  styles: [`
    .xss-alert {
      border: 1px solid #f8d7da;
      background-color: #fff3f3;
      color: #721c24;
      padding: 12px;
      margin: 10px 0;
      border-radius: 4px;
    }
    .xss-alert-critical {
      border-color: #dc3545;
      background-color: #ffebee;
    }
    .xss-alert-header {
      display: flex;
      align-items: center;
      margin-bottom: 8px;
      font-weight: bold;
    }
    .xss-alert-icon {
      margin-right: 8px;
    }
    .xss-alert-details {
      background-color: #f8f9fa;
      padding: 8px;
      border-radius: 4px;
      font-family: monospace;
      word-break: break-all;
      white-space: pre-wrap;
      margin: 8px 0;
      max-height: 150px;
      overflow: auto;
    }
    .xss-alert-actions {
      display: flex;
      gap: 8px;
      margin-top: 8px;
    }
    .xss-alert-actions button {
      padding: 4px 8px;
      background-color: #f8f9fa;
      border: 1px solid #ced4da;
      border-radius: 4px;
      cursor: pointer;
    }
    .xss-alert-actions button:hover {
      background-color: #e9ecef;
    }
  `]
})
export class XssAlertComponent implements OnChanges {
  @Input() content: string = '';
  @Input() autoDetect: boolean = true;
  @Input() isCritical: boolean = false;
  @Input() showAlert: boolean = true;

  showDetails: boolean = false;
  detectedContent: string = '';

  constructor(private xssSanitizer: XSSSanitizerService) {}

  ngOnChanges(changes: SimpleChanges): void {
    if ('content' in changes && this.autoDetect) {
      this.detectThreats();
    }
  }

  detectThreats(): void {
    if (this.content) {
      const isXSSThreat = this.xssSanitizer.detectXSSThreat(this.content);
      this.showAlert = isXSSThreat;

      if (isXSSThreat) {
        // Сохраняем только первые 500 символов для показа в деталях
        this.detectedContent = this.content.substring(0, 500);
        if (this.content.length > 500) {
          this.detectedContent += '...';
        }
      }
    } else {
      this.showAlert = false;
    }
  }

  toggleDetails(): void {
    this.showDetails = !this.showDetails;
  }

  close(): void {
    this.showAlert = false;
  }
}
