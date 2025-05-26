import { SanitizationConfig } from "./config";

/**
 * Logger class for XssDefender activities.
 */
export class Logger {
  /**
   * Logs an informational message.
   * @param message The message to log.
   * @param config The current sanitization configuration.
   */
  log(message: string, config: SanitizationConfig): void {
    if (config.enableLogging) {
      console.info(`XssDefender: ${message}`);
    }
  }

  /**
   * Logs a warning message.
   * @param message The warning message.
   * @param details Optional details to include in the log (used if logFormat is 'detailed').
   * @param config The current sanitization configuration.
   */
  warn(message: string, details?: any, config?: SanitizationConfig): void {
    if (config?.enableLogging) {
      if (config.logFormat === "detailed" && details) {
        console.warn(`XssDefender: ${message}`, details);
      } else {
        console.warn(`XssDefender: ${message}`);
      }
    }
  }
}
