import { SanitizationConfig, DEFAULT_SANITIZATION_CONFIG } from "./config";
import { DANGEROUS_PATTERNS } from "./patterns";
import { Logger } from "./logger";

/**
 * Main class for XSS sanitization and defense.
 * Provides methods to sanitize strings, HTML content, objects, and URL parameters.
 */
export class XssDefender {
  private currentConfig: SanitizationConfig;
  private readonly logger: Logger;

  /**
   * Initializes a new instance of the XssDefender.
   * @param initialConfig Optional initial configuration to override defaults.
   */
  constructor(initialConfig?: Partial<SanitizationConfig>) {
    this.currentConfig = { ...DEFAULT_SANITIZATION_CONFIG, ...initialConfig };
    this.logger = new Logger();
    if (this.currentConfig.enableLogging) {
      this.logger.log("XssDefender initialized.", this.currentConfig);
    }
  }

  /**
   * Updates the current sanitization configuration.
   * @param config Partial configuration object to merge with the current settings.
   */
  public setConfig(config: Partial<SanitizationConfig>): void {
    this.currentConfig = { ...this.currentConfig, ...config };
    if (this.currentConfig.enableLogging) {
      this.logger.log("Configuration updated.", this.currentConfig);
    }
  }

  /**
   * Retrieves the current sanitization configuration.
   * @returns A read-only copy of the current configuration.
   */
  public getConfig(): Readonly<SanitizationConfig> {
    return this.currentConfig;
  }

  /**
   * Performs basic sanitization of a string value based on the provided configuration.
   * This includes stripping dangerous patterns, and handling allowed/disallowed tags and attributes.
   * @param value The string to sanitize.
   * @param config The sanitization configuration to use.
   * @returns The sanitized string.
   */
  private _basicSanitization(
    value: string,
    config: SanitizationConfig,
  ): string {
    let sanitized = value;

    // 1. Remove known dangerous patterns
    DANGEROUS_PATTERNS.forEach((pattern) => {
      sanitized = sanitized.replace(pattern, "");
    });

    // 2. Handle HTML tags
    if (config.allowedTags && config.allowedTags.length > 0) {
      // Pattern to find tags that are NOT in the allowed list
      // This matches opening tags, closing tags, and self-closing tags.
      const tagsToRemovePattern = new RegExp(
        `</?(?!${config.allowedTags.join("|")})[a-zA-Z0-9]+[^>]*>`,
        "gi",
      );
      sanitized = sanitized.replace(tagsToRemovePattern, (match) => {
        if (config.stripIgnoreTag) {
          return ""; // Remove the disallowed tag
        }
        // Encode the disallowed tag (e.g., <badtag> becomes &lt;badtag&gt;)
        return match.replace(/</g, "&lt;").replace(/>/g, "&gt;");
      });
    } else {
      // No tags are allowed
      if (config.stripIgnoreTag) {
        // Remove all tags
        sanitized = sanitized.replace(/<[^>]+>/gi, "");
      } else {
        // Encode all tags (e.g., <tag> becomes &lt;tag&gt;)
        sanitized = sanitized.replace(
          /<(\/?[\w\d\s="/.'-]+?)>/gi,
          (m, tagContent) => `&lt;${tagContent}&gt;`,
        );
      }
    }

    // 3. Handle HTML attributes (only for tags that are allowed or were not stripped)
    if (config.allowedAttributes && config.allowedAttributes.length > 0) {
      const universalTagPattern = /<([a-zA-Z0-9]+)((?:\s+[^>]*)?)>/g; // Matches any tag and its attributes string
      sanitized = sanitized.replace(
        universalTagPattern,
        (match, tagName, attributesString) => {
          const lowerTagName = tagName.toLowerCase();
          // Skip if the tag itself is not allowed (it might have been encoded, so check original allowedTags)
          if (
            config.allowedTags &&
            !config.allowedTags.includes(lowerTagName) &&
            !config.stripIgnoreTag
          ) {
            // If tags are encoded, this attribute stripping logic might not apply as expected
            // This part primarily works if disallowed tags were stripped or if the tag is allowed.
            return match;
          }
          if (
            config.allowedTags &&
            !config.allowedTags.includes(lowerTagName) &&
            config.stripIgnoreTag
          ) {
            // If tag was supposed to be stripped but wasn't caught by previous step (e.g. complex/malformed)
            // this check might be redundant if previous step was perfect.
            return match; // Or consider stripping the match if tag is definitively disallowed
          }

          const attributePattern =
            /\s*([a-zA-Z0-9\-_]+)\s*=\s*(?:(["'])(.*?)\2|([^>\s]+))/g;
          let newAttributesString = "";
          let attrMatch;
          while (
            (attrMatch = attributePattern.exec(attributesString)) !== null
          ) {
            const attributeName = attrMatch[1].toLowerCase();
            if (config.allowedAttributes?.includes(attributeName)) {
              // Reconstruct the attribute, ensuring its value is not re-processed by dangerous patterns here
              // as those were globally applied. Value itself is not deeply sanitized here beyond initial pass.
              newAttributesString += ` ${attrMatch[0]}`;
            }
          }
          return `<${tagName}${newAttributesString}>`;
        },
      );
    } else {
      // No attributes allowed, remove all attributes from all tags
      const allAttributesPattern =
        /\s+[a-zA-Z0-9\-_]+\s*=\s*(?:(["']).*?\1|[^>\s]+)/g;
      sanitized = sanitized.replace(
        /<([a-zA-Z0-9]+)((?:\s+[^>]*)?)>/g,
        (match, tagName, attributesString) => {
          return `<${tagName}${attributesString.replace(allAttributesPattern, "")}>`;
        },
      );
    }

    return sanitized;
  }

  /**
   * Sanitizes a string, removing potential XSS threats.
   * @param value The string to sanitize. Can be null or undefined, in which case an empty string is returned.
   * @returns The sanitized string.
   */
  public sanitizeString(value: string | null | undefined): string {
    if (value === null || value === undefined || value === "") return "";
    const originalValue = String(value);
    let sanitizedValue = originalValue;

    sanitizedValue = this._basicSanitization(
      sanitizedValue,
      this.currentConfig,
    );

    if (originalValue !== sanitizedValue) {
      this._logDetection(originalValue, sanitizedValue);
    }
    return sanitizedValue;
  }

  /**
   * Sanitizes an HTML string and sets it as the innerHTML of a given HTMLElement.
   * @param element The HTMLElement whose innerHTML is to be set.
   * @param unsafeHtml The potentially unsafe HTML string to sanitize and apply.
   */
  public sanitizeHtmlForElement(
    element: HTMLElement,
    unsafeHtml: string,
  ): void {
    if (!element) return;
    const sanitizedHtml = this.sanitizeString(unsafeHtml);
    element.innerHTML = sanitizedHtml;
  }

  /**
   * Recursively sanitizes all string values within an object or an array.
   * @param obj The object or array to sanitize.
   * @returns The sanitized object or array.
   */
  public sanitizeObject<T extends Record<string, any> | Array<any>>(obj: T): T {
    if (obj === null || typeof obj !== "object") {
      if (typeof obj === "string") {
        return this.sanitizeString(obj) as any;
      }
      return obj;
    }

    if (Array.isArray(obj)) {
      return obj.map((item) => this.sanitizeObject(item as any)) as any;
    }

    const result: Record<string, any> = {};
    for (const key in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        const value = obj[key];
        if (typeof value === "string") {
          result[key] = this.sanitizeString(value);
        } else if (typeof value === "object") {
          result[key] = this.sanitizeObject(value as any);
        } else {
          result[key] = value;
        }
      }
    }
    return result as T;
  }

  /**
   * Checks URL parameters for potential XSS risks and returns sanitized versions.
   * @param params A record of URL parameters.
   * @returns An object indicating if all parameters are safe and a list of any issues found.
   */
  public checkUrlParams(
    params: Record<string, string | string[] | undefined>,
  ): {
    isSafe: boolean;
    issues: Array<{ key: string; value: string; originalValue: string }>;
  } {
    const issues: Array<{ key: string; value: string; originalValue: string }> =
      [];
    let isSafe = true;

    for (const key in params) {
      if (Object.prototype.hasOwnProperty.call(params, key)) {
        const paramValue = params[key];
        const valuesToCheck: string[] = Array.isArray(paramValue)
          ? paramValue
          : paramValue
            ? [paramValue]
            : [];

        for (const originalSingleValue of valuesToCheck) {
          if (typeof originalSingleValue !== "string") continue;

          const sanitizedSingleValue = this.sanitizeString(originalSingleValue);
          // An issue is logged if sanitization changed the value OR if the original value had detectable XSS patterns
          // (even if sanitizeString somehow missed it or the patterns are different)
          if (
            originalSingleValue !== sanitizedSingleValue ||
            this.hasXssRisks(originalSingleValue)
          ) {
            if (originalSingleValue !== sanitizedSingleValue) {
              // Prefer logging if actual change occurred
              isSafe = false;
              issues.push({
                key,
                value: sanitizedSingleValue,
                originalValue: originalSingleValue,
              });
              this.logger.warn(
                `Potential XSS risk in URL parameter "${key}" was sanitized.`,
                {
                  key,
                  originalValue: originalSingleValue,
                  sanitizedValue: sanitizedSingleValue,
                  timestamp: new Date().toISOString(),
                },
                this.currentConfig,
              );
            } else if (this.hasXssRisks(originalSingleValue)) {
              // Log if original had risk, even if sanitization resulted in same string (less likely)
              isSafe = false; // Still mark as not entirely safe due to initial risk
              issues.push({
                key,
                value: sanitizedSingleValue,
                originalValue: originalSingleValue,
              }); // Report original and "sanitized"
              this.logger.warn(
                `Potential XSS risk detected in URL parameter "${key}". Input was already clean or sanitization was ineffective.`,
                {
                  key,
                  originalValue: originalSingleValue,
                  sanitizedValue: sanitizedSingleValue,
                  timestamp: new Date().toISOString(),
                },
                this.currentConfig,
              );
            }
          }
        }
      }
    }
    return { isSafe, issues };
  }

  /**
   * Checks if a given string contains known XSS risk patterns.
   * This method tests the string against `DANGEROUS_PATTERNS`.
   * @param value The string to check. Can be null or undefined.
   * @returns `true` if XSS risks are found, `false` otherwise.
   */
  public hasXssRisks(value: string | null | undefined): boolean {
    if (!value) return false;
    return DANGEROUS_PATTERNS.some((pattern) => pattern.test(String(value)));
  }

  /**
   * Logs a detection event when sanitization modifies the input string.
   * @param originalValue The original, unsafe string.
   * @param sanitizedValue The sanitized string.
   */
  private _logDetection(originalValue: string, sanitizedValue: string): void {
    const details = {
      originalValue,
      sanitizedValue,
      configUsed: {
        // Log only key aspects of config for brevity unless detailed
        allowedTags: this.currentConfig.allowedTags,
        allowedAttributes: this.currentConfig.allowedAttributes,
        stripIgnoreTag: this.currentConfig.stripIgnoreTag,
      },
      timestamp: new Date().toISOString(),
    };
    this.logger.warn(
      "Potential XSS detected and input sanitized.",
      details,
      this.currentConfig,
    );
  }
}
