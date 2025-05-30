/**
 * Configuration options for the XSSDefender.
 */
export interface SanitizationConfig {
  /**
   * List of allowed HTML tags. If undefined or empty, all tags will be subject to
   * `stripIgnoreTag` rule (stripped or encoded).
   * Example: ['p', 'br', 'a']
   */
  allowedTags?: string[];

  /**
   * List of allowed HTML attributes. Attributes not in this list will be removed.
   * This applies to allowed tags.
   * Example: ['href', 'title', 'class']
   */
  allowedAttributes?: string[];

  /**
   * Determines how to handle tags not in `allowedTags`.
   * - If `true`: Disallowed tags are removed. (e.g., `<script>` becomes `''`)
   * - If `false`: Disallowed tags are HTML-encoded. (e.g., `<script>` becomes `&lt;script&gt;`)
   * @default true
   */
  stripIgnoreTag?: boolean;

  /**
   * Enables or disables logging of sanitization activities.
   * @default false
   */
  enableLogging?: boolean;

  /**
   * Specifies the format for logs.
   * - 'simple': Concise log messages.
   * - 'detailed': More verbose logs, including details of the sanitization.
   * @default 'simple'
   */
  logFormat?: "simple" | "detailed";
}

/**
 * Default sanitization configuration.
 */
export const DEFAULT_SANITIZATION_CONFIG: Readonly<SanitizationConfig> = {
  allowedTags: [
    "p",
    "br",
    "b",
    "i",
    "ul",
    "ol",
    "li",
    "span",
    "div",
    "a",
    "img",
  ],
  allowedAttributes: ["id", "class", "style", "href", "target", "src"],
  stripIgnoreTag: false,
  enableLogging: false,
  logFormat: "simple",
};
