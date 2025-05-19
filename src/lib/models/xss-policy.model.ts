export enum XSSFilterLevel {
  BASIC = 'basic',
  STRICT = 'strict',
  CUSTOM = 'custom'
}

export interface XSSFilterOptions {
  level: XSSFilterLevel;
  allowedTags?: string[];
  allowedAttributes?: Record<string, string[]>;
  disallowedTags?: string[];
  disallowedAttributes?: Record<string, string[]>;
  enableScriptFiltering?: boolean;
  enableStyleFiltering?: boolean;
  enableUrlFiltering?: boolean;
  customSanitizer?: (value: string) => string;
}
