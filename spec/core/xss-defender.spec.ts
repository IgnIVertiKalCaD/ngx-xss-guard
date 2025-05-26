import { XssDefender, DEFAULT_SANITIZATION_CONFIG } from "../../src/index"; // Предполагая, что index.ts экспортирует все необходимое

describe("XssDefender", () => {
  let defender: XssDefender;

  beforeEach(() => {
    // Инициализируем XssDefender с конфигурацией по умолчанию перед каждым тестом
    // Отключаем логирование для чистоты вывода тестов
    defender = new XssDefender({
      ...DEFAULT_SANITIZATION_CONFIG,
      enableLogging: false,
    });
  });

  describe("sanitizeString", () => {
    it("should return an empty string for null or undefined input", () => {
      expect(defender.sanitizeString(null)).toBe("");
      expect(defender.sanitizeString(undefined)).toBe("");
    });

    it("should return an empty string for an empty string input", () => {
      expect(defender.sanitizeString("")).toBe("");
    });

    it("should return the same string if it is safe", () => {
      const safeString = "This is a safe string with 漢字 and 123.";
      expect(defender.sanitizeString(safeString)).toBe(safeString);
    });

    it("should remove <script> tags by default", () => {
      const maliciousString = 'Hello <script>alert("XSS")</script> world!';
      const expectedString = "Hello  world!"; // Пробелы могут остаться в зависимости от реализации replace
      expect(defender.sanitizeString(maliciousString)).toBe(expectedString);
    });

    it("should remove <script> tags with attributes", () => {
      const maliciousString =
        'Hello <script type="text/javascript">alert("XSS")</script> world!';
      const expectedString = "Hello  world!";
      expect(defender.sanitizeString(maliciousString)).toBe(expectedString);
    });

    it("should remove on<event> handlers", () => {
      const maliciousString = "<div onclick=\"alert('XSS')\">Click me</div>";
      // По умолчанию, div является разрешенным тегом, но onclick должен быть удален
      // DANGEROUS_PATTERNS удалит 'onclick="alert(\'XSS\')"' целиком
      const expectedString = "<div>Click me</div>"; // Атрибут onclick удален
      expect(defender.sanitizeString(maliciousString)).toBe(expectedString);
    });

    it("should encode disallowed tags if stripIgnoreTag is false", () => {
      defender.setConfig({
        allowedTags: ["p"],
        stripIgnoreTag: false,
        enableLogging: false,
      });
      const htmlString = "<p>Allowed</p><badtag>Disallowed</badtag><img>";
      // <script> и другие DANGEROUS_PATTERNS удаляются до обработки тегов
      const maliciousScript = '<script>alert("no")</script>'; // будет удалено
      const mixedString = `<p>Allowed</p><badtag>Disallowed</badtag><img> ${maliciousScript}`;
      const expectedString =
        "<p>Allowed</p>&lt;badtag&gt;Disallowed&lt;/badtag&gt;&lt;img&gt; ";
      expect(defender.sanitizeString(mixedString)).toBe(expectedString);
    });
  });

  describe("hasXssRisks", () => {
    it("should return false for safe strings", () => {
      expect(defender.hasXssRisks("this is fine")).toBeFalse();
      expect(defender.hasXssRisks("")).toBeFalse();
      expect(defender.hasXssRisks(null)).toBeFalse();
      expect(defender.hasXssRisks(undefined)).toBeFalse();
    });

    it("should return true for strings with <script> tags", () => {
      expect(defender.hasXssRisks("<script>alert('XSS')</script>")).toBeTrue();
    });

    it("should return true for strings with on<event> handlers", () => {
      expect(
        defender.hasXssRisks('<img src="x" onerror="alert(\'XSS\')">'),
      ).toBeTrue();
    });

    it("should return true for strings with javascript: protocol", () => {
      expect(defender.hasXssRisks('href="javascript:alert(1)"')).toBeTrue();
    });

    it("should return true for strings with data: protocol", () => {
      expect(
        defender.hasXssRisks('src="data:text/html;base64,PHNjcmlwdD4="'),
      ).toBeTrue();
    });

    it("should return true for strings with expression() in style", () => {
      expect(
        defender.hasXssRisks("<div style=\"width: expression(alert('XSS'))\">"),
      ).toBeTrue();
    });
  });

  // Можно добавить тесты для sanitizeHtmlForElement, sanitizeObject, checkUrlParams
  // Для sanitizeHtmlForElement потребуются DOM-элементы (можно мокать или использовать jsdom в среде Node)
  // Для sanitizeObject - тесты с различными объектами и массивами
  // Для checkUrlParams - тесты с разными параметрами URL
});
