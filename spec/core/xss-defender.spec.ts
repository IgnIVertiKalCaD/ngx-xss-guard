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

  describe("Llama 3.2 tests XssDefender", () => {
    it("удаляет классический скрипт", () => {
      const payload = "<script>alert(1)</script>";
      expect(defender.hasXssRisks(payload)).toBeTrue();
    });

    it("обфусцированный регистром JS", () => {
      const payload = "<JaVaScRiPt>alert(2)</JAvAsCrIpT>";
      expect(defender.hasXssRisks(payload)).toBeTrue();
    });

    it("скрытая вставка с комментариями", () => {
      const payload = "<scr<!-- -->ipt>alert(3)</scr" + "ipt>";
      expect(defender.hasXssRisks(payload)).toBeTrue();
    });

    it("использует Unicode-экранирование", () => {
      const payload = "<\u0073\u0063\u0072\u0069\u0070\u0074>alert(4)</script>";
      expect(defender.hasXssRisks(payload)).toBeTrue();
    });

    it("HTML-комментарий внутри тега", () => {
      const payload = "<scr<!-- -->ipt>alert(5)</script>";
      expect(defender.hasXssRisks(payload)).toBeTrue();
    });

    it("hasXssRisks: простой <script> тег", () => {
      const payload = '<script>alert("XSS")</script>';
      expect(defender.hasXssRisks(payload)).toBeTrue();
    });

    it("hasXssRisks: <ScRiPt> смешанный регистр", () => {
      const payload = "текст <ScRiPt>alert(1)</ScRiPt> еще текст";
      expect(defender.hasXssRisks(payload)).toBeTrue();
    });

    it("hasXssRisks: javascript: URL, комментарий, регистр", () => {
      const payload = '<a hReF="jAvAsCrIpT:alert(1)">link</a>';
      expect(defender.hasXssRisks(payload)).toBeTrue();
    });

    it("hasXssRisks: style expression() с табуляцией", () => {
      const payload = '<div style="width: exPreSsIoN(\talert(1))"></div>';
      expect(defender.hasXssRisks(payload)).toBeTrue();
    });

    it("hasXssRisks: svg onload с hex и Unicode", () => {
      const payload = "<s\u0076g/onload=&#" + "x61;lert(1)>"; // 'alert'
      expect(defender.hasXssRisks(payload)).toBeTrue();
    });

    it("hasXssRisks: iframe srcdoc с внутренним скриптом", () => {
      const payload = '<IFRAME SRCdoc="<img src=1 oNErRoR=alert(1)>"></IFRAME>';
      expect(defender.hasXssRisks(payload)).toBeTrue();
    });

    it("hasXssRisks: data: URL с HTML+JS, регистр", () => {
      const payload =
        'Href="daTa:text/html;base64,PHNjcmlwdD5hbGVydCgiSGVsbG8iKTwvc2NyaXB0Pg=="';
      expect(defender.hasXssRisks(payload)).toBeTrue();
    });

    it("hasXssRisks: onerror с неразрывным пробелом", () => {
      const payload = '<img src="x" onerror\u00A0="alert(1)">'; // \u00A0 is NBSP
      expect(defender.hasXssRisks(payload)).toBeTrue();
    });

    it("sanitizeString: удаляет <script> смешанный регистр", () => {
      const payload = "Начало <ScR\u0049pT>alert(1)</ScR\u0049pT> Конец";
      // <script> удаляется DANGEROUS_PATTERNS
      expect(defender.sanitizeString(payload)).toBe("Начало  Конец");
    });

    it("sanitizeString: img onerror, Unicode в событии", () => {
      const payload = '<img src="x" o\u006Eerror="alert(1)">';
      // onerror атрибут удаляется DANGEROUS_PATTERNS или фильтром атрибутов
      // 'img' и 'src' разрешены по умолчанию.
      expect(defender.sanitizeString(payload)).toBe('<img src="x">');
    });

    it("sanitizeString: a href javascript: URL, комментарий", () => {
      const payload = '<a hrEf="jaVaScRiPt:alert(1)">Test</a>';
      // javascript: удаляется из href DANGEROUS_PATTERNS
      // 'a' и 'href' разрешены.
      expect(defender.sanitizeString(payload)).toBe('<a href="">Test</a>');
    });

    it("sanitizeString: style expression() с %20 и регистром", () => {
      const payload = '<div style="color:%20ExpReSsIoN(alert(1))">Text</div>';
      expect(defender.sanitizeString(payload)).toBe(
        '<div style="color:">Text</div>',
      );
    });

    it("sanitizeString: svg onload, hex в теге", () => {
      const payload = '<s&#x76;g onload="alert(1)"></s&#x76;g>';
      // onload удаляется DANGEROUS_PATTERNS.
      // <svg> не разрешен -> кодируется.
      expect(defender.sanitizeString(payload)).toBe("&lt;svg &gt;&lt;/svg&gt;");
    });

    it("sanitizeString: iframe src с TAB и JS URL", () => {
      const payload = '<IFRAME\tsrc="javascript:alert(1)"></IFRAME>';
      // javascript: удаляется DANGEROUS_PATTERNS.
      // <iframe> не разрешен -> кодируется.
      expect(defender.sanitizeString(payload)).toBe(
        '&lt;IFRAME\tsrc=""&gt;&lt;/IFRAME&gt;',
      );
    });

    it("sanitizeString: data: URL в href, Unicode в протоколе", () => {
      const payload =
        '<a hRef="d\u0061Ta:text/html,<script>alert(1)</script>">X</a>';
      // data:text/html со <script> удаляется из href DANGEROUS_PATTERNS
      expect(defender.sanitizeString(payload)).toBe('<a href="">X</a>');
    });

    it("sanitizeString: текст и <ScRiPt> %20 кодирование", () => {
      const payload = "SafeText <ScRiPt%20sRc='x.js'></ScRiPt%20> End";
      // <script> удаляется DANGEROUS_PATTERNS
      expect(defender.sanitizeString(payload)).toBe("SafeText  End");
    });

    it("sanitizeString: img OnMousEOVER с HTML-комментарием", () => {
      const payload = '<img src="ok.png" OnMousEOVER="alert(1)">';
      // OnMousEOVER удаляется DANGEROUS_PATTERNS или фильтром атрибутов.
      expect(defender.sanitizeString(payload)).toBe('<img src="ok.png">');
    });

    it("sanitizeString: ссылка с URL Unicode обфускацией JS", () => {
      const payload =
        '<a hRef="\u006a\u0061\u0076\u0061script:alert(1)">Link</a>';
      // javascript: удаляется DANGEROUS_PATTERNS
      expect(defender.sanitizeString(payload)).toBe('<a href="">Link</a>');
    });
  });
});
