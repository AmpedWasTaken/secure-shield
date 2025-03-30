import { XSSDetector } from '../detectors/xss';

describe('XSSDetector', () => {
  let detector: XSSDetector;

  beforeEach(() => {
    detector = new XSSDetector();
  });

  test('should detect basic XSS attack', () => {
    const input = '<script>alert("xss")</script>';
    const threats = detector.detect(input);
    expect(threats).toHaveLength(1);
    expect(threats[0].type).toBe('XSS');
    expect(threats[0].severity).toBe('HIGH');
  });

  test('should detect event handler XSS attack', () => {
    const input = '<img src="x" onerror="alert(\'xss\')">';
    const threats = detector.detect(input);
    expect(threats.length).toBeGreaterThan(0);
  });

  test('should sanitize malicious input', () => {
    const input = '<script>alert("xss")</script><p>Hello</p>';
    const sanitized = detector.sanitize(input);
    expect(sanitized).toBe('<p>Hello</p>');
  });

  test('should allow whitelisted tags and attributes', () => {
    const detector = new XSSDetector({
      allowedTags: ['p', 'a'],
      allowedAttributes: {
        'a': ['href']
      }
    });
    const input = '<p>Hello <a href="https://example.com">World</a></p><script>alert("xss")</script>';
    const sanitized = detector.sanitize(input);
    expect(sanitized).toBe('<p>Hello <a href="https://example.com">World</a></p>');
  });

  // Add more tests...
}); 