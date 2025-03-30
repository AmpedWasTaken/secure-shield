import { DefaultInputSanitizer } from '../utils/inputSanitizer';

describe('DefaultInputSanitizer', () => {
  let sanitizer: DefaultInputSanitizer;

  beforeEach(() => {
    sanitizer = new DefaultInputSanitizer();
  });

  describe('sanitize', () => {
    it('should handle string input', () => {
      expect(sanitizer.sanitize('test')).toBe('test');
    });

    it('should handle number input', () => {
      expect(sanitizer.sanitize(123)).toBe('123');
    });

    it('should handle boolean input', () => {
      expect(sanitizer.sanitize(true)).toBe('true');
    });

    it('should handle object input', () => {
      const input = { key: 'value' };
      expect(sanitizer.sanitize(input)).toBe('{"key":"value"}');
    });
  });

  describe('validate', () => {
    it('should validate string input', () => {
      expect(sanitizer.validate('test')).toBe(true);
    });

    it('should validate number input', () => {
      expect(sanitizer.validate(123)).toBe(true);
    });

    it('should validate boolean input', () => {
      expect(sanitizer.validate(true)).toBe(true);
    });

    it('should validate valid object input', () => {
      expect(sanitizer.validate({ key: 'value' })).toBe(true);
    });
  });
}); 