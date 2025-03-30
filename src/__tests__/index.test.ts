import { SecureShield } from '../index';

describe('SecureShield', () => {
    let shield: SecureShield;

    beforeEach(() => {
        shield = new SecureShield();
    });

    it('should create an instance', () => {
        expect(shield).toBeDefined();
        expect(shield).toBeInstanceOf(SecureShield);
    });

    it('should initialize with default options', () => {
        expect(shield).toBeDefined();
        // Add more specific assertions here
    });

    it('should provide middleware function', () => {
        expect(typeof shield.middleware).toBe('function');
    });

    it('should provide utility methods', () => {
        expect(typeof shield.sanitize).toBe('function');
        expect(typeof shield.encrypt).toBe('function');
        expect(typeof shield.decrypt).toBe('function');
        expect(typeof shield.hashPassword).toBe('function');
        expect(typeof shield.verifyPassword).toBe('function');
    });
}); 