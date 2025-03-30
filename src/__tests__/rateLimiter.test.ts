import { RateLimiter } from '../utils/rateLimiter';
import { Request } from 'express';

describe('RateLimiter', () => {
    let rateLimiter: RateLimiter;

    beforeEach(() => {
        rateLimiter = new RateLimiter({
            windowMs: 1000,
            maxRequests: 2
        });
    });

    afterAll(() => {
        // Clear any remaining intervals
        jest.clearAllTimers();
    });

    test('should allow requests within limit', async () => {
        const mockReq = {
            ip: '127.0.0.1',
            path: '/test',
            connection: {},
            socket: {}
        } as unknown as Request;

        const result1 = await rateLimiter.check(mockReq);
        const result2 = await rateLimiter.check(mockReq);

        expect(result1).toBe(true);
        expect(result2).toBe(true);
    });

    test('should block requests over limit', async () => {
        const mockReq = {
            ip: '127.0.0.1',
            path: '/test',
            connection: {},
            socket: {}
        } as unknown as Request;

        await rateLimiter.check(mockReq);
        await rateLimiter.check(mockReq);
        const result3 = await rateLimiter.check(mockReq);

        expect(result3).toBe(false);
    });
}); 