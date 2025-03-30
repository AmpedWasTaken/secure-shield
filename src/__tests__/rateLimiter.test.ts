import { RateLimiter } from '../utils/rateLimiter';

describe('RateLimiter', () => {
  let rateLimiter: RateLimiter;
  const config = {
    windowMs: 1000,
    maxRequests: 2
  };

  beforeEach(() => {
    rateLimiter = new RateLimiter(config);
  });

  it('should allow requests within limit', () => {
    const clientId = '127.0.0.1';
    expect(rateLimiter.checkLimit(clientId)).toBe(true);
    expect(rateLimiter.checkLimit(clientId)).toBe(true);
  });

  it('should block requests over limit', () => {
    const clientId = '127.0.0.1';
    expect(rateLimiter.checkLimit(clientId)).toBe(true);
    expect(rateLimiter.checkLimit(clientId)).toBe(true);
    expect(rateLimiter.checkLimit(clientId)).toBe(false);
  });

  it('should reset after window expires', async () => {
    const clientId = '127.0.0.1';
    expect(rateLimiter.checkLimit(clientId)).toBe(true);
    expect(rateLimiter.checkLimit(clientId)).toBe(true);
    expect(rateLimiter.checkLimit(clientId)).toBe(false);
    
    await new Promise(resolve => setTimeout(resolve, config.windowMs));
    expect(rateLimiter.checkLimit(clientId)).toBe(true);
  });

  it('should return correct limit info', () => {
    const clientId = '127.0.0.1';
    const info = rateLimiter.getLimitInfo(clientId);
    
    expect(info).toHaveProperty('remaining');
    expect(info).toHaveProperty('reset');
    expect(info).toHaveProperty('limit');
    expect(info.limit).toBe(config.maxRequests);
  });
}); 