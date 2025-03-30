import { SecureShield } from '../index';
import { Request, Response, NextFunction } from 'express';
import { Socket } from 'net';

describe('SecureShield', () => {
  let shield: SecureShield;

  beforeEach(() => {
    shield = new SecureShield();
  });

  describe('sanitizeInput', () => {
    it('should sanitize string input', () => {
      expect(shield.sanitizeInput('test')).toBe('test');
    });

    it('should sanitize object input', () => {
      const input = { key: 'value' };
      expect(shield.sanitizeInput(input)).toBe('{"key":"value"}');
    });
  });

  describe('middleware', () => {
    let mockReq: Partial<Request>;
    let mockRes: Partial<Response>;
    let mockNext: NextFunction;

    beforeEach(() => {
      mockReq = {
        ip: '127.0.0.1',
        method: 'GET',
        path: '/test',
        headers: {},
        socket: {
          remoteAddress: '127.0.0.1'
        } as Socket
      };
      mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };
      mockNext = jest.fn();
    });

    it('should call next() for valid requests', async () => {
      const middleware = shield.middleware();
      await middleware(mockReq as Request, mockRes as Response, mockNext);
      expect(mockNext).toHaveBeenCalled();
    });
  });
}); 