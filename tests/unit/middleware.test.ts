import { describe, it } from 'node:test';
import assert from 'node:assert';
import { defineMatrix, requirePermission, requireOwnPermission } from '../../src/index.js';
import type { RequestWithUser, Response, NextFunction } from '../../src/index.js';

describe('Phase 5 - Middleware Enforcement', () => {
  const matrix = defineMatrix({
    roles: {
      admin: {
        articles: ['create', 'read', 'update', 'delete'],
      },
      editor: {
        articles: [
          { action: 'read' },
          { action: 'update', scope: 'own' },
          { action: 'delete', deny: true },
        ],
      },
      reader: {
        articles: ['read'],
      },
    },
  });

  function mockReq(overrides: Partial<RequestWithUser> = {}): RequestWithUser {
    return { ...overrides };
  }

  function mockRes(): Response {
    const res: any = {};
    res._statusCode = 200;
    res._body = null;
    res.status = function(code: number) {
      this._statusCode = code;
      return this;
    };
    res.json = function(data: any) {
      this._body = data;
      return this;
    };
    return res as Response;
  }

  describe('requirePermission', () => {
    it('calls next() when user has permission', () => {
      const req = mockReq({ user: { id: 'user1', roles: ['admin'] } });
      const res = mockRes();
      let nextCalled = false;
      const next: NextFunction = () => { nextCalled = true; };

      const middleware = requirePermission(matrix, 'create', 'articles');
      middleware(req, res, next);

      assert.strictEqual(nextCalled, true);
    });

    it('returns 403 when user lacks permission', () => {
      const req = mockReq({ user: { id: 'user1', roles: ['reader'] } });
      const res: any = mockRes();
      let nextCalled = false;
      const next: NextFunction = () => { nextCalled = true; };

      const middleware = requirePermission(matrix, 'delete', 'articles');
      middleware(req, res, next);

      assert.strictEqual(nextCalled, false);
      assert.strictEqual(res._statusCode, 403);
      assert.ok(res._body.error);
    });

    it('returns 401 when user is not set (no auth)', () => {
      const req = mockReq();
      const res: any = mockRes();
      let nextCalled = false;
      const next: NextFunction = () => { nextCalled = true; };

      const middleware = requirePermission(matrix, 'read', 'articles');
      middleware(req, res, next);

      assert.strictEqual(nextCalled, false);
      assert.strictEqual(res._statusCode, 401);
    });

    it('handler never runs on denied request', () => {
      const req = mockReq({ user: { id: 'user1', roles: [] } });
      const res = mockRes();
      let nextCalled = false;
      const next: NextFunction = () => { nextCalled = true; };

      const middleware = requirePermission(matrix, 'read', 'articles');
      middleware(req, res, next);

      assert.strictEqual(nextCalled, false);
    });
  });

  describe('requireOwnPermission', () => {
    it('allows when user owns the resource', () => {
      const req = mockReq({
        user: { id: 'user1', roles: ['editor'] },
        resource: { ownerId: 'user1' },
      });
      const res = mockRes();
      let nextCalled = false;
      const next: NextFunction = () => { nextCalled = true; };

      const middleware = requireOwnPermission(matrix, 'update', 'articles');
      middleware(req, res, next);

      assert.strictEqual(nextCalled, true);
    });

    it('returns 403 when user does not own the resource', () => {
      const req = mockReq({
        user: { id: 'user1', roles: ['editor'] },
        resource: { ownerId: 'user2' },
      });
      const res: any = mockRes();
      let nextCalled = false;
      const next: NextFunction = () => { nextCalled = true; };

      const middleware = requireOwnPermission(matrix, 'update', 'articles');
      middleware(req, res, next);

      assert.strictEqual(nextCalled, false);
      assert.strictEqual(res._statusCode, 403);
    });

    it('returns 500 when resource is not loaded', () => {
      const req = mockReq({
        user: { id: 'user1', roles: ['editor'] },
      });
      const res: any = mockRes();
      let nextCalled = false;
      const next: NextFunction = () => { nextCalled = true; };

      const middleware = requireOwnPermission(matrix, 'update', 'articles');
      middleware(req, res, next);

      assert.strictEqual(nextCalled, false);
      assert.strictEqual(res._statusCode, 500);
    });

    it('returns 401 when user is not authenticated', () => {
      const req = mockReq({
        resource: { ownerId: 'user1' },
      });
      const res: any = mockRes();
      let nextCalled = false;
      const next: NextFunction = () => { nextCalled = true; };

      const middleware = requireOwnPermission(matrix, 'update', 'articles');
      middleware(req, res, next);

      assert.strictEqual(nextCalled, false);
      assert.strictEqual(res._statusCode, 401);
    });
  });
});
