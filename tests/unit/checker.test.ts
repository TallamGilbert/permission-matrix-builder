import { describe, it } from 'node:test';
import assert from 'node:assert';
import { defineMatrix, checkPermission } from '../../src/index.js';
import type { User } from '../../src/index.js';

describe('Decision Engine - Phase 2', () => {
  // Test matrix used across multiple tests
  const matrix = defineMatrix({
    roles: {
      admin: {
        articles: ['create', 'read', 'update', 'delete'],
        comments: '*',
      },
      editor: {
        articles: ['read', 'update'],
        comments: ['read'],
      },
      reader: {
        articles: ['read'],
      },
    },
  });

  describe('REQ-003: Allow decisions with default deny', () => {
    it('allows a user whose role grants the action', () => {
      const user: User = { id: 'user1', roles: ['admin'] };
      assert.strictEqual(checkPermission(matrix, user, 'create', 'articles'), true);
    });

    it('denies a user with no matching rule', () => {
      const user: User = { id: 'user1', roles: ['reader'] };
      assert.strictEqual(checkPermission(matrix, user, 'delete', 'articles'), false);
    });

    it('denies a user with no roles (empty array)', () => {
      const user: User = { id: 'user1', roles: [] };
      assert.strictEqual(checkPermission(matrix, user, 'read', 'articles'), false);
    });

    it('denies an action on a resource type not in the matrix', () => {
      const user: User = { id: 'user1', roles: ['admin'] };
      assert.strictEqual(checkPermission(matrix, user, 'read', 'nonexistent'), false);
    });

    it('denies an action that does not exist for that role', () => {
      const user: User = { id: 'user1', roles: ['editor'] };
      assert.strictEqual(checkPermission(matrix, user, 'delete', 'articles'), false);
    });

    it('does not crash on unknown action/resource type', () => {
      const user: User = { id: 'user1', roles: ['admin'] };
      // Should return false, not throw
      assert.strictEqual(checkPermission(matrix, user, 'fly', 'rockets'), false);
    });
  });

  describe('REQ-004: Multiple roles per user', () => {
    it('allows if at least one role grants the action', () => {
      const user: User = { id: 'user1', roles: ['reader', 'editor'] };
      // reader can only read, editor can read and update
      assert.strictEqual(checkPermission(matrix, user, 'update', 'articles'), true);
    });

    it('accumulates permissions from multiple roles', () => {
      const user: User = { id: 'user1', roles: ['reader', 'admin'] };
      // reader can read, admin can do everything
      assert.strictEqual(checkPermission(matrix, user, 'delete', 'articles'), true);
      assert.strictEqual(checkPermission(matrix, user, 'create', 'articles'), true);
    });

    it('produces same result regardless of role order', () => {
      const user1: User = { id: 'user1', roles: ['reader', 'editor'] };
      const user2: User = { id: 'user2', roles: ['editor', 'reader'] };
      
      const result1 = checkPermission(matrix, user1, 'update', 'articles');
      const result2 = checkPermission(matrix, user2, 'update', 'articles');
      
      assert.strictEqual(result1, result2);
    });

    it('denies if no role grants the action', () => {
      const user: User = { id: 'user1', roles: ['reader', 'editor'] };
      assert.strictEqual(checkPermission(matrix, user, 'delete', 'articles'), false);
    });

    it('second role does not remove access granted by first role', () => {
      // reader has read, editor also has read - combining shouldn't lose read
      const user: User = { id: 'user1', roles: ['reader', 'editor'] };
      assert.strictEqual(checkPermission(matrix, user, 'read', 'articles'), true);
    });

    it('handles non-existent roles gracefully', () => {
      const user: User = { id: 'user1', roles: ['nonexistent', 'reader'] };
      assert.strictEqual(checkPermission(matrix, user, 'read', 'articles'), true);
    });

    it('denies when all roles are non-existent', () => {
      const user: User = { id: 'user1', roles: ['ghost', 'phantom'] };
      assert.strictEqual(checkPermission(matrix, user, 'read', 'articles'), false);
    });
  });

  describe('Wildcard actions (from matrix setup)', () => {
    it('admin wildcard on comments allows any action', () => {
      const user: User = { id: 'user1', roles: ['admin'] };
      assert.strictEqual(checkPermission(matrix, user, 'create', 'comments'), true);
      assert.strictEqual(checkPermission(matrix, user, 'delete', 'comments'), true);
      assert.strictEqual(checkPermission(matrix, user, 'flag', 'comments'), true);
    });
  });
});
