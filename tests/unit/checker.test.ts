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

// ============================================================
// Phase 3: Wildcards and Deny Precedence
// ============================================================
describe('Phase 3 - Wildcards and Deny Precedence', () => {
  // Matrix specifically designed to test deny vs allow collisions
  const matrix = defineMatrix({
    roles: {
      superadmin: {
        articles: '*',
        comments: '*',
      },
      editor: {
        articles: [
          { action: 'read' },
          { action: 'update', scope: 'own' },
          { action: 'delete', deny: true },
        ],
      },
      moderator: {
        articles: [
          { action: 'read' },
          { action: 'update' },
          { action: 'delete', deny: true },
        ],
      },
      contributor: {
        articles: [
          { action: 'create' },
          { action: 'read' },
        ],
      },
      banned: {
        articles: [{ action: '*', deny: true }],
      },
    },
  });

  describe('REQ-005: Wildcard actions', () => {
    it('wildcard grants all actions on a resource type', () => {
      const user: User = { id: 'user1', roles: ['superadmin'] };
      assert.strictEqual(checkPermission(matrix, user, 'read', 'articles'), true);
      assert.strictEqual(checkPermission(matrix, user, 'create', 'articles'), true);
      assert.strictEqual(checkPermission(matrix, user, 'update', 'articles'), true);
      assert.strictEqual(checkPermission(matrix, user, 'delete', 'articles'), true);
    });

    it('wildcard grants actions never individually named', () => {
      const user: User = { id: 'user1', roles: ['superadmin'] };
      assert.strictEqual(checkPermission(matrix, user, 'publish', 'articles'), true);
      assert.strictEqual(checkPermission(matrix, user, 'archive', 'articles'), true);
      assert.strictEqual(checkPermission(matrix, user, 'export', 'comments'), true);
    });

    it('wildcard and specific rules coexist in one matrix', () => {
      const user: User = { id: 'user1', roles: ['superadmin'] };
      // superadmin has wildcard, editor has specific rules - both work
      assert.strictEqual(checkPermission(matrix, user, 'read', 'articles'), true);
      
      const editorUser: User = { id: 'user2', roles: ['editor'] };
      assert.strictEqual(checkPermission(matrix, editorUser, 'read', 'articles'), true);
    });
  });

  describe('REQ-006: Deny rules override allows', () => {
    it('explicit deny blocks even when another rule allows', () => {
      const user: User = { id: 'user1', roles: ['moderator'] };
      // moderator can update but is explicitly denied delete
      assert.strictEqual(checkPermission(matrix, user, 'update', 'articles'), true);
      assert.strictEqual(checkPermission(matrix, user, 'delete', 'articles'), false);
    });

    it('deny beats a wildcard allow', () => {
      const user: User = { id: 'user1', roles: ['superadmin', 'editor'] };
      // superadmin has wildcard allow, editor has explicit deny on delete
      assert.strictEqual(checkPermission(matrix, user, 'delete', 'articles'), false);
    });

    it('deny wins regardless of which role carries the deny', () => {
      const user1: User = { id: 'user1', roles: ['editor', 'superadmin'] };
      const user2: User = { id: 'user2', roles: ['superadmin', 'editor'] };
      // Order shouldn't matter - deny always wins
      assert.strictEqual(checkPermission(matrix, user1, 'delete', 'articles'), false);
      assert.strictEqual(checkPermission(matrix, user2, 'delete', 'articles'), false);
    });

    it('deny wins regardless of rule declaration order in matrix', () => {
      // editor declares delete deny - it wins even though superadmin has wildcard
      const user: User = { id: 'user1', roles: ['superadmin', 'editor'] };
      assert.strictEqual(checkPermission(matrix, user, 'delete', 'articles'), false);
    });

    it('wildcard deny blocks everything on a resource', () => {
      const user: User = { id: 'user1', roles: ['banned'] };
      assert.strictEqual(checkPermission(matrix, user, 'read', 'articles'), false);
      assert.strictEqual(checkPermission(matrix, user, 'create', 'articles'), false);
      assert.strictEqual(checkPermission(matrix, user, 'anything', 'articles'), false);
    });

    it('wildcard deny overridden by nothing - even with superadmin', () => {
      const user: User = { id: 'user1', roles: ['banned', 'superadmin'] };
      // banned has wildcard deny on articles, superadmin has wildcard allow
      // deny must win
      assert.strictEqual(checkPermission(matrix, user, 'read', 'articles'), false);
      assert.strictEqual(checkPermission(matrix, user, 'create', 'articles'), false);
      assert.strictEqual(checkPermission(matrix, user, 'update', 'articles'), false);
    });
  });
});
