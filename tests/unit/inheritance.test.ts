import { describe, it } from 'node:test';
import assert from 'node:assert';
import { defineMatrix, checkPermission, checkPermissionWithResource } from '../../src/index.js';
import type { User } from '../../src/index.js';

describe('Phase 6 Extended - Role Inheritance', () => {
  describe('Basic inheritance', () => {
    const matrix = defineMatrix({
      roles: {
        reader: {
          articles: ['read'],
        },
        editor: {
          extends: 'reader',
          articles: ['update'],
        },
        admin: {
          extends: 'editor',
          articles: ['delete'],
        },
      },
    } as any);

    it('child role inherits parent permissions', () => {
      const user: User = { id: 'user1', roles: ['editor'] };
      assert.strictEqual(checkPermission(matrix, user, 'read', 'articles'), true);
      assert.strictEqual(checkPermission(matrix, user, 'update', 'articles'), true);
    });

    it('child role does not have parent-only permissions reversed', () => {
      const user: User = { id: 'user1', roles: ['reader'] };
      assert.strictEqual(checkPermission(matrix, user, 'read', 'articles'), true);
      assert.strictEqual(checkPermission(matrix, user, 'update', 'articles'), false);
    });

    it('multi-level inheritance works (grandchild)', () => {
      const user: User = { id: 'user1', roles: ['admin'] };
      assert.strictEqual(checkPermission(matrix, user, 'read', 'articles'), true);
      assert.strictEqual(checkPermission(matrix, user, 'update', 'articles'), true);
      assert.strictEqual(checkPermission(matrix, user, 'delete', 'articles'), true);
    });

    it('inherited deny rules still win', () => {
      const matrix2 = defineMatrix({
        roles: {
          base: {
            articles: [{ action: 'delete', deny: true }],
          },
          moderator: {
            extends: 'base',
            articles: ['read', 'update'],
          },
        },
      } as any);

      const user: User = { id: 'user1', roles: ['moderator'] };
      assert.strictEqual(checkPermission(matrix2, user, 'read', 'articles'), true);
      assert.strictEqual(checkPermission(matrix2, user, 'update', 'articles'), true);
      assert.strictEqual(checkPermission(matrix2, user, 'delete', 'articles'), false);
    });
  });

  describe('Multiple inheritance', () => {
    const matrix = defineMatrix({
      roles: {
        reader: {
          articles: ['read'],
        },
        commenter: {
          comments: ['create', 'read'],
        },
        powerUser: {
          extends: ['reader', 'commenter'],
          articles: ['update'],
        },
      },
    } as any);

    it('inherits from multiple parents', () => {
      const user: User = { id: 'user1', roles: ['powerUser'] };
      assert.strictEqual(checkPermission(matrix, user, 'read', 'articles'), true);
      assert.strictEqual(checkPermission(matrix, user, 'update', 'articles'), true);
      assert.strictEqual(checkPermission(matrix, user, 'create', 'comments'), true);
      assert.strictEqual(checkPermission(matrix, user, 'read', 'comments'), true);
    });
  });

  describe('Cycle detection', () => {
    it('rejects direct cycle (A extends A)', () => {
      assert.throws(
        () =>
          defineMatrix({
            roles: {
              admin: {
                extends: 'admin',
                articles: ['read'],
              },
            },
          } as any),
        /Circular inheritance detected/
      );
    });

    it('rejects indirect cycle (A -> B -> A)', () => {
      assert.throws(
        () =>
          defineMatrix({
            roles: {
              editor: {
                extends: 'moderator',
                articles: ['update'],
              },
              moderator: {
                extends: 'editor',
                articles: ['read'],
              },
            },
          } as any),
        /Circular inheritance detected/
      );
    });

    it('rejects three-way cycle (A -> B -> C -> A)', () => {
      assert.throws(
        () =>
          defineMatrix({
            roles: {
              admin: {
                extends: 'editor',
                articles: ['delete'],
              },
              editor: {
                extends: 'moderator',
                articles: ['update'],
              },
              moderator: {
                extends: 'admin',
                articles: ['read'],
              },
            },
          } as any),
        /Circular inheritance detected/
      );
    });

    it('cycle detection happens at configuration time', () => {
      let configTimeError = false;
      try {
        defineMatrix({
          roles: {
            a: { extends: 'b', articles: ['read'] },
            b: { extends: 'a', articles: ['read'] },
          },
        } as any);
      } catch (e: any) {
        configTimeError = e.message.includes('Circular inheritance');
      }
      assert.strictEqual(configTimeError, true);
    });
  });

  describe('Inheritance edge cases', () => {
    it('extends non-existent role throws error', () => {
      assert.throws(
        () =>
          defineMatrix({
            roles: {
              admin: {
                extends: 'nonexistent',
                articles: ['read'],
              },
            },
          } as any),
        /not found/
      );
    });

    it('inherited own-scoped rules work correctly', () => {
      const matrix = defineMatrix({
        roles: {
          base: {
            articles: [{ action: 'update', scope: 'own' }],
          },
          editor: {
            extends: 'base',
            articles: ['read'],
          },
        },
      } as any);

      const user: User = { id: 'user1', roles: ['editor'] };
      assert.strictEqual(
        checkPermissionWithResource(matrix, user, 'update', 'articles', { ownerId: 'user1' }),
        true
      );
      assert.strictEqual(
        checkPermissionWithResource(matrix, user, 'update', 'articles', { ownerId: 'user2' }),
        false
      );
    });
  });
});
