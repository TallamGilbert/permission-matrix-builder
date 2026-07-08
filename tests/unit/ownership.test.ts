import { describe, it } from 'node:test';
import assert from 'node:assert';
import { defineMatrix, checkPermission, checkPermissionWithResource } from '../../src/index.js';
import type { User, OwnedResource } from '../../src/index.js';

describe('Phase 4 - Ownership Checks', () => {
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

  describe('REQ-007: Per-row ownership checks', () => {
    it('allows own-scoped action on own resource', () => {
      const user: User = { id: 'user1', roles: ['editor'] };
      const resource: OwnedResource = { ownerId: 'user1' };
      assert.strictEqual(
        checkPermissionWithResource(matrix, user, 'update', 'articles', resource),
        true
      );
    });

    it('denies own-scoped action on someone else\'s resource', () => {
      const user: User = { id: 'user1', roles: ['editor'] };
      const resource: OwnedResource = { ownerId: 'user2' };
      assert.strictEqual(
        checkPermissionWithResource(matrix, user, 'update', 'articles', resource),
        false
      );
    });

    it('ignores caller-supplied ownership claim', () => {
      const user: User = { id: 'user1', roles: ['editor'] };
      const resource: OwnedResource = { ownerId: 'user2' };
      assert.strictEqual(
        checkPermissionWithResource(matrix, user, 'update', 'articles', resource),
        false
      );
    });

    it('global rules are unaffected by ownership', () => {
      const user: User = { id: 'user1', roles: ['reader'] };
      const resource: OwnedResource = { ownerId: 'user2' };
      assert.strictEqual(
        checkPermissionWithResource(matrix, user, 'read', 'articles', resource),
        true
      );
    });

    it('admin can act on any resource regardless of ownership', () => {
      const user: User = { id: 'user1', roles: ['admin'] };
      const resource: OwnedResource = { ownerId: 'user2' };
      assert.strictEqual(
        checkPermissionWithResource(matrix, user, 'update', 'articles', resource),
        true
      );
      assert.strictEqual(
        checkPermissionWithResource(matrix, user, 'delete', 'articles', resource),
        true
      );
    });

    it('deny still overrides own-scoped rules', () => {
      const user: User = { id: 'user1', roles: ['editor'] };
      const resource: OwnedResource = { ownerId: 'user1' };
      assert.strictEqual(
        checkPermissionWithResource(matrix, user, 'update', 'articles', resource),
        true
      );
      assert.strictEqual(
        checkPermissionWithResource(matrix, user, 'delete', 'articles', resource),
        false
      );
    });

    it('checkPermission without resource still works', () => {
      const user: User = { id: 'user1', roles: ['reader'] };
      assert.strictEqual(
        checkPermission(matrix, user, 'read', 'articles'),
        true
      );
    });

    it('own-scoped with multiple roles accumulates correctly', () => {
      const user: User = { id: 'user1', roles: ['reader', 'editor'] };
      const ownResource: OwnedResource = { ownerId: 'user1' };
      const otherResource: OwnedResource = { ownerId: 'user2' };
      
      assert.strictEqual(
        checkPermissionWithResource(matrix, user, 'read', 'articles', otherResource),
        true
      );
      assert.strictEqual(
        checkPermissionWithResource(matrix, user, 'update', 'articles', ownResource),
        true
      );
      assert.strictEqual(
        checkPermissionWithResource(matrix, user, 'update', 'articles', otherResource),
        false
      );
    });
  });
});
