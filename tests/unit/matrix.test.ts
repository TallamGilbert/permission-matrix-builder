import { describe, it } from 'node:test';
import assert from 'node:assert';
import { defineMatrix, getRoles, getResourceTypes, getRules } from '../../src/index.js';

describe('Matrix DSL - Phase 1', () => {
  describe('defineMatrix - Valid configurations', () => {
    it('accepts simple string rules', () => {
      const matrix = defineMatrix({
        roles: { admin: { articles: ['create', 'read', 'update', 'delete'] } }
      });
      assert.ok(matrix.roles.admin);
      assert.strictEqual(matrix.roles.admin.articles.length, 4);
    });

    it('accepts wildcard rules', () => {
      const matrix = defineMatrix({
        roles: { admin: { articles: '*' } }
      });
      assert.deepStrictEqual(matrix.roles.admin.articles, [
        { action: '*', scope: null, deny: false }
      ]);
    });

    it('accepts object rules with scope', () => {
      const matrix = defineMatrix({
        roles: {
          editor: {
            articles: [
              { action: 'read' },
              { action: 'update', scope: 'own' }
            ]
          }
        }
      });
      assert.strictEqual(matrix.roles.editor.articles[1].scope, 'own');
    });

    it('accepts deny rules', () => {
      const matrix = defineMatrix({
        roles: {
          editor: {
            articles: [
              { action: 'delete', deny: true }
            ]
          }
        }
      });
      assert.strictEqual(matrix.roles.editor.articles[0].deny, true);
    });

    it('accepts mixed rule formats', () => {
      const matrix = defineMatrix({
        roles: {
          moderator: {
            posts: [
              'read',
              { action: 'update', scope: 'own' },
              { action: 'delete', deny: true }
            ]
          }
        }
      });
      assert.strictEqual(matrix.roles.moderator.posts.length, 3);
    });
  });

  describe('defineMatrix - Validation errors', () => {
    it('rejects missing roles', () => {
      assert.throws(() => defineMatrix({} as any), /must contain a "roles" object/);
    });

    it('rejects empty roles', () => {
      assert.throws(() => defineMatrix({ roles: {} }), /must define at least one role/);
    });

    it('rejects null config', () => {
      assert.throws(() => defineMatrix(null as any), /must be an object/);
    });

    it('rejects invalid rule type', () => {
      assert.throws(
        () => defineMatrix({ roles: { admin: { articles: [123 as any] } } }),
        /Invalid rule format/
      );
    });

    it('rejects rule without action', () => {
      assert.throws(
        () => defineMatrix({ roles: { admin: { articles: [{ scope: 'own' } as any] } } }),
        /missing required "action"/
      );
    });

    it('rejects invalid scope', () => {
      assert.throws(
        () => defineMatrix({ roles: { admin: { articles: [{ action: 'read', scope: 'any' as any }] } } }),
        /Invalid scope/
      );
    });
  });

  describe('Matrix queries', () => {
    const matrix = defineMatrix({
      roles: {
        admin: {
          articles: ['create', 'read'],
          comments: '*'
        },
        editor: {
          articles: [{ action: 'read' }]
        }
      }
    });

    it('getRoles returns all roles', () => {
      assert.deepStrictEqual(getRoles(matrix), ['admin', 'editor']);
    });

    it('getResourceTypes returns resource types', () => {
      assert.deepStrictEqual(getResourceTypes(matrix, 'admin'), ['articles', 'comments']);
    });

    it('getRules returns rules', () => {
      assert.strictEqual(getRules(matrix, 'admin', 'articles').length, 2);
    });

    it('getRules returns empty array for unknown resource', () => {
      assert.deepStrictEqual(getRules(matrix, 'admin', 'unknown'), []);
    });

    it('throws for unknown role', () => {
      assert.throws(() => getResourceTypes(matrix, 'unknown'), /not found in matrix/);
    });
  });
});
