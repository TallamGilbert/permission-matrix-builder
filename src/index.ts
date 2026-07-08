export type {
  PermissionMatrix,
  MatrixConfig,
  Rule,
  RuleInput,
  User,
  OwnedResource,
  Scope,
} from './core/types.js';

export { defineMatrix, getRoles, getResourceTypes, getRules } from './core/matrix.js';
export { checkPermission, checkPermissionWithResource } from './core/checker.js';
export { requirePermission, requireOwnPermission } from './core/middleware.js';
export type { RequestWithUser, Response, NextFunction } from './core/middleware.js';
