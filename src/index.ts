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
export { checkPermission } from './core/checker.js';
