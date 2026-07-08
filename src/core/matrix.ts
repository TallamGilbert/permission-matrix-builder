import type { MatrixConfig, PermissionMatrix, RuleInput, Rule, RolePermissions, ResourceRules } from './types.js';
import { resolveInheritance, type MatrixConfigWithInheritance } from './inheritance.js';

function validateRule(resourceType: string, rule: RuleInput): Rule {
  if (typeof rule === 'string') {
    if (rule.length === 0) {
      throw new Error(`Empty action string in rules for resource "${resourceType}"`);
    }
    return { action: rule, scope: null, deny: false };
  }

  if (typeof rule === 'object' && rule !== null) {
    if (!rule.action || typeof rule.action !== 'string') {
      throw new Error(`Rule for resource "${resourceType}" is missing required "action" string`);
    }
    if (rule.scope !== undefined && rule.scope !== 'own') {
      throw new Error(`Invalid scope "${rule.scope}" for action "${rule.action}" on "${resourceType}". Only "own" scope is supported.`);
    }
    if (rule.deny !== undefined && typeof rule.deny !== 'boolean') {
      throw new Error(`Invalid deny value for action "${rule.action}" on "${resourceType}". Deny must be a boolean.`);
    }
    return { action: rule.action, scope: rule.scope || null, deny: rule.deny || false };
  }

  throw new Error(`Invalid rule format for resource "${resourceType}". Expected string or { action, scope?, deny? } object, got ${typeof rule}`);
}

function validateResourceRules(roleName: string, resourceType: string, rules: string | string[] | RuleInput | RuleInput[]): ResourceRules {
  if (rules === '*') {
    return [{ action: '*', scope: null, deny: false }];
  }
  const ruleArray: RuleInput[] = Array.isArray(rules) ? rules : [rules];
  if (ruleArray.length === 0) {
    throw new Error(`Role "${roleName}" has empty rules array for resource "${resourceType}"`);
  }
  return ruleArray.map((rule) => validateRule(resourceType, rule));
}

function validateRole(roleName: string, roleConfig: Record<string, string | string[] | RuleInput | RuleInput[]>): RolePermissions {
  const resourceTypes = Object.keys(roleConfig);
  if (resourceTypes.length === 0) {
    throw new Error(`Role "${roleName}" has no resource types defined`);
  }
  const normalizedRole: RolePermissions = {};
  for (const resourceType of resourceTypes) {
    normalizedRole[resourceType] = validateResourceRules(roleName, resourceType, roleConfig[resourceType]);
  }
  return normalizedRole;
}

function validateMatrix(matrixConfig: MatrixConfig): PermissionMatrix {
  const roles: Record<string, RolePermissions> = {};
  for (const roleName of Object.keys(matrixConfig.roles)) {
    roles[roleName] = validateRole(roleName, matrixConfig.roles[roleName]);
  }
  return Object.freeze({ roles }) as PermissionMatrix;
}

export function defineMatrix(matrixConfig: MatrixConfig | MatrixConfigWithInheritance): PermissionMatrix {
  try {
    // Null/undefined check FIRST
    if (!matrixConfig || typeof matrixConfig !== 'object') {
      throw new Error('Matrix configuration must be an object');
    }
    if (!matrixConfig.roles || typeof matrixConfig.roles !== 'object') {
      throw new Error('Matrix configuration must contain a "roles" object');
    }
    
    const roleNames = Object.keys(matrixConfig.roles);
    if (roleNames.length === 0) {
      throw new Error('Matrix must define at least one role');
    }

    // Check if any role has "extends" - if so, resolve inheritance first
    const hasInheritance = Object.values(matrixConfig.roles).some(
      (role: any) => role && typeof role === 'object' && role.extends !== undefined
    );

    if (hasInheritance) {
      const flatConfig = resolveInheritance(matrixConfig as MatrixConfigWithInheritance);
      return validateMatrix(flatConfig as MatrixConfig);
    }

    return validateMatrix(matrixConfig as MatrixConfig);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid permission matrix: ${message}`);
  }
}

export function getRoles(matrix: PermissionMatrix): string[] {
  return Object.keys(matrix.roles);
}

export function getResourceTypes(matrix: PermissionMatrix, roleName: string): string[] {
  const role = matrix.roles[roleName];
  if (!role) throw new Error(`Role "${roleName}" not found in matrix`);
  return Object.keys(role);
}

export function getRules(matrix: PermissionMatrix, roleName: string, resourceType: string): ResourceRules {
  const role = matrix.roles[roleName];
  if (!role) throw new Error(`Role "${roleName}" not found in matrix`);
  return role[resourceType] ?? [];
}
