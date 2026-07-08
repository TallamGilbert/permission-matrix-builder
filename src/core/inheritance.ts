import type { PermissionMatrix, RolePermissions, ResourceRules } from './types.js';

/**
 * Role Inheritance - Extended Requirements
 * 
 * Allows roles to extend other roles, building a graph of permissions.
 * 
 * DSL addition: a role can have an "extends" property:
 * {
 *   moderator: {
 *     extends: 'editor',  // inherits all editor permissions
 *     articles: ['delete'] // plus its own
 *   }
 * }
 * 
 * Cycle detection happens at configuration time (load time),
 * not at request time.
 */

export interface MatrixConfigWithInheritance {
  roles: Record<string, RoleConfigWithInheritance>;
}

export interface RoleConfigWithInheritance {
  extends?: string | string[];
  [resourceType: string]: any;
}

/**
 * Resolve a role's full permission set by walking the extends chain.
 * Uses depth-first traversal with a visited set to detect cycles.
 * 
 * @param matrixConfig - The raw matrix config (before normalization)
 * @param roleName - The role to resolve
 * @param visited - Set of roles currently in the traversal path (for cycle detection)
 * @param resolved - Cache of already-resolved roles
 * @returns Fully resolved permissions for this role
 */
function resolveRole(
  matrixConfig: Record<string, RoleConfigWithInheritance>,
  roleName: string,
  visited: Set<string>,
  resolved: Map<string, RolePermissions>
): RolePermissions {
  // Cycle detection: if we're already visiting this role, we have a cycle
  if (visited.has(roleName)) {
    const chain = [...visited, roleName].join(' -> ');
    throw new Error(
      `Circular inheritance detected: ${chain}. ` +
      `Role inheritance must form a directed acyclic graph.`
    );
  }

  // Return cached result if already resolved
  if (resolved.has(roleName)) {
    return resolved.get(roleName)!;
  }

  const roleConfig = matrixConfig[roleName];
  if (!roleConfig) {
    throw new Error(`Role "${roleName}" not found in matrix configuration`);
  }

  visited.add(roleName);

  // Start with an empty permission set
  const permissions: RolePermissions = {};

  // First, inherit from parent roles (if any)
  const extendsRoles = roleConfig.extends
    ? (Array.isArray(roleConfig.extends) ? roleConfig.extends : [roleConfig.extends])
    : [];

  for (const parentRole of extendsRoles) {
    const parentPermissions = resolveRole(matrixConfig, parentRole, visited, resolved);
    
    // Merge parent permissions (parent rules come first, child can override)
    for (const [resourceType, rules] of Object.entries(parentPermissions)) {
      if (!permissions[resourceType]) {
        permissions[resourceType] = [];
      }
      permissions[resourceType].push(...rules);
    }
  }

  // Then add this role's own rules (they override inherited ones for same action)
  for (const [key, value] of Object.entries(roleConfig)) {
    if (key === 'extends') continue; // Skip the extends directive
    
    // The rules will be normalized later by the matrix validator
    // For now, store them as-is
    if (!permissions[key]) {
      permissions[key] = [];
    }
    permissions[key].push(...(Array.isArray(value) ? value : [value]));
  }

  visited.delete(roleName);
  resolved.set(roleName, permissions);

  return permissions;
}

/**
 * Resolve all roles with inheritance and return a flat MatrixConfig
 * that the existing validator can process.
 * 
 * This is called BEFORE defineMatrix() validates the matrix.
 * 
 * @param config - Raw matrix config with optional extends
 * @returns Flattened MatrixConfig with inheritance resolved
 */
export function resolveInheritance(
  config: MatrixConfigWithInheritance
): { roles: Record<string, Record<string, any>> } {
  if (!config.roles || typeof config.roles !== 'object') {
    throw new Error('Matrix configuration must contain a "roles" object');
  }

  const resolved = new Map<string, RolePermissions>();
  const flatRoles: Record<string, Record<string, any>> = {};

  for (const roleName of Object.keys(config.roles)) {
    const visited = new Set<string>();
    flatRoles[roleName] = resolveRole(config.roles, roleName, visited, resolved);
  }

  return { roles: flatRoles };
}
