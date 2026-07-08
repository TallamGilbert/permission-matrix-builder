import type { PermissionMatrix, User, OwnedResource, ResourceRules } from './types.js';

/**
 * Decision Engine - Phase 2-4
 * 
 * Core permission checking with:
 * - Default deny
 * - Multiple roles
 * - Wildcards
 * - Deny precedence
 * - Ownership checks (Phase 4)
 */

function ruleMatchesAction(rule: { action: string }, requestedAction: string): boolean {
  return rule.action === requestedAction || rule.action === '*';
}

function getApplicableRules(
  matrix: PermissionMatrix,
  userRoles: string[],
  resourceType: string,
  action: string
): ResourceRules {
  const applicableRules: ResourceRules = [];

  for (const roleName of userRoles) {
    const role = matrix.roles[roleName];
    if (!role) continue;

    const resourceRules = role[resourceType];
    if (!resourceRules) continue;

    for (const rule of resourceRules) {
      if (ruleMatchesAction(rule, action)) {
        applicableRules.push(rule);
      }
    }
  }

  return applicableRules;
}

/**
 * Core permission check (without ownership)
 * Used when no resource is involved or ownership doesn't apply
 */
export function checkPermission(
  matrix: PermissionMatrix,
  user: User,
  action: string,
  resourceType: string
): boolean {
  if (!user.roles || user.roles.length === 0) {
    return false;
  }

  const applicableRules = getApplicableRules(matrix, user.roles, resourceType, action);

  if (applicableRules.length === 0) {
    return false;
  }

  // Check denies first - a single deny overrides everything
  for (const rule of applicableRules) {
    if (rule.deny) {
      return false;
    }
  }

  return true;
}

/**
 * Permission check with ownership (Phase 4)
 * 
 * For own-scoped rules, the resource's owner must match the user's ID.
 * 
 * Logic:
 * 1. Collect all applicable rules
 * 2. If any deny rule matches -> DENIED (regardless of ownership)
 * 3. If any non-own allow rule matches -> ALLOWED
 * 4. If only own-scoped rules match -> check ownership
 *    - Resource owner === user ID -> ALLOWED
 *    - Resource owner !== user ID -> DENIED
 * 
 * @param matrix - The validated permission matrix
 * @param user - The user making the request
 * @param action - The action being attempted
 * @param resourceType - The type of resource
 * @param resource - The actual resource (must have ownerId for own-scoped checks)
 * @returns true if allowed, false if denied
 */
export function checkPermissionWithResource(
  matrix: PermissionMatrix,
  user: User,
  action: string,
  resourceType: string,
  resource: OwnedResource
): boolean {
  if (!user.roles || user.roles.length === 0) {
    return false;
  }

  const applicableRules = getApplicableRules(matrix, user.roles, resourceType, action);

  if (applicableRules.length === 0) {
    return false;
  }

  // Check denies first - deny always wins
  for (const rule of applicableRules) {
    if (rule.deny) {
      return false;
    }
  }

  // Separate rules into own-scoped and non-own-scoped
  const ownScopedRules = applicableRules.filter(r => r.scope === 'own');
  const globalRules = applicableRules.filter(r => r.scope !== 'own');

  // If any global (non-own) rule allows, it's an automatic allow
  if (globalRules.length > 0) {
    return true;
  }

  // Only own-scoped rules apply - must check ownership
  if (ownScopedRules.length > 0) {
    // Ownership is determined by comparing resource owner to user ID
    // Never trust a caller-supplied claim
    return resource.ownerId === user.id;
  }

  // Shouldn't reach here, but default deny
  return false;
}
