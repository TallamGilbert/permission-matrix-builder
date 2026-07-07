import type { PermissionMatrix, User, ResourceRules } from './types.js';

/**
 * Decision Engine - Phase 2
 * 
 * Core permission checking logic:
 * - Default deny: anything not explicitly allowed is denied
 * - Multiple roles: user gets combined permissions from all roles
 * - Order-independent: same roles = same decision regardless of order
 */

/**
 * Check if a specific rule matches the requested action
 * A rule matches if:
 * - The rule's action equals the requested action, OR
 * - The rule's action is a wildcard '*'
 */
function ruleMatchesAction(rule: { action: string }, requestedAction: string): boolean {
  return rule.action === requestedAction || rule.action === '*';
}

/**
 * Get all rules that apply to a given action and resource type
 * across all of a user's roles
 */
function getApplicableRules(
  matrix: PermissionMatrix,
  userRoles: string[],
  resourceType: string,
  action: string
): ResourceRules {
  const applicableRules: ResourceRules = [];

  for (const roleName of userRoles) {
    // Skip roles that don't exist in the matrix (graceful degradation)
    const role = matrix.roles[roleName];
    if (!role) continue;

    // Skip roles that don't have rules for this resource type
    const resourceRules = role[resourceType];
    if (!resourceRules) continue;

    // Filter rules that match this action
    for (const rule of resourceRules) {
      if (ruleMatchesAction(rule, action)) {
        applicableRules.push(rule);
      }
    }
  }

  return applicableRules;
}

/**
 * Core permission check
 * 
 * Given a user (with roles), an action, and a resource type:
 * - Returns true if the user is allowed
 * - Returns false otherwise (default deny)
 * 
 * Precedence rules:
 * 1. If ANY applicable rule is an explicit deny -> DENIED
 * 2. If ANY applicable rule allows (and no denies) -> ALLOWED
 * 3. If no rules match at all -> DENIED (default deny)
 * 
 * @param matrix - The validated permission matrix
 * @param user - The user making the request (with their roles)
 * @param action - The action being attempted ('read', 'create', etc.)
 * @param resourceType - The type of resource ('articles', 'comments', etc.)
 * @returns true if allowed, false if denied
 */
export function checkPermission(
  matrix: PermissionMatrix,
  user: User,
  action: string,
  resourceType: string
): boolean {
  // No roles? Default deny.
  if (!user.roles || user.roles.length === 0) {
    return false;
  }

  // Get all rules that could apply to this request
  const applicableRules = getApplicableRules(matrix, user.roles, resourceType, action);

  // No matching rules at all? Default deny.
  if (applicableRules.length === 0) {
    return false;
  }

  // Check denies first - a single deny overrides everything
  for (const rule of applicableRules) {
    if (rule.deny) {
      return false;
    }
  }

  // No denies found, and we have matching rules? Allow.
  return true;
}
