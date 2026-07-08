import type { PermissionMatrix, User, OwnedResource } from './types.js';
import { checkPermission, checkPermissionWithResource } from './checker.js';

/**
 * Middleware factory - Phase 5
 * 
 * Creates Express-compatible middleware that enforces permissions
 * before route handlers run.
 * 
 * The middleware expects:
 * - req.user to be set by authentication middleware (User object)
 * - For own-scoped routes: req.resource to contain the resource being accessed
 */

export interface RequestWithUser {
  user?: User;
  resource?: OwnedResource;
  params?: Record<string, string>;
  [key: string]: any;
}

export interface Response {
  status: (code: number) => Response;
  json: (body: any) => Response;
  [key: string]: any;
}

export type NextFunction = (error?: any) => void;

/**
 * Create middleware that checks a simple permission (no ownership)
 * 
 * @param matrix - The permission matrix
 * @param action - Required action ('read', 'create', etc.)
 * @param resourceType - Resource type ('articles', 'comments', etc.)
 * 
 * @example
 * app.put('/articles/:id', 
 *   authenticate, // sets req.user
 *   requirePermission(matrix, 'update', 'articles'),
 *   handler
 * );
 */
export function requirePermission(
  matrix: PermissionMatrix,
  action: string,
  resourceType: string
) {
  return function middleware(req: RequestWithUser, res: Response, next: NextFunction): void {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    const allowed = checkPermission(matrix, req.user, action, resourceType);

    if (!allowed) {
      res.status(403).json({
        error: 'Forbidden',
        message: `User does not have permission to ${action} on ${resourceType}`,
      });
      return;
    }

    next();
  };
}

/**
 * Create middleware that checks a permission with ownership
 * 
 * The middleware requires that req.resource is set before it runs.
 * Use a resource loader middleware before this one.
 * 
 * @param matrix - The permission matrix
 * @param action - Required action
 * @param resourceType - Resource type
 * 
 * @example
 * app.put('/articles/:id',
 *   authenticate,
 *   loadArticle, // sets req.resource = { ownerId: article.authorId }
 *   requireOwnPermission(matrix, 'update', 'articles'),
 *   handler
 * );
 */
export function requireOwnPermission(
  matrix: PermissionMatrix,
  action: string,
  resourceType: string
) {
  return function middleware(req: RequestWithUser, res: Response, next: NextFunction): void {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    if (!req.resource) {
      res.status(500).json({ error: 'Resource not loaded for ownership check' });
      return;
    }

    const allowed = checkPermissionWithResource(
      matrix,
      req.user,
      action,
      resourceType,
      req.resource
    );

    if (!allowed) {
      res.status(403).json({
        error: 'Forbidden',
        message: `User does not have permission to ${action} on this ${resourceType}`,
      });
      return;
    }

    next();
  };
}
