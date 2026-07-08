# Permission Matrix Builder

A reusable RBAC (Role-Based Access Control) library that centralizes permission declaration and enforcement for Node.js applications. Declare your entire permission matrix in one place and enforce it everywhere.

## What This Library Does

- **Centralized permissions** — define all roles, actions, and resource types in a single matrix
- **Default deny** — anything not explicitly allowed is denied
- **Deny precedence** — an explicit deny always wins, even over wildcards
- **Multiple roles** — users can hold multiple roles; permissions accumulate
- **Wildcards** — grant all actions on a resource type with `*`
- **Ownership checks** — allow users to act on their own resources only
- **Role inheritance** — roles can extend other roles, with cycle detection
- **Middleware** — enforce permissions at the middleware layer, before handlers run

---

## Installation

```bash
npm install permission-matrix-builder
```

No configuration required. No external dependencies. Import and define your matrix.

## Running Tests

```bash
npm test
```

---

## TypeScript Types

The library is written in TypeScript. These are the core types:

```typescript
interface User {
  id: string;
  roles: string[];
}

interface Resource {
  ownerId: string; // compared against user.id for ownership checks
}

type Action = string;
type ResourceType = string;

interface RuleObject {
  action: Action;
  scope?: "own"; // restrict to resources the user owns
  deny?: true; // explicitly block this action
}

type RuleEntry = Action | RuleObject;

interface RoleDefinition {
  extends?: string | string[]; // inherit from one or more roles
  [resourceType: ResourceType]: "*" | RuleEntry[] | string | string[];
}

interface MatrixDefinition {
  roles: Record<string, RoleDefinition>;
}
```

---

## Defining the Matrix

The permission matrix is declared as a JavaScript/TypeScript object passed to `defineMatrix()`.

### Basic Structure

```typescript
import { defineMatrix } from "permission-matrix-builder";

const matrix = defineMatrix({
  roles: {
    roleName: {
      resourceType: ["action1", "action2"],
      anotherResource: "*",
    },
  },
});
```

### Rule Formats

**String rules** — simple action names:

```typescript
articles: ["create", "read", "update", "delete"];
```

**Wildcard** — grants all actions on a resource type:

```typescript
articles: "*";
```

**Object rules** — with optional scope and/or deny:

```typescript
articles: [
  { action: "read" }, // basic allow
  { action: "update", scope: "own" }, // own-resource only
  { action: "delete", deny: true }, // explicit deny
];
```

### Complete Example

```typescript
import { defineMatrix } from "permission-matrix-builder";

const matrix = defineMatrix({
  roles: {
    admin: {
      articles: "*", // all actions on articles
      comments: "*", // all actions on comments
    },
    editor: {
      articles: [
        { action: "read" },
        { action: "update", scope: "own" },
        { action: "delete", deny: true },
      ],
    },
    reader: {
      articles: ["read"],
      comments: ["read"],
    },
  },
});
```

---

## Checking a Permission

Use `checkPermission()` for imperative checks in application logic:

```typescript
import { defineMatrix, checkPermission } from "permission-matrix-builder";

const matrix = defineMatrix({
  /* ... */
});

const user: User = { id: "user-1", roles: ["editor"] };

if (checkPermission(matrix, user, "update", "articles")) {
  // allowed — proceed
} else {
  // denied
}
```

---

## Middleware

Use `requirePermission()` and `requireOwnPermission()` to enforce permissions at the route layer, before handlers run.

### Contracts

For middleware to work, your upstream middleware must set the correct shape on the request object:

- `authenticate` must set `req.user = { id: string, roles: string[] }`
- `loadResource` must set `req.resource = { ownerId: string }` (required for ownership checks only)

### Simple Permission Check

```typescript
import { requirePermission } from "permission-matrix-builder";

app.put(
  "/articles/:id",
  authenticate, // sets req.user
  requirePermission(matrix, "update", "articles"), // checks permission
  handler,
);
```

### Ownership Check

```typescript
import { requireOwnPermission } from "permission-matrix-builder";

app.put(
  "/articles/:id",
  authenticate, // sets req.user
  loadArticle, // sets req.resource = { ownerId }
  requireOwnPermission(matrix, "update", "articles"), // checks ownership
  handler,
);
```

Ownership is determined by comparing `resource.ownerId` to `user.id`. The caller cannot assert ownership — it always comes from the loaded resource.

### `checkPermission` vs `requirePermission`

|          | `checkPermission`                       | `requirePermission`               |
| -------- | --------------------------------------- | --------------------------------- |
| Use case | Imperative logic, conditional branching | Route middleware                  |
| Returns  | `boolean`                               | `(req, res, next) => void`        |
| On deny  | Returns `false`                         | Calls `next()` with a `403` error |

---

## Multiple Roles

Users can hold multiple roles. Permissions accumulate across all roles:

```typescript
const user: User = { id: "user-1", roles: ["reader", "editor"] };

// Gets read from reader + update (own) from editor
checkPermission(matrix, user, "update", "articles"); // true
```

The order of roles does not affect the result.

---

## Wildcard Actions

Use `*` to grant all actions on a resource type:

```typescript
admin: {
  articles: "*"; // admin can do anything on articles
}
```

Wildcards allow actions that were never individually named in the matrix.

---

## Deny Rules and Precedence

An explicit deny always wins. This is the fundamental precedence rule:

- Deny beats allow
- Deny beats wildcard allow
- Deny wins regardless of which role carries it
- Deny wins regardless of declaration order

```typescript
editor: {
  articles: [
    { action: "delete", deny: true }, // editor can never delete
  ];
}
```

Even if another role grants `delete`, the deny wins.

---

## Ownership Checks

Own-scoped rules restrict actions to resources the user owns:

```typescript
editor: {
  articles: [
    { action: "update", scope: "own" }, // only own articles
  ];
}
```

Ownership is determined by comparing `resource.ownerId` to `user.id`. The caller cannot assert ownership — it comes from the actual resource object set by your `loadResource` middleware.

---

## Role Inheritance

Roles can extend other roles using the `extends` property:

```typescript
const matrix = defineMatrix({
  roles: {
    reader: {
      articles: ["read"],
    },
    editor: {
      extends: "reader", // inherits read from reader
      articles: ["update"], // adds update
    },
    admin: {
      extends: ["editor"], // can extend multiple roles
      articles: ["delete"], // adds delete
    },
  },
});
```

### Multiple Inheritance

A role can extend multiple parent roles:

```typescript
powerUser: {
  extends: ['reader', 'commenter'],
  articles: ['update'],
}
```

### Cycle Detection

Circular inheritance is detected at configuration time when `defineMatrix()` is called, not at request time:

```typescript
// This throws immediately:
defineMatrix({
  roles: {
    a: { extends: "b", articles: ["read"] },
    b: { extends: "a", articles: ["read"] }, // cycle!
  },
});
// Error: Circular inheritance detected: a -> b -> a
```

---

## Known Limitations

- **Authentication is external** — this library only handles authorization, not authentication
- **Static matrix** — the matrix is loaded at startup and cannot be modified at runtime
- **`ownerId` contract** — resource ownership requires the resource to expose an `ownerId` property
- **Framework-agnostic middleware** — the middleware follows a generic `(req, res, next)` pattern with no built-in Express or HTTP framework dependency
