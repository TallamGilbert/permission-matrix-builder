export type Scope = 'own' | null;

export interface Rule {
  action: string;
  scope: Scope;
  deny: boolean;
}

export type ResourceRules = Rule[];
export type RolePermissions = Record<string, ResourceRules>;

export interface MatrixConfig {
  roles: Record<string, Record<string, string | string[] | RuleInput | RuleInput[]>>;
}

export type RuleInput = string | {
  action: string;
  scope?: 'own';
  deny?: boolean;
};

export interface PermissionMatrix {
  readonly roles: Record<string, RolePermissions>;
}

export interface User {
  id: string;
  roles: string[];
}

export interface OwnedResource {
  ownerId: string;
}
