-- Migration 006: RBAC (Role-Based Access Control) tables
-- Adds workspace-scoped roles, permissions, and API key scoping.
-- Part of SOC2 compliance foundation.

BEGIN;

-- Workspaces (multi-tenancy)
CREATE TABLE IF NOT EXISTS workspaces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    owner_id UUID REFERENCES users(id),
    settings JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_workspaces_slug ON workspaces(slug);
CREATE INDEX idx_workspaces_owner ON workspaces(owner_id);

-- Roles
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    permissions JSONB NOT NULL DEFAULT '[]',
    -- e.g., ["analyze", "migrate", "manage_users", "audit"]
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(workspace_id, name)
);

CREATE INDEX idx_roles_workspace ON roles(workspace_id);

-- User-Role assignments
CREATE TABLE IF NOT EXISTS user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    granted_by UUID REFERENCES users(id),
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,  -- NULL = never expires
    UNIQUE(user_id, role_id, workspace_id)
);

CREATE INDEX idx_user_roles_user ON user_roles(user_id);
CREATE INDEX idx_user_roles_workspace ON user_roles(workspace_id);

-- API Key permissions
CREATE TABLE IF NOT EXISTS api_key_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key_id UUID NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    resource_pattern TEXT NOT NULL DEFAULT '*',
    -- e.g., 'workspace/*', 'plan/*', 'migration/prod-*'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(api_key_id, permission, resource_pattern)
);

CREATE INDEX idx_api_key_perms_key ON api_key_permissions(api_key_id);

-- Audit log table (persistent, append-only)
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    event_type TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id UUID,
    workspace_id UUID,
    resource_type TEXT NOT NULL DEFAULT '',
    resource_id TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'success',
    details JSONB NOT NULL DEFAULT '{}',
    ip_address INET,
    user_agent TEXT NOT NULL DEFAULT '',
    duration_ms FLOAT NOT NULL DEFAULT 0,
    correlation_id TEXT NOT NULL DEFAULT ''
);

-- Partition audit_log by month for performance
-- (In production, use TimescaleDB or manual partitioning)
CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_log_user ON audit_log(user_id);
CREATE INDEX idx_audit_log_type ON audit_log(event_type);
CREATE INDEX idx_audit_log_workspace ON audit_log(workspace_id);
CREATE INDEX idx_audit_log_resource ON audit_log(resource_type, resource_id);

-- Insert default roles for new workspaces
CREATE OR REPLACE FUNCTION create_default_roles()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO roles (workspace_id, name, description, permissions, is_default) VALUES
    (NEW.id, 'viewer', 'Read-only access to analyses and reports',
     '["analyze", "compare", "audit.read", "config.read"]'::jsonb, TRUE),
    (NEW.id, 'analyst', 'Full analysis and health check access',
     '["analyze", "compare", "rewrite", "schema.snapshot", "health.check", "bench", "audit.read", "config.read"]'::jsonb, FALSE),
    (NEW.id, 'developer', 'Analysis plus migration and budget management',
     '["analyze", "compare", "rewrite", "migrate", "schema.snapshot", "health.check", "bench", "audit.read", "config.read", "budget.manage"]'::jsonb, FALSE),
    (NEW.id, 'admin', 'Full administrative access',
     '["admin"]'::jsonb, FALSE);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_create_default_roles
AFTER INSERT ON workspaces
FOR EACH ROW EXECUTE FUNCTION create_default_roles();

COMMIT;
