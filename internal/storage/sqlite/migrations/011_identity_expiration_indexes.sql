CREATE INDEX identity_flows_expiration ON identity_flows(expires_at);
CREATE INDEX mfa_enrollments_expiration ON mfa_enrollments(expires_at);
CREATE INDEX identity_handoffs_expiration ON handoffs(expires_at);
CREATE INDEX identity_limits_expiration ON identity_limits(window_start);
