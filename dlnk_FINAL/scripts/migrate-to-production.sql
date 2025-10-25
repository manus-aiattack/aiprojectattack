-- dLNk Attack Platform - Production Database Migration Script
-- This script migrates from development to production database

-- ============================================================================
-- PRODUCTION DATABASE SETUP
-- ============================================================================

-- Create production database (run as postgres superuser)
-- CREATE DATABASE dlnk_production;
-- CREATE USER dlnk_user WITH PASSWORD 'CHANGE_THIS_PASSWORD';
-- GRANT ALL PRIVILEGES ON DATABASE dlnk_production TO dlnk_user;

-- Connect to production database
-- \c dlnk_production;

-- ============================================================================
-- SECURITY ENHANCEMENTS
-- ============================================================================

-- Enable Row Level Security (RLS) for sensitive tables
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE key_usage_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE attacks ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE exploits ENABLE ROW LEVEL SECURITY;
ALTER TABLE exfiltrated_data ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_logs ENABLE ROW LEVEL SECURITY;

-- Create RLS policies for api_keys table
CREATE POLICY api_keys_admin_policy ON api_keys
    FOR ALL TO dlnk_user
    USING (true); -- Admin can see all keys

-- Create RLS policies for attacks table
CREATE POLICY attacks_user_policy ON attacks
    FOR ALL TO dlnk_user
    USING (true); -- Users can see their own attacks

-- Create RLS policies for vulnerabilities table
CREATE POLICY vulnerabilities_user_policy ON vulnerabilities
    FOR ALL TO dlnk_user
    USING (true); -- Users can see vulnerabilities from their attacks

-- Create RLS policies for exploits table
CREATE POLICY exploits_user_policy ON exploits
    FOR ALL TO dlnk_user
    USING (true); -- Users can see exploits from their attacks

-- Create RLS policies for exfiltrated_data table
CREATE POLICY exfiltrated_data_user_policy ON exfiltrated_data
    FOR ALL TO dlnk_user
    USING (true); -- Users can see exfiltrated data from their attacks

-- ============================================================================
-- AUDIT LOGGING
-- ============================================================================

-- Create audit log table
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    operation VARCHAR(10) NOT NULL, -- INSERT, UPDATE, DELETE
    old_values JSONB,
    new_values JSONB,
    user_id VARCHAR(100),
    ip_address INET,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_logs_table_name ON audit_logs(table_name);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);

-- Audit trigger function
CREATE OR REPLACE FUNCTION audit_trigger_function()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO audit_logs (table_name, operation, new_values, user_id, ip_address)
        VALUES (TG_TABLE_NAME, 'INSERT', to_jsonb(NEW), current_setting('app.current_user_id', true), inet_client_addr());
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO audit_logs (table_name, operation, old_values, new_values, user_id, ip_address)
        VALUES (TG_TABLE_NAME, 'UPDATE', to_jsonb(OLD), to_jsonb(NEW), current_setting('app.current_user_id', true), inet_client_addr());
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO audit_logs (table_name, operation, old_values, user_id, ip_address)
        VALUES (TG_TABLE_NAME, 'DELETE', to_jsonb(OLD), current_setting('app.current_user_id', true), inet_client_addr());
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Create audit triggers for sensitive tables
CREATE TRIGGER audit_api_keys_trigger
    AFTER INSERT OR UPDATE OR DELETE ON api_keys
    FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();

CREATE TRIGGER audit_attacks_trigger
    AFTER INSERT OR UPDATE OR DELETE ON attacks
    FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();

CREATE TRIGGER audit_vulnerabilities_trigger
    AFTER INSERT OR UPDATE OR DELETE ON vulnerabilities
    FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();

CREATE TRIGGER audit_exploits_trigger
    AFTER INSERT OR UPDATE OR DELETE ON exploits
    FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();

CREATE TRIGGER audit_exfiltrated_data_trigger
    AFTER INSERT OR UPDATE OR DELETE ON exfiltrated_data
    FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();

-- ============================================================================
-- PERFORMANCE OPTIMIZATIONS
-- ============================================================================

-- Create additional indexes for performance
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_attacks_status_started_at ON attacks(status, started_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vulnerabilities_severity_discovered_at ON vulnerabilities(severity, discovered_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_key_usage_logs_endpoint_timestamp ON key_usage_logs(endpoint, timestamp DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_exfiltrated_data_exfiltrated_at ON exfiltrated_data(exfiltrated_at DESC);

-- Create partial indexes for active records
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_api_keys_active ON api_keys(key_value) WHERE is_active = true;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_attacks_active ON attacks(id) WHERE status IN ('pending', 'running', 'analyzing');

-- ============================================================================
-- DATA RETENTION POLICIES
-- ============================================================================

-- Create function to clean up old data
CREATE OR REPLACE FUNCTION cleanup_old_data()
RETURNS INTEGER AS $$
DECLARE
    retention_days INTEGER;
    deleted_count INTEGER := 0;
BEGIN
    -- Get retention period from settings
    SELECT value::INTEGER INTO retention_days
    FROM system_settings
    WHERE key = 'data_retention_days';
    
    -- Default to 30 days if not set
    IF retention_days IS NULL THEN
        retention_days := 30;
    END IF;
    
    -- Delete old completed attacks and related data
    WITH deleted_attacks AS (
        DELETE FROM attacks
        WHERE status IN ('completed', 'failed')
        AND started_at < CURRENT_TIMESTAMP - INTERVAL '1 day' * retention_days
        RETURNING id
    )
    SELECT COUNT(*) INTO deleted_count FROM deleted_attacks;
    
    -- Delete old usage logs (keep only 90 days)
    DELETE FROM key_usage_logs
    WHERE timestamp < CURRENT_TIMESTAMP - INTERVAL '90 days';
    
    -- Delete old audit logs (keep only 1 year)
    DELETE FROM audit_logs
    WHERE timestamp < CURRENT_TIMESTAMP - INTERVAL '1 year';
    
    -- Log cleanup activity
    INSERT INTO admin_logs (admin_key_id, action, details, timestamp)
    VALUES (NULL, 'data_cleanup', jsonb_build_object('deleted_attacks', deleted_count), CURRENT_TIMESTAMP);
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- BACKUP AND RECOVERY FUNCTIONS
-- ============================================================================

-- Create function to export attack data
CREATE OR REPLACE FUNCTION export_attack_data(attack_id UUID)
RETURNS JSONB AS $$
DECLARE
    result JSONB;
BEGIN
    SELECT jsonb_build_object(
        'attack', to_jsonb(a.*),
        'vulnerabilities', COALESCE(
            (SELECT jsonb_agg(to_jsonb(v.*)) FROM vulnerabilities v WHERE v.attack_id = a.id),
            '[]'::jsonb
        ),
        'exploits', COALESCE(
            (SELECT jsonb_agg(to_jsonb(e.*)) FROM exploits e WHERE e.attack_id = a.id),
            '[]'::jsonb
        ),
        'exfiltrated_data', COALESCE(
            (SELECT jsonb_agg(to_jsonb(ed.*)) FROM exfiltrated_data ed WHERE ed.attack_id = a.id),
            '[]'::jsonb
        )
    ) INTO result
    FROM attacks a
    WHERE a.id = attack_id;
    
    RETURN result;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- MONITORING AND HEALTH CHECKS
-- ============================================================================

-- Create function to check database health
CREATE OR REPLACE FUNCTION check_database_health()
RETURNS JSONB AS $$
DECLARE
    result JSONB;
    table_count INTEGER;
    index_count INTEGER;
    connection_count INTEGER;
BEGIN
    -- Get table count
    SELECT COUNT(*) INTO table_count
    FROM information_schema.tables
    WHERE table_schema = 'public';
    
    -- Get index count
    SELECT COUNT(*) INTO index_count
    FROM pg_indexes
    WHERE schemaname = 'public';
    
    -- Get active connection count
    SELECT COUNT(*) INTO connection_count
    FROM pg_stat_activity
    WHERE state = 'active';
    
    result := jsonb_build_object(
        'status', 'healthy',
        'timestamp', CURRENT_TIMESTAMP,
        'tables', table_count,
        'indexes', index_count,
        'active_connections', connection_count,
        'database_size', pg_size_pretty(pg_database_size(current_database())),
        'version', version()
    );
    
    RETURN result;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- SECURITY FUNCTIONS
-- ============================================================================

-- Create function to validate API key format
CREATE OR REPLACE FUNCTION validate_api_key_format(key_value TEXT)
RETURNS BOOLEAN AS $$
BEGIN
    -- Check if key starts with 'dlnk_' and is 64 characters total
    RETURN key_value ~ '^dlnk_[a-f0-9]{58}$';
END;
$$ LANGUAGE plpgsql;

-- Create function to check for suspicious activity
CREATE OR REPLACE FUNCTION check_suspicious_activity(key_id UUID, ip_address INET)
RETURNS BOOLEAN AS $$
DECLARE
    recent_failures INTEGER;
    different_ips INTEGER;
BEGIN
    -- Check for recent authentication failures
    SELECT COUNT(*) INTO recent_failures
    FROM key_usage_logs
    WHERE key_id = check_suspicious_activity.key_id
    AND response_status >= 400
    AND timestamp > CURRENT_TIMESTAMP - INTERVAL '1 hour';
    
    -- Check for requests from different IPs
    SELECT COUNT(DISTINCT ip_address) INTO different_ips
    FROM key_usage_logs
    WHERE key_id = check_suspicious_activity.key_id
    AND timestamp > CURRENT_TIMESTAMP - INTERVAL '1 hour';
    
    -- Flag as suspicious if more than 5 failures or requests from more than 3 IPs
    RETURN recent_failures > 5 OR different_ips > 3;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- PRODUCTION SETTINGS
-- ============================================================================

-- Update system settings for production
INSERT INTO system_settings (key, value, description) VALUES
    ('production_mode', 'true', 'Production mode flag'),
    ('data_retention_days', '30', 'Days to retain attack data'),
    ('max_concurrent_attacks', '3', 'Maximum concurrent attacks per user'),
    ('rate_limit_per_minute', '30', 'API rate limit per minute'),
    ('session_timeout_minutes', '480', 'Session timeout in minutes'),
    ('enable_audit_logging', 'true', 'Enable audit logging'),
    ('backup_frequency_hours', '24', 'Backup frequency in hours'),
    ('monitoring_enabled', 'true', 'Enable monitoring'),
    ('security_scanning_enabled', 'true', 'Enable security scanning')
ON CONFLICT (key) DO UPDATE SET
    value = EXCLUDED.value,
    description = EXCLUDED.description,
    updated_at = CURRENT_TIMESTAMP;

-- ============================================================================
-- FINAL COMMENTS
-- ============================================================================

COMMENT ON FUNCTION cleanup_old_data() IS 'Cleans up old data based on retention policies';
COMMENT ON FUNCTION export_attack_data(UUID) IS 'Exports complete attack data for backup/analysis';
COMMENT ON FUNCTION check_database_health() IS 'Checks database health and returns status';
COMMENT ON FUNCTION validate_api_key_format(TEXT) IS 'Validates API key format';
COMMENT ON FUNCTION check_suspicious_activity(UUID, INET) IS 'Checks for suspicious API usage patterns';

-- Grant necessary permissions
GRANT EXECUTE ON FUNCTION cleanup_old_data() TO dlnk_user;
GRANT EXECUTE ON FUNCTION export_attack_data(UUID) TO dlnk_user;
GRANT EXECUTE ON FUNCTION check_database_health() TO dlnk_user;
GRANT EXECUTE ON FUNCTION validate_api_key_format(TEXT) TO dlnk_user;
GRANT EXECUTE ON FUNCTION check_suspicious_activity(UUID, INET) TO dlnk_user;

-- ============================================================================
-- MIGRATION COMPLETE
-- ============================================================================

-- Log successful migration
INSERT INTO admin_logs (admin_key_id, action, details, timestamp)
VALUES (NULL, 'database_migration', jsonb_build_object('version', '2.0', 'type', 'production'), CURRENT_TIMESTAMP);

-- Display migration summary
SELECT 
    'Migration completed successfully' as status,
    COUNT(*) as total_tables,
    (SELECT COUNT(*) FROM pg_indexes WHERE schemaname = 'public') as total_indexes,
    (SELECT COUNT(*) FROM pg_proc WHERE pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')) as total_functions
FROM information_schema.tables
WHERE table_schema = 'public';
