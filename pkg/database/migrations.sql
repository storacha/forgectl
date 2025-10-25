-- PostgreSQL Triggers for Normalized Diff-Based Time Series
-- These triggers implement conditional insert/update logic for FK-based schema:
-- - If content changed: INSERT new row with both timestamps set to NOW()
-- - If content unchanged: UPDATE most recent row, only updating checked_at

-- =============================================================================
-- Payment Account Snapshots Trigger
-- =============================================================================

CREATE OR REPLACE FUNCTION upsert_payment_account_snapshot()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    latest_row payment_account_snapshots%ROWTYPE;
BEGIN
    -- Get most recent row for this payer_token_pair_id
    SELECT * INTO latest_row
    FROM payment_account_snapshots
    WHERE payer_token_pair_id = NEW.payer_token_pair_id
    ORDER BY checked_at DESC LIMIT 1;

    -- If no previous row exists, allow insert
    IF latest_row IS NULL THEN
        RETURN NEW;
    END IF;

    -- Compare content fields (using CAST to compare numeric types)
    IF CAST(latest_row.funds AS TEXT) = CAST(NEW.funds AS TEXT) AND
       CAST(latest_row.lockup_current AS TEXT) = CAST(NEW.lockup_current AS TEXT) AND
       CAST(latest_row.lockup_rate AS TEXT) = CAST(NEW.lockup_rate AS TEXT) AND
       CAST(latest_row.lockup_last_settled_at AS TEXT) = CAST(NEW.lockup_last_settled_at AS TEXT) THEN
        -- Content unchanged, update checked_at on existing row
        UPDATE payment_account_snapshots
        SET checked_at = NOW()
        WHERE id = latest_row.id;
        -- Cancel the insert by returning NULL
        RETURN NULL;
    ELSE
        -- Content changed, allow insert
        RETURN NEW;
    END IF;
END;
$$;

CREATE OR REPLACE TRIGGER payment_account_upsert
BEFORE INSERT ON payment_account_snapshots
FOR EACH ROW EXECUTE FUNCTION upsert_payment_account_snapshot();

-- =============================================================================
-- Payment Operator Snapshots Trigger
-- =============================================================================

CREATE OR REPLACE FUNCTION upsert_payment_operator_snapshot()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    latest_row payment_operator_snapshots%ROWTYPE;
BEGIN
    -- Get most recent row for this payer_token_pair_id
    SELECT * INTO latest_row
    FROM payment_operator_snapshots
    WHERE payer_token_pair_id = NEW.payer_token_pair_id
    ORDER BY checked_at DESC LIMIT 1;

    -- If no previous row exists, allow insert
    IF latest_row IS NULL THEN
        RETURN NEW;
    END IF;

    -- Compare content fields
    IF latest_row.is_approved = NEW.is_approved AND
       CAST(latest_row.rate_allowance AS TEXT) = CAST(NEW.rate_allowance AS TEXT) AND
       CAST(latest_row.lockup_allowance AS TEXT) = CAST(NEW.lockup_allowance AS TEXT) AND
       CAST(latest_row.rate_usage AS TEXT) = CAST(NEW.rate_usage AS TEXT) AND
       CAST(latest_row.lockup_usage AS TEXT) = CAST(NEW.lockup_usage AS TEXT) AND
       CAST(latest_row.max_lockup_period AS TEXT) = CAST(NEW.max_lockup_period AS TEXT) THEN
        -- Content unchanged, update checked_at on existing row
        UPDATE payment_operator_snapshots
        SET checked_at = NOW()
        WHERE id = latest_row.id;
        -- Cancel the insert
        RETURN NULL;
    ELSE
        -- Content changed, allow insert
        RETURN NEW;
    END IF;
END;
$$;

CREATE OR REPLACE TRIGGER payment_operator_upsert
BEFORE INSERT ON payment_operator_snapshots
FOR EACH ROW EXECUTE FUNCTION upsert_payment_operator_snapshot();

-- =============================================================================
-- Payment Rails Summary Trigger
-- =============================================================================

CREATE OR REPLACE FUNCTION upsert_payment_rails_summary()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    latest_row payment_rails_summary%ROWTYPE;
BEGIN
    -- Get most recent row for this payer_token_pair_id
    SELECT * INTO latest_row
    FROM payment_rails_summary
    WHERE payer_token_pair_id = NEW.payer_token_pair_id
    ORDER BY checked_at DESC LIMIT 1;

    -- If no previous row exists, allow insert
    IF latest_row IS NULL THEN
        RETURN NEW;
    END IF;

    -- Compare content fields
    IF CAST(latest_row.total_rails AS TEXT) = CAST(NEW.total_rails AS TEXT) AND
       CAST(latest_row.next_offset AS TEXT) = CAST(NEW.next_offset AS TEXT) THEN
        -- Content unchanged, update checked_at on existing row
        UPDATE payment_rails_summary
        SET checked_at = NOW()
        WHERE id = latest_row.id;
        -- Cancel the insert
        RETURN NULL;
    ELSE
        -- Content changed, allow insert
        RETURN NEW;
    END IF;
END;
$$;

CREATE OR REPLACE TRIGGER payment_rails_summary_upsert
BEFORE INSERT ON payment_rails_summary
FOR EACH ROW EXECUTE FUNCTION upsert_payment_rails_summary();

-- =============================================================================
-- Payment Rail Info Trigger
-- =============================================================================

CREATE OR REPLACE FUNCTION upsert_payment_rail_info()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    latest_row payment_rail_info%ROWTYPE;
BEGIN
    -- Get most recent row for this rail_id
    SELECT * INTO latest_row
    FROM payment_rail_info
    WHERE CAST(rail_id AS TEXT) = CAST(NEW.rail_id AS TEXT)
    ORDER BY checked_at DESC LIMIT 1;

    -- If no previous row exists, allow insert
    IF latest_row IS NULL THEN
        RETURN NEW;
    END IF;

    -- Compare all content fields (FK IDs and data)
    IF latest_row.payer_token_pair_id = NEW.payer_token_pair_id AND
       latest_row.provider_id = NEW.provider_id AND
       latest_row.operator_contract_id = NEW.operator_contract_id AND
       latest_row.validator_contract_id = NEW.validator_contract_id AND
       latest_row.service_fee_recipient_contract_id = NEW.service_fee_recipient_contract_id AND
       CAST(latest_row.payment_rate AS TEXT) = CAST(NEW.payment_rate AS TEXT) AND
       CAST(latest_row.lockup_period AS TEXT) = CAST(NEW.lockup_period AS TEXT) AND
       CAST(latest_row.lockup_fixed AS TEXT) = CAST(NEW.lockup_fixed AS TEXT) AND
       CAST(latest_row.settled_up_to AS TEXT) = CAST(NEW.settled_up_to AS TEXT) AND
       CAST(latest_row.end_epoch AS TEXT) = CAST(NEW.end_epoch AS TEXT) AND
       CAST(latest_row.commission_rate_bps AS TEXT) = CAST(NEW.commission_rate_bps AS TEXT) AND
       latest_row.is_terminated = NEW.is_terminated THEN
        -- Content unchanged, update checked_at on existing row
        UPDATE payment_rail_info
        SET checked_at = NOW()
        WHERE id = latest_row.id;
        -- Cancel the insert
        RETURN NULL;
    ELSE
        -- Content changed, allow insert
        RETURN NEW;
    END IF;
END;
$$;

CREATE OR REPLACE TRIGGER payment_rail_info_upsert
BEFORE INSERT ON payment_rail_info
FOR EACH ROW EXECUTE FUNCTION upsert_payment_rail_info();

-- =============================================================================
-- Provider Snapshots Trigger
-- =============================================================================

CREATE OR REPLACE FUNCTION upsert_provider_snapshot()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    latest_row provider_snapshots%ROWTYPE;
BEGIN
    -- Get most recent row for this provider_id
    SELECT * INTO latest_row
    FROM provider_snapshots
    WHERE provider_id = NEW.provider_id
    ORDER BY checked_at DESC LIMIT 1;

    -- If no previous row exists, allow insert
    IF latest_row IS NULL THEN
        RETURN NEW;
    END IF;

    -- Compare content fields
    IF latest_row.is_active = NEW.is_active AND
       latest_row.is_approved = NEW.is_approved THEN
        -- Content unchanged, update checked_at on existing row
        UPDATE provider_snapshots
        SET checked_at = NOW()
        WHERE id = latest_row.id;
        -- Cancel the insert
        RETURN NULL;
    ELSE
        -- Content changed, allow insert
        RETURN NEW;
    END IF;
END;
$$;

CREATE OR REPLACE TRIGGER provider_snapshot_upsert
BEFORE INSERT ON provider_snapshots
FOR EACH ROW EXECUTE FUNCTION upsert_provider_snapshot();

-- =============================================================================
-- Instructions
-- =============================================================================
-- To apply these triggers, run this SQL file against your PostgreSQL database:
--   psql -U postgres -d forgectl -f pkg/database/migrations.sql
--
-- Or execute via code using db.Exec() after GORM auto-migration creates the tables.
--
-- Schema Summary:
-- Entity Tables: payers, tokens, providers, contracts, payer_token_pairs
-- Time-Series Tables: payment_account_snapshots, payment_operator_snapshots,
--                     payment_rails_summary, payment_rail_info, provider_snapshots
