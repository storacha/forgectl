package database

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	logging "github.com/ipfs/go-log/v2"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var log = logging.Logger("database")

// DB wraps the GORM database connection
type DB struct {
	*gorm.DB
}

// Connect establishes a connection to the PostgreSQL database
func Connect(databaseURL string) (*DB, error) {
	if databaseURL == "" {
		return nil, fmt.Errorf("database URL is required")
	}

	// Configure GORM logger to be less verbose
	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	}

	// Open database connection
	db, err := gorm.Open(postgres.Open(databaseURL), gormConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	log.Info("Successfully connected to database")

	// Auto-migrate the schema (entity tables first, then time-series tables)
	if err := db.AutoMigrate(
		// Entity tables
		&Payer{},
		&Token{},
		&Provider{},
		&Contract{},
		&PayerTokenPair{},
		// Time-series tables
		&PaymentAccountSnapshot{},
		&PaymentOperatorSnapshot{},
		&PaymentRailsSummary{},
		&PaymentRailInfo{},
		&ProviderSnapshot{},
	); err != nil {
		return nil, fmt.Errorf("failed to auto-migrate schema: %w", err)
	}

	log.Info("Database schema migrated successfully")

	return &DB{DB: db}, nil
}

// Close closes the database connection
func (db *DB) Close() error {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// SaveAccountSnapshot saves a payment account snapshot to the database
// Note: PostgreSQL trigger handles deduplication (updates checked_at if content unchanged)
func (db *DB) SaveAccountSnapshot(snapshot *PaymentAccountSnapshot) error {
	result := db.Create(snapshot)
	if result.Error != nil {
		return fmt.Errorf("failed to save account snapshot: %w", result.Error)
	}
	// Note: result.RowsAffected will be 0 if trigger prevented insert
	log.Debugf("Processed account snapshot for payer_token_pair_id %d (rows affected: %d)", snapshot.PayerTokenPairID, result.RowsAffected)
	return nil
}

// SaveOperatorSnapshot saves a payment operator snapshot to the database
// Note: PostgreSQL trigger handles deduplication (updates checked_at if content unchanged)
func (db *DB) SaveOperatorSnapshot(snapshot *PaymentOperatorSnapshot) error {
	result := db.Create(snapshot)
	if result.Error != nil {
		return fmt.Errorf("failed to save operator snapshot: %w", result.Error)
	}
	// Note: result.RowsAffected will be 0 if trigger prevented insert
	log.Debugf("Processed operator snapshot for payer_token_pair_id %d (rows affected: %d)", snapshot.PayerTokenPairID, result.RowsAffected)
	return nil
}

// SaveRailsSummary saves a payment rails summary to the database
// Note: PostgreSQL trigger handles deduplication (updates checked_at if content unchanged)
func (db *DB) SaveRailsSummary(summary *PaymentRailsSummary) error {
	result := db.Create(summary)
	if result.Error != nil {
		return fmt.Errorf("failed to save rails summary: %w", result.Error)
	}
	log.Debugf("Processed rails summary for payer_token_pair_id %d (rows affected: %d)", summary.PayerTokenPairID, result.RowsAffected)
	return nil
}

// SaveRailInfo saves a payment rail info to the database
// Note: PostgreSQL trigger handles deduplication (updates checked_at if content unchanged)
func (db *DB) SaveRailInfo(railInfo *PaymentRailInfo) error {
	result := db.Create(railInfo)
	if result.Error != nil {
		return fmt.Errorf("failed to save rail info: %w", result.Error)
	}
	log.Debugf("Processed rail info for rail_id %s (rows affected: %d)", railInfo.RailID.Int.String(), result.RowsAffected)
	return nil
}

// ApplyTriggers reads and executes the SQL migration file to create triggers
func (db *DB) ApplyTriggers() error {
	// Get the path to migrations.sql
	migrationPath := filepath.Join("pkg", "database", "migrations.sql")

	// Read the SQL file
	sqlBytes, err := os.ReadFile(migrationPath)
	if err != nil {
		return fmt.Errorf("failed to read migrations.sql: %w", err)
	}

	// Execute the SQL
	result := db.Exec(string(sqlBytes))
	if result.Error != nil {
		return fmt.Errorf("failed to apply triggers: %w", result.Error)
	}

	log.Info("Database triggers applied successfully")
	return nil
}

// ============================================================================
// UPSERT Helper Methods (for entity lookups)
// ============================================================================

// GetOrCreatePayer uses UPSERT pattern to efficiently lookup/create payer
func (db *DB) GetOrCreatePayer(address string) (uint, error) {
	var payer Payer
	err := db.Where(Payer{Address: address}).
		Attrs(Payer{Address: address}).
		FirstOrCreate(&payer).Error
	return payer.ID, err
}

// GetOrCreateToken uses UPSERT pattern to efficiently lookup/create token
func (db *DB) GetOrCreateToken(address string) (uint, error) {
	var token Token
	err := db.Where(Token{Address: address}).
		Attrs(Token{Address: address}).
		FirstOrCreate(&token).Error
	return token.ID, err
}

// GetOrCreateProvider uses UPSERT pattern to efficiently lookup/create provider
func (db *DB) GetOrCreateProvider(address string, providerID *big.Int, name, description, payee string) (uint, error) {
	var provider Provider
	err := db.Where(Provider{Address: address}).
		Attrs(Provider{
			Address:     address,
			ProviderID:  NewBigInt(providerID),
			Name:        name,
			Description: description,
			Payee:       payee,
		}).
		FirstOrCreate(&provider).Error
	return provider.ID, err
}

// GetOrCreateContract uses UPSERT pattern to efficiently lookup/create contract
func (db *DB) GetOrCreateContract(address string) (uint, error) {
	var contract Contract
	err := db.Where(Contract{Address: address}).
		Attrs(Contract{Address: address}).
		FirstOrCreate(&contract).Error
	return contract.ID, err
}

// GetOrCreatePayerTokenPair combines payer and token lookups
func (db *DB) GetOrCreatePayerTokenPair(payerAddr, tokenAddr string) (uint, error) {
	payerID, err := db.GetOrCreatePayer(payerAddr)
	if err != nil {
		return 0, fmt.Errorf("failed to get/create payer: %w", err)
	}

	tokenID, err := db.GetOrCreateToken(tokenAddr)
	if err != nil {
		return 0, fmt.Errorf("failed to get/create token: %w", err)
	}

	var pair PayerTokenPair
	err = db.Where(PayerTokenPair{PayerID: payerID, TokenID: tokenID}).
		Attrs(PayerTokenPair{PayerID: payerID, TokenID: tokenID}).
		FirstOrCreate(&pair).Error

	return pair.ID, err
}

// SaveProviderSnapshot saves a provider snapshot
func (db *DB) SaveProviderSnapshot(snapshot *ProviderSnapshot) error {
	result := db.Create(snapshot)
	if result.Error != nil {
		return fmt.Errorf("failed to save provider snapshot: %w", result.Error)
	}
	log.Debugf("Processed provider snapshot for provider %d (rows affected: %d)", snapshot.ProviderID, result.RowsAffected)
	return nil
}
