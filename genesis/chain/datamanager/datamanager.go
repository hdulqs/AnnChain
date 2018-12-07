package datamanager

import (
	"sync"

	"github.com/dappledger/AnnChain/ann-module/lib/go-config"
	"github.com/dappledger/AnnChain/genesis/chain/database"
	"go.uber.org/zap"
)

// DBCreator to create db instance
type DBCreator func(dbname string) database.Database

// DataManager data access between app and database
type DataManager struct {
	opdb database.Database
	qdb  database.Database

	opNeedLock bool
	opLock     sync.Mutex

	qNeedLock bool
	qLock     sync.Mutex
}

// NewDataManager create data manager
func NewDataManager(cfg config.Config, logger *zap.Logger, dbc DBCreator) (*DataManager, error) {
	opdb := dbc("delosop.db")
	qdb := dbc("delosquety.db")

	// GetInitSQLs has nothing to do with specific instances, so use opdb or qdb are both ok
	opt, opi, qt, qi := opdb.GetInitSQLs()
	err := opdb.PrepareTables(opt, opi)
	if err != nil {
		return nil, err
	}
	err = qdb.PrepareTables(qt, qi)
	if err != nil {
		return nil, err
	}

	dm := &DataManager{
		opdb: opdb,
		qdb:  qdb,
	}
	switch cfg.GetString("db_type") {
	case database.DBTypeSQLite3:
		dm.opNeedLock = true
		dm.qNeedLock = true
	default:
		dm.opNeedLock = true
		dm.qNeedLock = true
	}

	return dm, nil
}

// Close close all dbs
func (m *DataManager) Close() {
	if m.opNeedLock {
		m.opLock.Lock()
		defer m.opLock.Unlock()
	}
	if m.opdb != nil {
		m.opdb.Close()
		m.opdb = nil
	}

	if m.qNeedLock {
		m.qLock.Lock()
		defer m.qLock.Unlock()
	}
	if m.qdb != nil {
		m.qdb.Close()
		m.qdb = nil
	}
}

// OpTxBegin start database transaction of opdb
func (m *DataManager) OpTxBegin() error {
	if m.opNeedLock {
		m.opLock.Lock()
		defer m.opLock.Unlock()
	}

	return m.opdb.Begin()
}

// OpTxCommit commit database transaction of opdb
func (m *DataManager) OpTxCommit() error {
	if m.opNeedLock {
		m.opLock.Lock()
		defer m.opLock.Unlock()
	}

	return m.opdb.Commit()
}

// OpTxRollback rollback database transaction of opdb
func (m *DataManager) OpTxRollback() error {
	if m.opNeedLock {
		m.opLock.Lock()
		defer m.opLock.Unlock()
	}

	return m.opdb.Rollback()
}

// QTxBegin start database transaction of qdb
func (m *DataManager) QTxBegin() error {
	if m.qNeedLock {
		m.qLock.Lock()
		defer m.qLock.Unlock()
	}

	return m.qdb.Begin()
}

// QTxCommit commit database transaction of qdb
func (m *DataManager) QTxCommit() error {
	if m.qNeedLock {
		m.qLock.Lock()
		defer m.qLock.Unlock()
	}

	return m.qdb.Commit()
}

// QTxRollback rollback database transaction of qdb
func (m *DataManager) QTxRollback() error {
	if m.qNeedLock {
		m.qLock.Lock()
		defer m.qLock.Unlock()
	}

	return m.qdb.Rollback()
}
