// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package state provides a caching layer atop the Ethereum state trie.
package state

import (
	"fmt"
	"math/big"
	"sort"

	"go.uber.org/zap"

	ethcmn "github.com/dappledger/AnnChain/genesis/eth/common"
	"github.com/dappledger/AnnChain/genesis/eth/crypto"
	"github.com/dappledger/AnnChain/genesis/eth/ethdb"
	"github.com/dappledger/AnnChain/genesis/eth/rlp"
	"github.com/dappledger/AnnChain/genesis/eth/trie"
	"github.com/dappledger/AnnChain/genesis/types"
	lru "github.com/hashicorp/golang-lru"
)

// Trie cache generation limit after which to evic trie nodes from memory.
var (
	MaxTrieCacheGen = uint16(120)
	logger          *zap.Logger
)

const (
	// Number of past tries to keep. This value is chosen such that
	// reasonable chain reorg depths will hit an existing trie.
	maxPastTries = 12

	//	baseReserve       = 10000000
	codeSizeCacheSize = 100000
)

type revision struct {
	id           int
	journalIndex int
}

// StateDBs within the ethereum protocol are used to store anything
// within the merkle trie. StateDBs take care of caching and storing
// nested states. It's the general query interface to retrieve:
// * Contracts
// * Accounts
type StateDB struct {
	db            ethdb.Database
	trie          *trie.SecureTrie
	pastTries     []*trie.SecureTrie
	codeSizeCache *lru.Cache

	// This map holds 'live' objects, which will get modified while processing a state transition.
	stateObjects      map[ethcmn.Address]*StateObject
	stateObjectsDirty map[ethcmn.Address]struct{}

	// DB error.
	// State objects are used by the consensus core and VM which are
	// unable to deal with database-level errors. Any error that occurs
	// during a database read is memoized here and will eventually be returned
	// by StateDB.Commit.
	dbErr error

	// The refund counter, also used by state transitioning.
	refund *big.Int

	thash, bhash ethcmn.Hash
	txIndex      int
	logs         map[ethcmn.Hash][]*types.Log
	logSize      uint

	preimages map[ethcmn.Hash][]byte

	// Journal of state modifications. This is the backbone of
	// Snapshot and RevertToSnapshot.
	journal        journal
	validRevisions []revision
	nextRevisionId int
}

func (s *StateDB) GetTrie() *trie.SecureTrie {
	return s.trie
}

func (s *StateDB) LenStateObjects() int {
	return len(s.stateObjects)
}

func Init(l *zap.Logger) {
	logger = l
}

// Create a new state from a given trie
func New(root ethcmn.Hash, db ethdb.Database) (*StateDB, error) {
	tr, err := trie.NewSecure(root, db, MaxTrieCacheGen)
	if err != nil {
		return nil, err
	}
	csc, _ := lru.New(codeSizeCacheSize)
	return &StateDB{
		db:                db,
		trie:              tr,
		stateObjects:      make(map[ethcmn.Address]*StateObject),
		stateObjectsDirty: make(map[ethcmn.Address]struct{}),
		codeSizeCache:     csc,
		refund:            new(big.Int),
		logs:              make(map[ethcmn.Hash][]*types.Log),
		preimages:         make(map[ethcmn.Hash][]byte),
	}, nil
}

// setError remembers the first non-nil error it is called with.
func (self *StateDB) setError(err error) {
	if self.dbErr == nil {
		self.dbErr = err
	}
}

func (self *StateDB) Error() error {
	return self.dbErr
}

// New creates a new statedb by reusing any journalled tries to avoid costly
// disk io.
func (self *StateDB) New(root ethcmn.Hash) (*StateDB, error) {
	tr, err := self.openTrie(root)
	if err != nil {
		return nil, err
	}
	return &StateDB{
		db:                self.db,
		trie:              tr,
		stateObjects:      make(map[ethcmn.Address]*StateObject),
		stateObjectsDirty: make(map[ethcmn.Address]struct{}),
		refund:            new(big.Int),
		codeSizeCache:     self.codeSizeCache,
		logs:              make(map[ethcmn.Hash][]*types.Log),
		preimages:         make(map[ethcmn.Hash][]byte),
	}, nil
}

// Reset clears out all emphemeral state objects from the state db, but keeps
// the underlying state trie to avoid reloading data for the next operations.
func (self *StateDB) Reset(root ethcmn.Hash) error {
	tr, err := self.openTrie(root)
	if err != nil {
		return err
	}
	self.trie = tr
	self.stateObjects = make(map[ethcmn.Address]*StateObject)
	self.stateObjectsDirty = make(map[ethcmn.Address]struct{})
	self.thash = ethcmn.Hash{}
	self.bhash = ethcmn.Hash{}
	self.txIndex = 0
	self.logs = make(map[ethcmn.Hash][]*types.Log)
	self.logSize = 0
	self.preimages = make(map[ethcmn.Hash][]byte)
	self.clearJournalAndRefund()

	return nil
}

// openTrie creates a trie. It uses an existing trie if one is available
// from the journal if available.
func (self *StateDB) openTrie(root ethcmn.Hash) (*trie.SecureTrie, error) {
	for i := len(self.pastTries) - 1; i >= 0; i-- {
		if self.pastTries[i].Hash() == root {
			tr := *self.pastTries[i]
			return &tr, nil
		}
	}
	return trie.NewSecure(root, self.db, MaxTrieCacheGen)
}

func (self *StateDB) pushTrie(t *trie.SecureTrie) {
	if len(self.pastTries) >= maxPastTries {
		copy(self.pastTries, self.pastTries[1:])
		self.pastTries[len(self.pastTries)-1] = t
	} else {
		self.pastTries = append(self.pastTries, t)
	}
}

func (self *StateDB) StartRecord(thash, bhash ethcmn.Hash, ti int) {
	self.thash = thash
	self.bhash = bhash
	self.txIndex = ti
}

func (self *StateDB) AddLog(log *types.Log) {
	self.journal = append(self.journal, addLogChange{txhash: self.thash})

	log.TxHash = self.thash
	log.BlockHash = self.bhash
	log.TxIndex = uint(self.txIndex)
	log.Index = self.logSize
	self.logs[self.thash] = append(self.logs[self.thash], log)
	self.logSize++
}

func (self *StateDB) GetLogs(hash ethcmn.Hash) []*types.Log {
	return self.logs[hash]
}

func (self *StateDB) Logs() []*types.Log {
	var logs []*types.Log
	for _, lgs := range self.logs {
		logs = append(logs, lgs...)
	}
	return logs
}

// AddPreimage records a SHA3 preimage seen by the VM.
func (self *StateDB) AddPreimage(hash ethcmn.Hash, preimage []byte) {
	if _, ok := self.preimages[hash]; !ok {
		self.journal = append(self.journal, addPreimageChange{hash: hash})
		pi := make([]byte, len(preimage))
		copy(pi, preimage)
		self.preimages[hash] = pi
	}
}

// Preimages returns a list of SHA3 preimages that have been submitted.
func (self *StateDB) Preimages() map[ethcmn.Hash][]byte {
	return self.preimages
}

func (self *StateDB) AddRefund(gas *big.Int) {
	self.journal = append(self.journal, refundChange{prev: new(big.Int).Set(self.refund)})
	self.refund.Add(self.refund, gas)
}

// Exist reports whether the given account address exists in the state.
// Notably this also returns true for suicided accounts.
func (self *StateDB) Exist(addr ethcmn.Address) bool {
	return self.GetStateObject(addr) != nil
}

// Empty returns whether the state object is either non-existent
// or empty according to the EIP161 specification (balance = nonce = code = 0)
func (self *StateDB) Empty(addr ethcmn.Address) bool {
	so := self.GetStateObject(addr)
	return so == nil || so.empty()
}

func (self *StateDB) GetAccount(addr ethcmn.Address) types.Account {
	return self.GetStateObject(addr)
}

// Retrieve the balance from the given address or 0 if object not found
func (self *StateDB) GetBalance(addr ethcmn.Address) *big.Int {
	stateObject := self.GetStateObject(addr)
	if stateObject != nil {
		return stateObject.Balance()
	}
	return ethcmn.Big0
}

func (self *StateDB) GetNonce(addr ethcmn.Address) uint64 {
	stateObject := self.GetStateObject(addr)
	if stateObject != nil {
		return stateObject.Nonce()
	}

	return 0
}

func (self *StateDB) GetState(a ethcmn.Address, b ethcmn.Hash) (ethcmn.Hash, bool) {
	stateObject := self.GetStateObject(a)
	if stateObject == nil {
		return ethcmn.Hash{}, false
	}

	d := stateObject.GetState(self.db, b)
	if d == (ethcmn.Hash{}) {
		return d, false
	}
	return d, true
}

func (self *StateDB) HasSuicided(addr ethcmn.Address) bool {
	stateObject := self.GetStateObject(addr)
	if stateObject != nil {
		return stateObject.suicided
	}
	return false
}

/*
 * SETTERS
 */

// AddBalance adds amount to the account associated with addr
func (self *StateDB) AddBalance(addr ethcmn.Address, amount *big.Int, log string) {
	stateObject := self.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.AddBalance(amount, log)
	}
}

// SubBalance subtracts amount from the account associated with addr
func (self *StateDB) SubBalance(addr ethcmn.Address, amount *big.Int, log string) {
	stateObject := self.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SubBalance(amount, log)
	}
}

func (self *StateDB) SetBalance(addr ethcmn.Address, amount *big.Int, log string) {
	stateObject := self.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetBalance(amount, log)
	}
}

func (self *StateDB) SetNonce(addr ethcmn.Address, nonce uint64) {
	stateObject := self.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetNonce(nonce)
	}
}
func (self *StateDB) SetCode(addr ethcmn.Address, code []byte, byteCode []byte) {
	stateObject := self.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetByteCode(byteCode)
		stateObject.SetCode(crypto.Keccak256Hash(code), code)
	}
}

func (self *StateDB) SetState(addr ethcmn.Address, key, value ethcmn.Hash) {
	stateObject := self.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetState(self.db, key, value)
	}
}

// Suicide marks the given account as suicided.
// This clears the account balance.
//
// The account's state object is still available until the state is committed,
// GetStateObject will return a non-nil account after Suicide.
func (self *StateDB) Suicide(addr ethcmn.Address) bool {
	stateObject := self.GetStateObject(addr)
	if stateObject == nil {
		return false
	}
	self.journal = append(self.journal, suicideChange{
		account:     &addr,
		prev:        stateObject.suicided,
		prevbalance: new(big.Int).Set(stateObject.Balance()),
	})
	stateObject.markSuicided()
	stateObject.data.Balance = new(big.Int)
	return true
}

//
// Setting, updating & deleting state object methods
//

// updateStateObject writes the given object to the trie.
func (self *StateDB) updateStateObject(stateObject *StateObject) {
	addr := stateObject.Address()
	data, err := rlp.EncodeToBytes(stateObject)
	if err != nil {
		panic(fmt.Errorf("can't encode object at %x: %v", addr[:], err))
	}
	self.trie.Update(addr[:], data)
}

// deleteStateObject removes the given object from the state trie.
func (self *StateDB) deleteStateObject(stateObject *StateObject) {
	stateObject.deleted = true
	addr := stateObject.Address()
	self.trie.Delete(addr[:])
}

// Retrieve a state object given my the address. Returns nil if not found.
func (self *StateDB) GetStateObject(addr ethcmn.Address) (stateObject *StateObject) {
	// Prefer 'live' objects.
	if obj := self.stateObjects[addr]; obj != nil {
		if obj.deleted {
			return nil
		}
		return obj
	}

	// Load the object from the database.
	enc := self.trie.Get(addr[:])
	if len(enc) == 0 {
		return nil
	}
	var data Account
	if err := rlp.DecodeBytes(enc, &data); err != nil {
		logger.Warn("[statedb],getStateObj,can't decode object", zap.String("at", addr.Hex()), zap.String("err", err.Error()))
		return nil
	}
	// Insert into the live set.
	obj := newObject(self, addr, data, self.MarkStateObjectDirty)
	self.setStateObject(obj)
	return obj
}

func (self *StateDB) setStateObject(object *StateObject) {
	self.stateObjects[object.Address()] = object
}

// Retrieve a state object or create a new state object if nil
func (self *StateDB) GetOrNewStateObject(addr ethcmn.Address) *StateObject {
	stateObject := self.GetStateObject(addr)
	if stateObject == nil || stateObject.deleted {
		stateObject, _ = self.createObject(addr)
	}
	return stateObject
}

// MarkStateObjectDirty adds the specified object to the dirty map to avoid costly
// state object cache iteration to find a handful of modified ones.
func (self *StateDB) MarkStateObjectDirty(addr ethcmn.Address) {
	self.stateObjectsDirty[addr] = struct{}{}
}

// createObject creates a new state object. If there is an existing account with
// the given address, it is overwritten and returned as the second return value.
func (self *StateDB) createObject(addr ethcmn.Address) (newobj, prev *StateObject) {
	prev = self.GetStateObject(addr)
	newobj = newObject(self, addr, Account{}, self.MarkStateObjectDirty)
	newobj.setNonce(0) // sets the object to dirty
	if prev == nil {
		//if glog.V(logger.Core) {
		//	glog.Infof("(+) %x\n", addr)
		//}
		self.journal = append(self.journal, createObjectChange{account: &addr})
	} else {
		self.journal = append(self.journal, resetObjectChange{prev: prev})
	}
	self.setStateObject(newobj)
	return newobj, prev
}

// CreateAccount explicitly creates a state object. If a state object with the address
// already exists the balance is carried over to the new account.
//
// CreateAccount is called during the EVM CREATE operation. The situation might arise that
// a contract does the following:
//
//   1. sends funds to sha(account ++ (nonce + 1))
//   2. tx_create(sha(account ++ nonce)) (note that this gets the address of 1)
//
// Carrying over the balance ensures that Ether doesn't disappear.
func (self *StateDB) CreateAccount(addr ethcmn.Address) types.Account {
	new, prev := self.createObject(addr)
	if prev != nil {
		new.setBalance(prev.data.Balance, "creat exist account")
	}

	return new
}

// Copy creates a deep, independent copy of the state.
// Snapshots of the copied state cannot be applied to the copy.
func (self *StateDB) Copy() *StateDB {
	// Copy all the basic fields, initialize the memory ones
	state := &StateDB{
		db:                self.db,
		trie:              self.trie,
		pastTries:         self.pastTries,
		codeSizeCache:     self.codeSizeCache,
		stateObjects:      make(map[ethcmn.Address]*StateObject, len(self.stateObjectsDirty)),
		stateObjectsDirty: make(map[ethcmn.Address]struct{}, len(self.stateObjectsDirty)),
		refund:            new(big.Int).Set(self.refund),
		logs:              make(map[ethcmn.Hash][]*types.Log, len(self.logs)),
		logSize:           self.logSize,
		preimages:         make(map[ethcmn.Hash][]byte),
	}
	// Copy the dirty states, logs, and preimages
	for addr := range self.stateObjectsDirty {
		state.stateObjects[addr] = self.stateObjects[addr].deepCopy(state, state.MarkStateObjectDirty)
		state.stateObjectsDirty[addr] = struct{}{}
	}
	for hash, logs := range self.logs {
		state.logs[hash] = make([]*types.Log, len(logs))
		copy(state.logs[hash], logs)
	}
	for hash, preimage := range self.preimages {
		state.preimages[hash] = preimage
	}
	return state
}

func (self *StateDB) DeepCopy() *StateDB {
	// Copy all the basic fields, initialize the memory ones
	newTrie, err := trie.NewSecure(self.trie.Hash(), self.db, MaxTrieCacheGen)
	if err != nil {
		return nil
	}

	state := &StateDB{
		db:                self.db,
		trie:              newTrie,
		pastTries:         self.pastTries,
		codeSizeCache:     self.codeSizeCache,
		stateObjects:      make(map[ethcmn.Address]*StateObject, len(self.stateObjectsDirty)),
		stateObjectsDirty: make(map[ethcmn.Address]struct{}, len(self.stateObjectsDirty)),
		refund:            new(big.Int).Set(self.refund),
		logs:              make(map[ethcmn.Hash][]*types.Log, len(self.logs)),
		logSize:           self.logSize,
		preimages:         make(map[ethcmn.Hash][]byte),
	}
	// Copy the dirty states, logs, and preimages
	for addr := range self.stateObjectsDirty {
		state.stateObjects[addr] = self.stateObjects[addr].deepCopy(state, state.MarkStateObjectDirty)
		state.stateObjectsDirty[addr] = struct{}{}
	}
	for hash, logs := range self.logs {
		state.logs[hash] = make([]*types.Log, len(logs))
		copy(state.logs[hash], logs)
	}
	for hash, preimage := range self.preimages {
		state.preimages[hash] = preimage
	}
	return state
}

// Snapshot returns an identifier for the current revision of the state.
func (self *StateDB) Snapshot() int {
	id := self.nextRevisionId
	self.nextRevisionId++
	self.validRevisions = append(self.validRevisions, revision{id, len(self.journal)})
	return id
}

// RevertToSnapshot reverts all state changes made since the given revision.
func (self *StateDB) RevertToSnapshot(revid int) {
	// Find the snapshot in the stack of valid snapshots.
	idx := sort.Search(len(self.validRevisions), func(i int) bool {
		return self.validRevisions[i].id >= revid
	})
	if idx == len(self.validRevisions) || self.validRevisions[idx].id != revid {
		panic(fmt.Errorf("revision id %v cannot be reverted", revid))
	}
	snapshot := self.validRevisions[idx].journalIndex

	// Replay the journal to undo changes.
	for i := len(self.journal) - 1; i >= snapshot; i-- {
		self.journal[i].undo(self)
	}
	self.journal = self.journal[:snapshot]

	// Remove invalidated snapshots from the stack.
	self.validRevisions = self.validRevisions[:idx]
}

// GetRefund returns the current value of the refund counter.
// The return value must not be modified by the caller and will become
// invalid at the next call to AddRefund.
func (self *StateDB) GetRefund() *big.Int {
	return self.refund
}

// IntermediateRoot computes the current root hash of the state trie.
// It is called in between transactions to get the root hash that
// goes into transaction receipts.
func (s *StateDB) IntermediateRoot(deleteEmptyObjects bool) ethcmn.Hash {
	for addr := range s.stateObjectsDirty {
		stateObject := s.stateObjects[addr]
		if stateObject.suicided || (deleteEmptyObjects && stateObject.empty()) {
			s.deleteStateObject(stateObject)
		} else {
			stateObject.updateRoot(s.db)
			s.updateStateObject(stateObject)
		}
	}
	// Invalidate journal because reverting across transactions is not allowed.
	s.clearJournalAndRefund()
	return s.trie.Hash()
}

// DeleteSuicides flags the suicided objects for deletion so that it
// won't be referenced again when called / queried up on.
//
// DeleteSuicides should not be used for consensus related updates
// under any circumstances.
func (s *StateDB) DeleteSuicides() {
	// Reset refund so that any used-gas calculations can use this method.
	s.clearJournalAndRefund()
	for addr := range s.stateObjectsDirty {
		stateObject := s.stateObjects[addr]

		// If the object has been removed by a suicide
		// flag the object as deleted.
		if stateObject.suicided {
			stateObject.deleted = true
		}
		delete(s.stateObjectsDirty, addr)
	}
}

// Commit commits all state changes to the database.
func (s *StateDB) Commit(deleteEmptyObjects bool) (root ethcmn.Hash, err error) {
	root, batch := s.CommitBatch(deleteEmptyObjects)
	return root, batch.Write()
}

// CommitBatch commits all state changes to a write batch but does not
// execute the batch. It is used to validate state changes against
// the root hash stored in a b.
func (s *StateDB) CommitBatch(deleteEmptyObjects bool) (root ethcmn.Hash, batch ethdb.Batch) {
	batch = s.db.NewBatch()
	root, _ = s.commit(batch, deleteEmptyObjects)

	//glog.V(logger.Debug).Infof("Trie cache stats: %d misses, %d unloads", trie.CacheMisses(), trie.CacheUnloads())
	logger.Debug("[statedb],commitBatch,trie cache stats", zap.Int64("misses", trie.CacheMisses()), zap.Int64("unloads", trie.CacheUnloads()))
	return root, batch
}

func (s *StateDB) clearJournalAndRefund() {
	s.journal = nil
	s.validRevisions = s.validRevisions[:0]
	s.refund = new(big.Int)
}

func (s *StateDB) commit(dbw trie.DatabaseWriter, deleteEmptyObjects bool) (root ethcmn.Hash, err error) {
	defer s.clearJournalAndRefund()

	// Commit objects to the trie.
	for addr, stateObject := range s.stateObjects {
		_, isDirty := s.stateObjectsDirty[addr]
		switch {
		case stateObject.suicided || (isDirty && deleteEmptyObjects && stateObject.empty()):
			// If the object has been removed, don't bother syncing it
			// and just mark it for deletion in the trie.
			s.deleteStateObject(stateObject)
		case isDirty:
			// Write any contract code associated with the state object
			if stateObject.code != nil && stateObject.dirtyCode {
				if err := dbw.Put(stateObject.ByteCodeHash(), stateObject.byteCode); err != nil {
					return ethcmn.Hash{}, err
				}
				if err := dbw.Put(stateObject.CodeHash(), stateObject.code); err != nil {
					return ethcmn.Hash{}, err
				}
				stateObject.dirtyCode = false
			}
			// Write any storage changes in the state object to its storage trie.
			if err := stateObject.CommitTrie(s.db, dbw); err != nil {
				return ethcmn.Hash{}, err
			}
			// Update the object in the main account trie.
			s.updateStateObject(stateObject)
		}
		delete(s.stateObjectsDirty, addr)
	}
	// Write trie changes.
	root, err = s.trie.CommitTo(dbw)

	if err == nil {
		s.pushTrie(s.trie)
	}
	return root, err
}

// should be read only
func (s *StateDB) ExecAllAccount(root ethcmn.Hash, exec func(a *Account)) {
	tr, err := trie.NewSecure(root, s.db, 1) // cache to 1???
	if err != nil {
		logger.Warn("[stateDB],execAllObject,get trie", zap.String("root", root.Hex()), zap.String("err", err.Error()))
		return
	}

	it := tr.Iterator()
	var acc *Account
	for it.Next() {
		addr := ethcmn.BytesToAddress(it.Key)
		if stateObject, ok := s.stateObjects[addr]; ok {
			if stateObject.suicided {
				continue
			}
			acc = &stateObject.data
		} else {
			acc = &Account{}
			err := rlp.DecodeBytes(it.Value, acc)
			if err != nil {
				logger.Warn("[stateDB],execAllObject,rlp decode", zap.String("addr", string(it.Key)), zap.String("err", err.Error()))
				continue
			}
		}
		exec(acc)
	}
}

func (self *StateDB) GetCode(addr ethcmn.Address) []byte {
	stateObject := self.GetStateObject(addr)
	if stateObject != nil {
		code := stateObject.Code(self.db)
		key := ethcmn.BytesToHash(stateObject.CodeHash())
		self.codeSizeCache.Add(key, len(code))
		return code
	}
	return nil
}

func (self *StateDB) GetByteCode(addr ethcmn.Address) []byte {
	stateObject := self.GetStateObject(addr)
	if stateObject != nil {
		byteCode := stateObject.ByteCode(self.db)
		return byteCode
	}
	return nil
}

func (self *StateDB) GetCodeHash(addr ethcmn.Address) ethcmn.Hash {
	stateObject := self.GetStateObject(addr)
	if stateObject == nil {
		return ethcmn.Hash{}
	}
	return ethcmn.BytesToHash(stateObject.CodeHash())
}
func (self *StateDB) GetCodeSize(addr ethcmn.Address) int {
	stateObject := self.GetStateObject(addr)
	if stateObject == nil {
		return 0
	}
	key := ethcmn.BytesToHash(stateObject.CodeHash())
	if cached, ok := self.codeSizeCache.Get(key); ok {
		return cached.(int)
	}
	size := len(stateObject.Code(self.db))
	if stateObject.dbErr == nil {
		self.codeSizeCache.Add(key, size)
	}
	return size
}
