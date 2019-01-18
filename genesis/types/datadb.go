// Copyright 2017 ZhongAn Information Technology Services Co.,Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package types

import (
	"math/big"
	"time"

	ethcmn "github.com/dappledger/AnnChain/genesis/eth/common"
)

// TradeData object for app
type TradeData struct {
	TradeID       uint64         `json:"id"`
	OfferID       uint64         `json:"offerid"`
	Seller        ethcmn.Address `json:"seller"`
	SellingAmount *big.Int       `json:"sellingamount"`
	Buyer         ethcmn.Address `json:"buyer"`
	BuyingAmount  *big.Int       `json:"boughtamount"`
	CreateDate    uint64         `json:"create_at"`
}

// LedgerHeaderData object for app
type LedgerHeaderData struct {
	LedgerID         uint64            `json:"id"`
	Height           *big.Int          `json:"height"`
	Hash             ethcmn.LedgerHash `json:"hash"`
	PrevHash         ethcmn.LedgerHash `json:"prev_hash"`
	TransactionCount uint64            `json:"transaction_count"`
	ClosedAt         *big.Int          `json:"closed_at"`
	TotalCoins       *big.Int          `json:"total_coins"`
	BaseFee          *big.Int          `json:"base_fee"`
	MaxTxSetSize     uint64            `json:"max_tx_set_size"`
}

// LedgerHeaderData object for app
type QueryLedgerHeaderData struct {
	LedgerID         uint64   `json:"id"`
	Height           *big.Int `json:"height"`
	Hash             string   `json:"hash"`
	PrevHash         string   `json:"prev_hash"`
	TransactionCount uint64   `json:"transaction_count"`
	ClosedAt         *big.Int `json:"closed_at"`
	TotalCoins       *big.Int `json:"total_coins"`
	BaseFee          *big.Int `json:"base_fee"`
	MaxTxSetSize     uint64   `json:"max_tx_set_size"`
}

// TransactionData object for app
type TransactionData struct {
	TxID       uint64            `json:"txid"`
	TxHash     ethcmn.Hash       `json:"hash"`
	LedgerHash ethcmn.LedgerHash `json:"-"`
	Height     *big.Int          `json:"height"`
	CreateDate *big.Int          `json:"created_at"`
	Account    ethcmn.Address    `json:"from"`
	Target     ethcmn.Address    `json:"to"`
	OpType     string            `json:"optype"`
	//	Operation       interface{}       `json:"operation"`
	AccountSequence *big.Int `json:"nonce"`
	FeePaid         *big.Int `json:"basefee"`
	ResultCode      uint     `json:"result_code"`
	ResultCodes     string   `json:"result_code_s"`
	Memo            string   `json:"memo"`
}

// ActionData object for app
type ActionData struct {
	ActionID uint64
	JSONData string
}

type LedgerHeaderQueryData struct {
	Height           *big.Int  `json:"height"`
	Hash             string    `json:"hash"`
	PrevHash         string    `json:"prev_hash"`
	TransactionCount uint64    `json:"transaction_count"`
	ClosedAt         time.Time `json:"closed_at"`
	TotalCoins       *big.Int  `json:"total_coins"`
	BaseFee          *big.Int  `json:"base_fee"`
	MaxTxSetSize     uint64    `json:"max_tx_set_size"`
}

type TransactionQueryData struct {
	Hash     ethcmn.Hash    `json:"hash"`
	Height   *big.Int       `json:"height"`
	CreateAt int64          `json:"created_at"`
	From     ethcmn.Address `json:"from"`
	Target   ethcmn.Address `json:"to"`
	Nonce    *big.Int       `json:"nonce"`
	BaseFee  *big.Int       `json:"basefee"`
	OpType   string         `json:"optype"`
	Memo     string         `json:"memo"`
}

// ActionObject interface
type ActionObject interface {
	GetActionBase() *ActionBase
	// SetTxhash(txhash ethcmn.Hash)
}
type ManageDataCategory struct {
	Value    string `json:"value"`
	Category string `json:"category"`
}

// GetActionBase interface impl
func (a *ActionBase) GetActionBase() *ActionBase {
	return a
}

type ValueCategory struct {
	Value    string
	Category string
}

type (
	// ActionBase object for app(Action-Base)
	ActionBase struct {
		Typei       TYPE_OP        `json:"type_i"`
		Type        OP_NAME        `json:"optype"`
		Height      *big.Int       `json:"height"`
		TxHash      ethcmn.Hash    `json:"hash"`
		FromAccount ethcmn.Address `json:"from"` // only used in payment
		ToAccount   ethcmn.Address `json:"to"`   // only used in payment
		CreateAt    uint64         `json:"created_at"`
		Nonce       uint64         `json:"nonce"`
		BaseFee     *big.Int       `json:"basefee"`
		Memo        string         `json:"memo"`
	}

	// ActionCreateAccount object for app(Action-CreateAccount)
	ActionCreateAccount struct {
		ActionBase
		StartingBalance *big.Int `json:"starting_balance"`
	}

	// ActionPayment object for app(Action-Payment)
	ActionPayment struct {
		ActionBase
		From   ethcmn.Address `json:"from"`
		To     ethcmn.Address `json:"to"`
		Amount string         `json:"amount"`
	}

	ActionManageData struct {
		ActionBase
		KeyPair map[string]ValueCategory `json:"keypair"`
		Source  ethcmn.Address           `json:"source_account"`
	}

	ActionCreateContract struct {
		ActionBase
		ContractAddr string `json:"contract_address"`
		Price        string `json:"gas_price"`
		Amount       string `json:"amount"`
		GasLimit     string `json:"gas_limit"`
		Gas          string `json:"gas_used"`
	}

	ActionExcuteContract struct {
		ActionBase
		ContractAddr string `json:"contract_address"`
		Price        string `json:"price"`
		Amount       string `json:"amount"`
		GasLimit     string `json:"gas_limit"`
		Gas          string `json:"gas"`
	}
)

// EffectData object for app
type EffectData struct {
	EffectID uint64
	JSONData string
}

// EffectObject interface
type EffectObject interface {
	GetEffectBase() *EffectBase
}

// GetEffectBase interface impl
func (a *EffectBase) GetEffectBase() *EffectBase {
	return a
}

type (
	// EffectBase object for app(Effect-Base)
	EffectBase struct {
		Typei    TYPE_EFFECT    `json:"type_i"`
		Type     string         `json:"type"`
		Height   *big.Int       `json:"-"`
		TxHash   ethcmn.Hash    `json:"-"`
		ActionID uint64         `json:"-"`
		Account  ethcmn.Address `json:"-"`
		CreateAt uint64         `json:"created_at"`
	}

	// EffectAccountCreated object for app(Effect-AccountCreated)
	EffectAccountCreated struct {
		EffectBase
		StartingBalance *big.Int `json:"starting_balance"`
	}

	// EffectAccountCredited object for app(Effect-AccountCredited)
	EffectAccountCredited struct {
		EffectBase
		Amount string `json:"amount"`
	}
	// EffectAccountDebited object for app(Effect-AccountDebited)
	EffectAccountDebited struct {
		EffectBase
		Amount string `json:"amount"`
	}

	EffectCreateContract struct {
		EffectBase
		ContractAddr string `json:"contract_address"`
		Price        string `json:"price"`
		Amount       string `json:"amount"`
		GasLimit     string `json:"gas_limit"`
		Gas          string `json:"gas"`
	}

	EffectExcuteContract struct {
		EffectBase
		ContractAddr string `json:"contract_address"`
		Price        string `json:"price"`
		Amount       string `json:"amount"`
		GasLimit     string `json:"gas_limit"`
		Gas          string `json:"gas"`
	}
)

type EffectGroup struct {
	ActionID uint64
	Action   ActionObject
	Effects  []EffectObject
}

type OperationDBItfc interface {

	// ops for Manage AccData
	AddAccData(acct ethcmn.Address, k, v, category string) (uint64, error)
	QueryAccData(acc ethcmn.Address, order string) (map[string]ManageDataCategory, error)

	//=================================================================================================//

	// ops for action(operation)
	AddActionData(o ActionObject) (uint64, error)
	QueryActionData(q ActionsQuery) ([]ActionData, error)

	// ops for effects
	AddEffectData(o EffectObject) (uint64, error)
	QueryEffectData(q EffectsQuery) ([]EffectData, error)

	// ops for ledgerheader
	AddLedgerHeaderData(data *LedgerHeaderData) (uint64, error)
	QueryLedgerHeaderData(seq *big.Int) (*LedgerHeaderQueryData, error)
	QueryAllLedgerHeaderData(cursor, limit uint64, order string) ([]LedgerHeaderQueryData, error)

	// ops for transaction
	AddTransaction(data *TransactionData) (uint64, error)
	QuerySingleTx(txhash *ethcmn.Hash) (*TransactionData, error)
	QueryAccountTxs(accid *ethcmn.Address, cursor, limit uint64, order string) ([]TransactionQueryData, error)
	QueryAllTxs(cursor, limit uint64, order string) ([]TransactionQueryData, error)
}
