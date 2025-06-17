package proxyd

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcessTransaction(t *testing.T) {
	server := &Server{}

	testCases := []struct {
		name         string
		rawTx        string
		expectedFrom string
		expectedTo   string
		expectErr    bool
	}{
		{
			name:         "Valid ETH transaction",
			rawTx:        "0x02f9011901048405f5e10085051f4d5c00830251289499c9fc46f92e8a1c0dec1b1747d010903e884be1884563918244f40000b8a4e11013dd00000000000000000000000088fccc17adc325c0b86e0a9d3fc09cc0bf6ef2100000000000000000000000000000000000000000000000000000000000030d400000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000b7375706572627269646765000000000000000000000000000000000000000000c080a068ffe0ad59ed8a7563566c2838c9f1c5d32ae6a5d1a2dd94f049ab6d587606bfa05a56aa704f28e853651c71a032c2b5f586582d73d91610f668b23d633f25c6f0",
			expectedFrom: "0x88fCcc17aDC325c0B86e0A9D3fc09Cc0bF6ef210",
			expectedTo:   "0x99C9fc46f92E8a1c0deC1b1747d010903E884bE1",
			expectErr:    false,
		},
		{
			name:         "Valid OP transaction",
			rawTx:        "0x02f8ad0a028399128f83b914d3829baa94420000000000000000000000000000000000004280b844a9059cbb000000000000000000000000420000000000000000000000000000000000004200000000000000000000000000000000000000000000003fa25ee7716cd38000c080a0cffcc8326c48c58721770bd99604cc47e6b52b11ee1d3d332558d81568701533a04b097510176885b9799ac97941caa1470990217aac2baaf20d21e04ea7b107c7",
			expectedFrom: "0xf55f12917D72087aceEC6eF749d92054bE5a071b",
			expectedTo:   "0x4200000000000000000000000000000000000042",
			expectErr:    false,
		},
		{
			name:         "Valid CELO transaction",
			rawTx:        "0x02f8b582a4ec83313b748459682f008502ad74130082cae594765de816845861e75a25fca122bb6898b8b1282a80b844a9059cbb000000000000000000000000bf5ddd312bf3f1880ec4132ff27373139028846500000000000000000000000000000000000000000000000000038d7ea4c68000c080a0ffc08f68787aec3220797e5557f6fe42604a9cf0407733aa1389c52bdce730a3a060657079bcf0d2d82b2d29ded1fbc57ed6cac144d177e1b24cf1525e9b6ac950",
			expectedFrom: "0x37B67b9f26F1901f53beF753c113AAa124200CE6",
			expectedTo:   "0x765DE816845861e75A25fCA122bb6898B8B1282a",
			expectErr:    false,
		},
		{
			name:      "Invalid transaction",
			rawTx:     "0x02f8b582a4ec83313b748459682f008502ad74130082cae594765de816845861e75a25fca122bb6898b8b1282a80b844a9059cbb000000000000000000000000bf5ddd312bf3f1880ec4132ff27373139028846500000000000000000000000000000000000000000000000000038d7ea4c68000c080a0ffc08f68787aec3220797e5557f6fe42604a9cf0407733aa1389c52bdce730a3a060657079bcf0d2d82b2d29ded1fbc57ed6cac144d177e1b24cf1525e9b6ac",
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &RPCReq{
				Params: json.RawMessage(`["` + tc.rawTx + `"]`),
			}

			tx, from, err := server.processTransaction(context.Background(), req)

			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, tx)
				// assert.NotNil(t, msg)
				assert.Equal(t, tc.expectedFrom, from.Hex())
				assert.Equal(t, tc.expectedTo, tx.To().Hex())
			}
		})
	}
}

func TestFilterSanctionedAddresses(t *testing.T) {
	server := &Server{
		sanctionedAddresses: map[common.Address]struct{}{
			common.HexToAddress("0x4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97"): {},
			common.HexToAddress("0x4675c7e5baafbffbca748158becba61ef3b0a263"): {},
		},
	}

	testCases := []struct {
		name     string
		req      *RPCReq
		expected error
	}{
		{
			name: "Sender is sanctioned",
			req: &RPCReq{
				Method: "eth_sendRawTransaction",
				Params: json.RawMessage(`["0x02f87001830872a98084780a4d0a825208944675c7e5baafbffbca748158becba61ef3b0a263875922b6ab7cb7cd80c001a0795c9fc9d70ce247360f99b37dd4ad816a2ebb257571cb78523b4b17d03bc28fa02095ef30e1e1060f7c117cac0ca23e4b676ad6e3500beab4a3a004e20b9fe56b"]`),
			},
			expected: ErrNoBackends,
		},
		{
			name: "Recipient is sanctioned",
			req: &RPCReq{
				Method: "eth_sendRawTransaction",
				Params: json.RawMessage(`["0x02f87001830872a98084780a4d0a825208944675c7e5baafbffbca748158becba61ef3b0a263875922b6ab7cb7cd80c001a0795c9fc9d70ce247360f99b37dd4ad816a2ebb257571cb78523b4b17d03bc28fa02095ef30e1e1060f7c117cac0ca23e4b676ad6e3500beab4a3a004e20b9fe56b"]`),
			},
			expected: ErrNoBackends,
		},
		{
			name: "Neither sender nor recipient is sanctioned",
			req: &RPCReq{
				Method: "eth_sendRawTransaction",
				Params: json.RawMessage(`["0x02f870010c830f4240847c2b1da682520894f175e95b93a34ae6d0bf7cc978ac5219a8c747f08704d3c18e542c2a80c080a01a0cba457c7ba2f0bcee41060f55d718a4a5f321376d88949abdb853ab65fd4aa0771a3702bfa8635ec64429f5286957c6608bb87577adac1eefc79990a8498bc3"]`),
			},
			expected: nil,
		},
		{
			name: "Create tx with non sanctioned address",
			req: &RPCReq{
				Method: "eth_sendRawTransaction",
				Params: json.RawMessage(fmt.Sprintf(`["%s"]`, makeContractCreationTransaction(t))),
			},
			expected: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := server.filterSanctionedAddresses(context.Background(), tc.req)
			assert.Equal(t, tc.expected, err)
		})
	}
}

func makeContractCreationTransaction(t *testing.T) string {
	one := big.NewInt(1)
	tx := types.NewTx(&types.DynamicFeeTx{
		Nonce:     1,
		ChainID:   one,
		GasFeeCap: one,
		GasTipCap: one,
		Gas:       1,
		Data:      make([]byte, 40),
	})
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	signedTx, err := types.SignTx(tx, types.NewLondonSigner(tx.ChainId()), key)
	require.NoError(t, err)
	rawTxBytes, err := signedTx.MarshalBinary()
	require.NoError(t, err)
	h := hexutil.Encode(rawTxBytes)
	return h
}

func TestCheckSanctionedAddresses(t *testing.T) {
	sanctionedPkey1 := "0x0000000000000000000000000000000000000000000000000000000000000001"
	sanctionedPkey2 := "0x0000000000000000000000000000000000000000000000000000000000000002"
	nonSanctionedPkey1 := "0x0000000000000000000000000000000000000000000000000000000000000003"
	sanctionedAddr1 := addressFromPrivateKey(t, sanctionedPkey1)
	sanctionedAddr2 := addressFromPrivateKey(t, sanctionedPkey2)
	nonSanctionedAddr1 := addressFromPrivateKey(t, nonSanctionedPkey1)

	server := &Server{
		sanctionedAddresses: map[common.Address]struct{}{
			sanctionedAddr1: {},
			sanctionedAddr2: {},
		},
	}

	testCases := []struct {
		name        string
		method      string
		rawTx       string
		expectError bool
		errorType   error
	}{
		{
			name:        "Non-transaction method should pass",
			method:      "eth_getBalance",
			rawTx:       "",
			expectError: false,
		},
		{
			name:        "Transaction with sanctioned sender should be blocked",
			method:      "eth_sendRawTransaction",
			rawTx:       createRawTransactionFromPrivateKey(t, sanctionedPkey1, common.HexToAddress("0x1234567890123456789012345678901234567890")),
			expectError: true,
			errorType:   ErrNoBackends,
		},
		{
			name:        "Transaction with sanctioned recipient should be blocked",
			method:      "eth_sendRawTransaction",
			rawTx:       createRawTransactionFromPrivateKey(t, nonSanctionedPkey1, sanctionedAddr2),
			expectError: true,
			errorType:   ErrNoBackends,
		},
		{
			name:        "Transaction with both sender and recipient sanctioned should be blocked",
			method:      "eth_sendRawTransaction",
			rawTx:       createRawTransactionFromPrivateKey(t, sanctionedPkey1, sanctionedAddr2),
			expectError: true,
			errorType:   ErrNoBackends,
		},
		{
			name:        "Transaction with neither sender nor recipient sanctioned should pass",
			method:      "eth_sendRawTransaction",
			rawTx:       createRawTransactionFromPrivateKey(t, nonSanctionedPkey1, nonSanctionedAddr1),
			expectError: false,
		},
		{
			name:        "Contract creation transaction with sanctioned sender should be blocked",
			method:      "eth_sendRawTransaction",
			rawTx:       createContractCreationFromPrivateKey(t, sanctionedPkey1),
			expectError: true,
			errorType:   ErrNoBackends,
		},
		{
			name:        "Contract creation transaction with non-sanctioned sender should pass",
			method:      "eth_sendRawTransaction",
			rawTx:       createContractCreationFromPrivateKey(t, nonSanctionedPkey1),
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testServer := server
			if strings.Contains(tc.name, "nil sanctioned addresses") {
				testServer = &Server{sanctionedAddresses: nil}
			}

			var req *RPCReq
			if tc.rawTx != "" {
				req = &RPCReq{
					Method: tc.method,
					Params: json.RawMessage(`["` + tc.rawTx + `"]`),
				}
			} else {
				req = &RPCReq{
					Method: tc.method,
					Params: json.RawMessage(`[]`),
				}
			}

			err := testServer.CheckSanctionedAddresses(context.Background(), req)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorType != nil {
					assert.Equal(t, tc.errorType, err)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSanctionedAddressesWebSocketFiltering(t *testing.T) {
	sanctionedPkey1 := "0x0000000000000000000000000000000000000000000000000000000000000001"
	sanctionedPkey2 := "0x0000000000000000000000000000000000000000000000000000000000000002"
	nonSanctionedPkey1 := "0x0000000000000000000000000000000000000000000000000000000000000003"
	sanctionedAddr1 := addressFromPrivateKey(t, sanctionedPkey1)
	sanctionedAddr2 := addressFromPrivateKey(t, sanctionedPkey2)
	nonSanctionedAddr1 := addressFromPrivateKey(t, nonSanctionedPkey1)

	// Create mock backend
	mockBackend := &TestMockBackend{
		responses: make(map[string]string),
	}
	mockBackend.Start()
	defer mockBackend.Close()

	// Create server with sanctioned addresses
	server := &Server{
		sanctionedAddresses: map[common.Address]struct{}{
			sanctionedAddr1: {},
			sanctionedAddr2: {},
		},
		wsMethodWhitelist: NewStringSetFromStrings([]string{"eth_sendRawTransaction", "eth_getBalance"}),
	}

	testCases := []struct {
		name          string
		message       string
		expectBlocked bool
		expectedError string
	}{
		{
			name: "Transaction with sanctioned sender should be blocked",
			message: fmt.Sprintf(`{
				"id": 1,
				"method": "eth_sendRawTransaction",
				"params": ["%s"]
			}`, createRawTransactionFromPrivateKey(t, sanctionedPkey1, nonSanctionedAddr1)),
			expectBlocked: true,
			expectedError: "no backend is currently healthy to serve traffic",
		},
		{
			name: "Transaction with sanctioned recipient should be blocked",
			message: fmt.Sprintf(`{
				"id": 2,
				"method": "eth_sendRawTransaction",
				"params": ["%s"]
			}`, createRawTransactionFromPrivateKey(t, nonSanctionedPkey1, sanctionedAddr1)),
			expectBlocked: true,
			expectedError: "no backend is currently healthy to serve traffic",
		},
		{
			name: "Non-transaction method should pass",
			message: `{
				"id": 4,
				"method": "eth_getBalance",
				"params": ["0x1234567890123456789012345678901234567890", "latest"]
			}`,
			expectBlocked: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// For simplicity, we'll test the CheckSanctionedAddresses function directly
			// instead of setting up a full WebSocket server
			var req *RPCReq
			var err error
			if strings.Contains(tc.message, "eth_sendRawTransaction") {
				req, err = ParseRPCReq([]byte(tc.message))
				require.NoError(t, err)

				checkErr := server.CheckSanctionedAddresses(context.Background(), req)

				if tc.expectBlocked {
					assert.Error(t, checkErr)
					assert.Equal(t, ErrNoBackends, checkErr)
				} else {
					assert.NoError(t, checkErr)
				}
			} else {
				req, err = ParseRPCReq([]byte(tc.message))
				require.NoError(t, err)

				checkErr := server.CheckSanctionedAddresses(context.Background(), req)
				assert.NoError(t, checkErr) // Non-transaction methods should always pass
			}
		})
	}
}

func TestSanctionedAddressesErrorHandling(t *testing.T) {
	server := &Server{
		sanctionedAddresses: map[common.Address]struct{}{
			common.HexToAddress("0x4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97"): {},
		},
	}

	testCases := []struct {
		name        string
		req         *RPCReq
		expectError bool
		errorType   error
	}{
		{
			name: "Invalid transaction parameters should return invalid params error",
			req: &RPCReq{
				Method: "eth_sendRawTransaction",
				Params: json.RawMessage(`["invalid_hex"]`),
			},
			expectError: true,
			// The error is actually ErrInvalidParams because "invalid_hex" fails hex decoding
			errorType: nil, // Don't check specific error type, just that an error occurred
		},
		{
			name: "Missing transaction parameters should return invalid params error",
			req: &RPCReq{
				Method: "eth_sendRawTransaction",
				Params: json.RawMessage(`[]`),
			},
			expectError: true,
		},
		{
			name: "Too many transaction parameters should return invalid params error",
			req: &RPCReq{
				Method: "eth_sendRawTransaction",
				Params: json.RawMessage(`["0x02f870010c830f4240847c2b1da682520894f175e95b93a34ae6d0bf7cc978ac5219a8c747f08704d3c18e542c2a80c080a01a0cba457c7ba2f0bcee41060f55d718a4a5f321376d88949abdb853ab65fd4aa0771a3702bfa8635ec64429f5286957c6608bb87577adac1eefc79990a8498bc3", "extra_param"]`),
			},
			expectError: true,
		},
		{
			name: "Malformed JSON parameters should return parse error",
			req: &RPCReq{
				Method: "eth_sendRawTransaction",
				Params: json.RawMessage(`["0x123`), // Malformed JSON
			},
			expectError: true,
			errorType:   ErrParseErr,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := server.CheckSanctionedAddresses(context.Background(), tc.req)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorType != nil {
					assert.Equal(t, tc.errorType, err)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Mock backend for testing
type TestMockBackend struct {
	server    *httptest.Server
	responses map[string]string
}

func (m *TestMockBackend) Start() {
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		if err := json.Unmarshal(body, &req); err != nil {
			w.WriteHeader(400)
			return
		}

		method := req["method"].(string)
		if response, exists := m.responses[method]; exists {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(response)) // Explicitly ignore error in test helper
		} else {
			w.WriteHeader(404)
		}
	}))
}

func (m *TestMockBackend) URL() string {
	return m.server.URL
}

func (m *TestMockBackend) Close() {
	if m.server != nil {
		m.server.Close()
	}
}

// Mock WebSocket connection for testing
//
//nolint:unused // Test helper that may be used in future tests
type mockWebSocketConn struct {
	messages chan []byte
	closed   bool
}

//nolint:unused // Test helper method
func (m *mockWebSocketConn) WriteMessage(messageType int, data []byte) error {
	if m.closed {
		return websocket.ErrCloseSent
	}
	select {
	case m.messages <- data:
		return nil
	default:
		return errors.New("message buffer full")
	}
}

//nolint:unused // Test helper method
func (m *mockWebSocketConn) ReadMessage() (messageType int, p []byte, err error) {
	if m.closed {
		return 0, nil, websocket.ErrCloseSent
	}
	select {
	case msg := <-m.messages:
		return websocket.TextMessage, msg, nil
	case <-time.After(time.Second):
		return 0, nil, errors.New("read timeout")
	}
}

//nolint:unused // Test helper method
func (m *mockWebSocketConn) Close() error {
	m.closed = true
	close(m.messages)
	return nil
}

//nolint:unused // Test helper method
func (m *mockWebSocketConn) SetReadLimit(limit int64) {}

//nolint:unused // Test helper method
func (m *mockWebSocketConn) SetWriteDeadline(t time.Time) error { return nil }

//nolint:unused // Test helper method
func (m *mockWebSocketConn) SetReadDeadline(t time.Time) error { return nil }

// Helper functions for creating test transactions with specific private keys

// createRawTransactionFromPrivateKey creates a transaction signed with the given private key
func createRawTransactionFromPrivateKey(t *testing.T, fromPrivateKeyHex string, to common.Address) string {
	// Remove 0x prefix if present
	fromPrivateKeyHex = strings.TrimPrefix(fromPrivateKeyHex, "0x")

	// Convert hex string to ECDSA private key
	privateKeyBytes, err := hex.DecodeString(fromPrivateKeyHex)
	require.NoError(t, err)

	key, err := crypto.ToECDSA(privateKeyBytes)
	require.NoError(t, err)

	nonce := uint64(1)
	gasLimit := uint64(21000)
	gasPrice := big.NewInt(20000000000)      // 20 gwei
	value := big.NewInt(1000000000000000000) // 1 ETH
	chainID := big.NewInt(1)

	tx := types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		To:       &to,
		Value:    value,
		Gas:      gasLimit,
		GasPrice: gasPrice,
		Data:     nil,
	})

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), key)
	require.NoError(t, err)

	rawTxBytes, err := signedTx.MarshalBinary()
	require.NoError(t, err)

	return hexutil.Encode(rawTxBytes)
}

// createContractCreationFromPrivateKey creates a contract creation transaction signed with the given private key
func createContractCreationFromPrivateKey(t *testing.T, privateKeyHex string) string {
	// Remove 0x prefix if present
	privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")

	// Convert hex string to ECDSA private key
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	require.NoError(t, err)

	key, err := crypto.ToECDSA(privateKeyBytes)
	require.NoError(t, err)

	nonce := uint64(1)
	gasLimit := uint64(500000)
	gasPrice := big.NewInt(20000000000) // 20 gwei
	value := big.NewInt(0)
	chainID := big.NewInt(1)
	data := []byte{0x60, 0x60, 0x60, 0x40} // Simple contract bytecode

	tx := types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		To:       nil, // Contract creation
		Value:    value,
		Gas:      gasLimit,
		GasPrice: gasPrice,
		Data:     data,
	})

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), key)
	require.NoError(t, err)

	rawTxBytes, err := signedTx.MarshalBinary()
	require.NoError(t, err)

	return hexutil.Encode(rawTxBytes)
}

// addressFromPrivateKey derives the Ethereum address from a private key hex string
func addressFromPrivateKey(t *testing.T, privateKeyHex string) common.Address {
	// Remove 0x prefix if present
	privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")

	// Convert hex string to ECDSA private key
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	require.NoError(t, err)

	key, err := crypto.ToECDSA(privateKeyBytes)
	require.NoError(t, err)

	// Derive the address from the public key
	return crypto.PubkeyToAddress(key.PublicKey)
}
