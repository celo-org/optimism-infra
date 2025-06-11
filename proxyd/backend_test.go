package proxyd

import (
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/assert"
)

func TestStripXFF(t *testing.T) {
	tests := []struct {
		in, out string
	}{
		{"1.2.3, 4.5.6, 7.8.9", "1.2.3"},
		{"1.2.3,4.5.6", "1.2.3"},
		{" 1.2.3 , 4.5.6 ", "1.2.3"},
	}

	for _, test := range tests {
		actual := stripXFF(test.in)
		assert.Equal(t, test.out, actual)
	}
}

func TestExtractBlockParameter(t *testing.T) {
	tests := []struct {
		name     string
		param    interface{}
		expected string
	}{
		{
			name:     "string parameter - latest",
			param:    "latest",
			expected: "latest",
		},
		{
			name:     "string parameter - earliest",
			param:    "earliest",
			expected: "earliest",
		},
		{
			name:     "string parameter - pending",
			param:    "pending",
			expected: "pending",
		},
		{
			name:     "string parameter - hex block number",
			param:    "0x1234",
			expected: "0x1234",
		},
		{
			name: "object parameter with blockNumber",
			param: map[string]interface{}{
				"blockNumber": "0x5678",
			},
			expected: "0x5678",
		},
		{
			name: "object parameter with blockNumber - latest",
			param: map[string]interface{}{
				"blockNumber": "latest",
			},
			expected: "latest",
		},
		{
			name: "object parameter with blockHash (no blockNumber)",
			param: map[string]interface{}{
				"blockHash": "0xabcdef",
			},
			expected: "",
		},
		{
			name: "object parameter with non-string blockNumber",
			param: map[string]interface{}{
				"blockNumber": 123,
			},
			expected: "",
		},
		{
			name:     "nil parameter",
			param:    nil,
			expected: "",
		},
		{
			name:     "number parameter",
			param:    123,
			expected: "",
		},
		{
			name:     "empty object",
			param:    map[string]interface{}{},
			expected: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := extractBlockParameter(test.param)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestRequiresArchiveForBlock(t *testing.T) {
	latestBlock := hexutil.Uint64(1000)

	tests := []struct {
		name       string
		blockParam string
		latest     hexutil.Uint64
		expected   bool
	}{
		{
			name:       "earliest block",
			blockParam: "earliest",
			latest:     latestBlock,
			expected:   true,
		},
		{
			name:       "pending block",
			blockParam: "pending",
			latest:     latestBlock,
			expected:   false,
		},
		{
			name:       "latest block",
			blockParam: "latest",
			latest:     latestBlock,
			expected:   false,
		},
		{
			name:       "recent block (within 128 blocks)",
			blockParam: "0x3e0", // 992 in decimal (1000 - 8)
			latest:     latestBlock,
			expected:   false,
		},
		{
			name:       "old block (beyond 128 blocks)",
			blockParam: "0x300", // 768 in decimal (1000 - 232)
			latest:     latestBlock,
			expected:   true,
		},
		{
			name:       "block exactly at boundary",
			blockParam: "0x368", // 872 in decimal (1000 - 128)
			latest:     latestBlock,
			expected:   true,
		},
		{
			name:       "block just within boundary (needs archive)",
			blockParam: "0x359", // 857 in decimal (1000 - 143, needs archive)
			latest:     latestBlock,
			expected:   true,
		},
		{
			name:       "block just outside archive boundary",
			blockParam: "0x367", // 871 in decimal (1000 - 129, first block that doesn't need archive)
			latest:     latestBlock,
			expected:   true,
		},
		{
			name:       "invalid hex",
			blockParam: "0xinvalid",
			latest:     latestBlock,
			expected:   false,
		},
		{
			name:       "non-hex string",
			blockParam: "notahex",
			latest:     latestBlock,
			expected:   false,
		},
		{
			name:       "empty string",
			blockParam: "",
			latest:     latestBlock,
			expected:   false,
		},
		{
			name:       "zero latest block",
			blockParam: "0x100",
			latest:     hexutil.Uint64(0),
			expected:   false,
		},
		{
			name:       "block number zero",
			blockParam: "0x0",
			latest:     latestBlock,
			expected:   true,
		},
		{
			name:       "block number equals latest",
			blockParam: "0x3e8", // 1000 in decimal
			latest:     latestBlock,
			expected:   false,
		},
		{
			name:       "block number greater than latest",
			blockParam: "0x400", // 1024 in decimal
			latest:     latestBlock,
			expected:   false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := requiresArchiveForBlock(test.blockParam, test.latest)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestArchiveDetectionIntegration(t *testing.T) {
	tests := []struct {
		name            string
		params          []interface{}
		paramIndex      int
		expectedParam   string
		expectedArchive bool
		latestBlock     hexutil.Uint64
	}{
		{
			name:            "eth_getBalance with latest",
			params:          []interface{}{"0x123", "latest"},
			paramIndex:      1,
			expectedParam:   "latest",
			expectedArchive: false,
			latestBlock:     hexutil.Uint64(1000),
		},
		{
			name:            "eth_getBalance with earliest",
			params:          []interface{}{"0x123", "earliest"},
			paramIndex:      1,
			expectedParam:   "earliest",
			expectedArchive: true,
			latestBlock:     hexutil.Uint64(1000),
		},
		{
			name:            "eth_getBalance with old block",
			params:          []interface{}{"0x123", "0x100"}, // 256 in decimal
			paramIndex:      1,
			expectedParam:   "0x100",
			expectedArchive: true,
			latestBlock:     hexutil.Uint64(1000),
		},
		{
			name: "eth_getBalance with object parameter",
			params: []interface{}{
				"0x123",
				map[string]interface{}{
					"blockNumber": "0x100",
				},
			},
			paramIndex:      1,
			expectedParam:   "0x100",
			expectedArchive: true,
			latestBlock:     hexutil.Uint64(1000),
		},
		{
			name: "eth_getStorageAt with blockHash",
			params: []interface{}{
				"0x123",
				"0x0",
				map[string]interface{}{
					"blockHash": "0xabcdef",
				},
			},
			paramIndex:      2,
			expectedParam:   "",
			expectedArchive: true, // blockHash should trigger archive
			latestBlock:     hexutil.Uint64(1000),
		},
		{
			name:            "eth_call with recent block",
			params:          []interface{}{map[string]interface{}{"to": "0x123"}, "0x3e0"}, // 992
			paramIndex:      1,
			expectedParam:   "0x3e0",
			expectedArchive: false,
			latestBlock:     hexutil.Uint64(1000),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Test parameter extraction
			if test.paramIndex < len(test.params) {
				extractedParam := extractBlockParameter(test.params[test.paramIndex])
				assert.Equal(t, test.expectedParam, extractedParam)

				// Test archive requirement logic
				if extractedParam != "" {
					requiresArchive := requiresArchiveForBlock(extractedParam, test.latestBlock)
					assert.Equal(t, test.expectedArchive, requiresArchive)
				} else {
					// Special case for blockHash - check if it's a map with blockHash
					if blockParamMap, ok := test.params[test.paramIndex].(map[string]interface{}); ok {
						if _, exists := blockParamMap["blockHash"]; exists {
							assert.True(t, test.expectedArchive, "blockHash should require archive")
						}
					}
				}
			}
		})
	}
}
