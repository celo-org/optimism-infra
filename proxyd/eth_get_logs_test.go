package proxyd

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

const (
	blockedAddr = "0x2ca1bf1a40e2b77608345eeb5dea41cdc071d43c"
	otherAddr   = "0x1111111111111111111111111111111111111111"
)

func getLogsReq(t *testing.T, filter map[string]interface{}) *RPCReq {
	t.Helper()
	params, err := json.Marshal([]interface{}{filter})
	require.NoError(t, err)
	return &RPCReq{Method: "eth_getLogs", Params: params, ID: json.RawMessage(`1`)}
}

func TestParseGetLogsFilter(t *testing.T) {
	tests := []struct {
		name      string
		params    string
		wantOK    bool
		wantAddrs []string
		wantFrom  string
		wantTo    string
		wantHash  string
	}{
		{name: "single address string", params: `[{"address":"` + blockedAddr + `","fromBlock":"0x1","toBlock":"0x2"}]`, wantOK: true, wantAddrs: []string{blockedAddr}, wantFrom: "0x1", wantTo: "0x2"},
		{name: "address array", params: `[{"address":["` + blockedAddr + `","` + otherAddr + `"]}]`, wantOK: true, wantAddrs: []string{blockedAddr, otherAddr}},
		{name: "no address", params: `[{"fromBlock":"0x1"}]`, wantOK: true, wantAddrs: nil, wantFrom: "0x1"},
		{name: "blockHash", params: `[{"blockHash":"0xabc"}]`, wantOK: true, wantHash: "0xabc"},
		{name: "empty address string ignored", params: `[{"address":""}]`, wantOK: true, wantAddrs: nil},
		{name: "malformed object", params: `["nope"]`, wantOK: false},
		{name: "empty params", params: `[]`, wantOK: false},
		{name: "not json", params: `garbage`, wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, ok := parseGetLogsFilter(json.RawMessage(tt.params))
			require.Equal(t, tt.wantOK, ok)
			if !tt.wantOK {
				return
			}
			require.Equal(t, tt.wantAddrs, f.addresses)
			require.Equal(t, tt.wantFrom, f.fromBlock)
			require.Equal(t, tt.wantTo, f.toBlock)
			require.Equal(t, tt.wantHash, f.blockHash)
		})
	}
}

func TestAnyBlocked(t *testing.T) {
	blocked := map[common.Address]struct{}{common.HexToAddress(blockedAddr): {}}

	require.True(t, anyBlocked([]string{blockedAddr}, blocked))
	require.True(t, anyBlocked([]string{otherAddr, blockedAddr}, blocked))
	// case-insensitive match
	require.True(t, anyBlocked([]string{common.HexToAddress(blockedAddr).Hex()}, blocked))
	require.False(t, anyBlocked([]string{otherAddr}, blocked))
	require.False(t, anyBlocked(nil, blocked))
	// invalid hex is ignored, not matched
	require.False(t, anyBlocked([]string{"not-an-address"}, blocked))
}

func TestBlockSpan(t *testing.T) {
	// latest=12000, safe=10000, finalized=9000 mirrors a chain where safe/finalized
	// lag latest.
	lagging := consensusHeads{latest: 12000, safe: 10000, finalized: 9000, known: true}

	tests := []struct {
		name     string
		from, to string
		heads    consensusHeads
		wantSpan uint64
		wantOK   bool
	}{
		{name: "numeric range", from: "0x10", to: "0x20", wantSpan: 0x10, wantOK: true},
		{name: "earliest to number", from: "earliest", to: "0x64", wantSpan: 100, wantOK: true},
		{name: "latest with head", from: "0x0", to: "latest", heads: consensusHeads{latest: 50, known: true}, wantSpan: 50, wantOK: true},
		{name: "latest without head not resolvable", from: "0x0", to: "latest", wantOK: false},
		{name: "absent bounds default latest", from: "", to: "", heads: consensusHeads{latest: 0, known: true}, wantSpan: 0, wantOK: true},
		{name: "pending", from: "0x0", to: "pending", heads: consensusHeads{latest: 9, known: true}, wantSpan: 10, wantOK: true},
		// finalized/safe resolve against their own heads, not latest.
		{name: "finalized uses finalized head", from: "0x2000", to: "finalized", heads: lagging, wantSpan: 9000 - 0x2000, wantOK: true},
		{name: "safe uses safe head", from: "safe", to: "latest", heads: lagging, wantSpan: 2000, wantOK: true},
		{name: "finalized unknown not resolvable", from: "0x0", to: "finalized", heads: consensusHeads{latest: 100, known: true}, wantOK: false},
		{name: "inverted range not ok", from: "0x20", to: "0x10", wantOK: false},
		{name: "unparseable bound not ok", from: "0xzz", to: "0x10", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &getLogsFilter{fromBlock: tt.from, toBlock: tt.to}
			span, ok := blockSpan(f, tt.heads)
			require.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				require.Equal(t, tt.wantSpan, span)
			}
		})
	}
}

func TestNewEthGetLogsLimits(t *testing.T) {
	// defaults applied when unset
	def := newEthGetLogsLimits(EthGetLogsConfig{})
	require.Equal(t, uint64(defaultEthGetLogsMaxBlockRange), def.maxBlockRange)
	require.Equal(t, defaultEthGetLogsMaxAddressCount, def.maxAddressCount)
	require.Equal(t, defaultEthGetLogsErrorMessage, def.errorMessage)
	require.Empty(t, def.blockedAddresses)

	// explicit values kept, invalid address discarded
	lim := newEthGetLogsLimits(EthGetLogsConfig{
		BlockedAddresses: []string{blockedAddr, "garbage"},
		MaxBlockRange:    100,
		MaxAddressCount:  3,
		ErrorMessage:     "nope",
	})
	require.Equal(t, uint64(100), lim.maxBlockRange)
	require.Equal(t, 3, lim.maxAddressCount)
	require.Equal(t, "nope", lim.errorMessage)
	require.Len(t, lim.blockedAddresses, 1)
	_, ok := lim.blockedAddresses[common.HexToAddress(blockedAddr)]
	require.True(t, ok)
}

func TestApplyEthGetLogsPolicy(t *testing.T) {
	// No BackendGroups -> consensus head unknown, so tag-anchored ranges are
	// skipped and numeric ranges are checked exactly.
	s := &Server{ethGetLogs: newEthGetLogsLimits(EthGetLogsConfig{
		BlockedAddresses: []string{blockedAddr},
		MaxBlockRange:    5000,
		MaxAddressCount:  25,
	})}
	ctx := context.Background()

	isEmptyArray := func(t *testing.T, res *RPCRes) {
		t.Helper()
		raw, ok := res.Result.(json.RawMessage)
		require.True(t, ok)
		require.Equal(t, "[]", string(raw))
	}

	t.Run("blocked address served empty", func(t *testing.T) {
		res, rpcErr := s.applyEthGetLogsPolicy(ctx, getLogsReq(t, map[string]interface{}{"address": blockedAddr}), "")
		require.Nil(t, rpcErr)
		require.NotNil(t, res)
		isEmptyArray(t, res)
	})

	t.Run("blocked address in array served empty", func(t *testing.T) {
		res, rpcErr := s.applyEthGetLogsPolicy(ctx, getLogsReq(t, map[string]interface{}{"address": []string{otherAddr, blockedAddr}}), "")
		require.Nil(t, rpcErr)
		require.NotNil(t, res)
		isEmptyArray(t, res)
	})

	t.Run("normal request forwarded", func(t *testing.T) {
		res, rpcErr := s.applyEthGetLogsPolicy(ctx, getLogsReq(t, map[string]interface{}{"address": otherAddr, "fromBlock": "0x1", "toBlock": "0x2"}), "")
		require.Nil(t, rpcErr)
		require.Nil(t, res)
	})

	t.Run("address count exceeded rejected", func(t *testing.T) {
		addrs := make([]string, 26)
		for i := range addrs {
			addrs[i] = otherAddr
		}
		res, rpcErr := s.applyEthGetLogsPolicy(ctx, getLogsReq(t, map[string]interface{}{"address": addrs}), "")
		require.Nil(t, res)
		require.NotNil(t, rpcErr)
		require.Contains(t, rpcErr.Message, defaultEthGetLogsErrorMessage)
		require.Contains(t, rpcErr.Message, "25") // configured max address count
		require.Contains(t, rpcErr.Message, "26") // requested count
	})

	t.Run("range exceeded rejected", func(t *testing.T) {
		res, rpcErr := s.applyEthGetLogsPolicy(ctx, getLogsReq(t, map[string]interface{}{"fromBlock": "0x0", "toBlock": "0x1771"}), "") // 6001 blocks
		require.Nil(t, res)
		require.NotNil(t, rpcErr)
		require.Contains(t, rpcErr.Message, defaultEthGetLogsErrorMessage)
		require.Contains(t, rpcErr.Message, "5000") // configured max block range
		require.Contains(t, rpcErr.Message, "6001") // requested span
	})

	t.Run("range at limit allowed", func(t *testing.T) {
		res, rpcErr := s.applyEthGetLogsPolicy(ctx, getLogsReq(t, map[string]interface{}{"fromBlock": "0x0", "toBlock": "0x1388"}), "") // exactly 5000
		require.Nil(t, res)
		require.Nil(t, rpcErr)
	})

	t.Run("blockHash skips range check", func(t *testing.T) {
		res, rpcErr := s.applyEthGetLogsPolicy(ctx, getLogsReq(t, map[string]interface{}{"blockHash": "0xabc"}), "")
		require.Nil(t, res)
		require.Nil(t, rpcErr)
	})

	t.Run("tag range without head skipped", func(t *testing.T) {
		res, rpcErr := s.applyEthGetLogsPolicy(ctx, getLogsReq(t, map[string]interface{}{"fromBlock": "earliest", "toBlock": "latest"}), "")
		require.Nil(t, res)
		require.Nil(t, rpcErr)
	})

	t.Run("malformed params forwarded", func(t *testing.T) {
		res, rpcErr := s.applyEthGetLogsPolicy(ctx, &RPCReq{Method: "eth_getLogs", Params: json.RawMessage(`["nope"]`), ID: json.RawMessage(`1`)}, "")
		require.Nil(t, res)
		require.Nil(t, rpcErr)
	})
}
