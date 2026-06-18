package proxyd

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/log"
)

const (
	defaultEthGetLogsMaxBlockRange   = 1000
	defaultEthGetLogsMaxAddressCount = 5
	defaultEthGetLogsErrorMessage    = "query exceeds range, retry smaller"
)

// reasons recorded on the eth_get_logs_policy_total metric.
const (
	ethGetLogsReasonBlockedAddress       = "blocked_address"
	ethGetLogsReasonAddressCountExceeded = "address_count_exceeded"
	ethGetLogsReasonRangeExceeded        = "range_exceeded"
)

// ethGetLogsLimits holds the resolved policy applied to eth_getLogs requests:
// a blocklist of addresses (served an empty result) and caps on the block range
// and number of addresses per query (rejected with an error).
type ethGetLogsLimits struct {
	blockedAddresses map[common.Address]struct{}
	maxBlockRange    uint64
	maxAddressCount  int
	errorMessage     string
}

// newEthGetLogsLimits builds the runtime policy from config, validating blocked
// addresses and applying defaults for any unset limit.
func newEthGetLogsLimits(cfg EthGetLogsConfig) ethGetLogsLimits {
	blocked := make(map[common.Address]struct{}, len(cfg.BlockedAddresses))
	for _, addr := range cfg.BlockedAddresses {
		if !common.IsHexAddress(addr) {
			log.Warn("invalid eth_getLogs blocked address", "address", addr)
			continue
		}
		blocked[common.HexToAddress(addr)] = struct{}{}
		log.Info("blocking eth_getLogs for address", "address", common.HexToAddress(addr).Hex())
	}

	lim := ethGetLogsLimits{
		blockedAddresses: blocked,
		maxBlockRange:    cfg.MaxBlockRange,
		maxAddressCount:  cfg.MaxAddressCount,
		errorMessage:     cfg.ErrorMessage,
	}
	if lim.maxBlockRange == 0 {
		lim.maxBlockRange = defaultEthGetLogsMaxBlockRange
	}
	if lim.maxAddressCount == 0 {
		lim.maxAddressCount = defaultEthGetLogsMaxAddressCount
	}
	if lim.errorMessage == "" {
		lim.errorMessage = defaultEthGetLogsErrorMessage
	}
	return lim
}

// getLogsFilter holds the parts of an eth_getLogs filter object we care about.
type getLogsFilter struct {
	addresses []string
	fromBlock string
	toBlock   string
	blockHash string
}

// parseGetLogsFilter extracts the address list and block bounds from eth_getLogs
// params. ok is false when the params are absent or malformed, in which case the
// caller should forward the request and let normal validation/the backend handle it.
func parseGetLogsFilter(params json.RawMessage) (*getLogsFilter, bool) {
	var arr []json.RawMessage
	if err := json.Unmarshal(params, &arr); err != nil || len(arr) == 0 {
		return nil, false
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(arr[0], &obj); err != nil {
		return nil, false
	}

	f := &getLogsFilter{
		fromBlock: stringField(obj, "fromBlock"),
		toBlock:   stringField(obj, "toBlock"),
		blockHash: stringField(obj, "blockHash"),
	}

	// The address field is either a single string or an array of strings.
	if raw, ok := obj["address"]; ok {
		var single string
		if err := json.Unmarshal(raw, &single); err == nil {
			if single != "" {
				f.addresses = []string{single}
			}
		} else {
			var many []string
			if err := json.Unmarshal(raw, &many); err == nil {
				f.addresses = many
			}
			// If neither shape matches, leave addresses empty: a malformed
			// address can't match the blocklist and shouldn't be counted.
		}
	}

	return f, true
}

func stringField(obj map[string]json.RawMessage, key string) string {
	raw, ok := obj[key]
	if !ok {
		return ""
	}
	var s string
	_ = json.Unmarshal(raw, &s)
	return s
}

// anyBlocked reports whether any address in the query is in the blocklist.
// Matching is case-insensitive via common.HexToAddress; invalid hex is ignored.
func anyBlocked(addrs []string, blocked map[common.Address]struct{}) bool {
	for _, a := range addrs {
		if !common.IsHexAddress(a) {
			continue
		}
		if _, ok := blocked[common.HexToAddress(a)]; ok {
			return true
		}
	}
	return false
}

// consensusHeads holds the latest/safe/finalized agreed block numbers used to
// resolve eth_getLogs block tags. known is false when no head is available (the
// group isn't consensus-aware, or hasn't agreed on a head yet).
type consensusHeads struct {
	latest    uint64
	safe      uint64
	finalized uint64
	known     bool
}

// blockSpan computes toBlock-fromBlock for the filter. ok is false when a bound
// can't be resolved to a number (e.g. a tag requiring a chain head that isn't
// known, or an inverted range), in which case the range isn't enforced.
func blockSpan(f *getLogsFilter, heads consensusHeads) (uint64, bool) {
	from, ok := resolveLogBlock(f.fromBlock, heads)
	if !ok {
		return 0, false
	}
	to, ok := resolveLogBlock(f.toBlock, heads)
	if !ok {
		return 0, false
	}
	if to < from {
		return 0, false
	}
	return to - from, true
}

// resolveLogBlock turns a fromBlock/toBlock value into a concrete block number.
// An empty value defaults to "latest" (the eth_getLogs default for both bounds).
// safe/finalized resolve against their own consensus heads, matching the tag
// rewriting the consensus group applies before forwarding, so a finalized-anchored
// range isn't measured against the (higher) latest head. ok is false when the
// value needs a head that isn't known, or isn't a recognizable tag or hex quantity.
func resolveLogBlock(tag string, heads consensusHeads) (uint64, bool) {
	switch tag {
	case "", "latest":
		return heads.latest, heads.known
	case "pending":
		return heads.latest + 1, heads.known
	case "safe":
		return heads.safe, heads.known && heads.safe > 0
	case "finalized":
		return heads.finalized, heads.known && heads.finalized > 0
	case "earliest":
		return 0, true
	default:
		n, err := hexutil.DecodeUint64(tag)
		if err != nil {
			return 0, false
		}
		return n, true
	}
}

// applyEthGetLogsPolicy enforces the eth_getLogs blocklist and range/count caps.
// It returns a non-nil *RPCRes to serve directly (empty result for a blocked
// address), a non-nil *RPCErr to reject the request, or (nil, nil) to forward it.
func (s *Server) applyEthGetLogsPolicy(ctx context.Context, req *RPCReq, group string) (*RPCRes, *RPCErr) {
	lim := s.ethGetLogs

	f, ok := parseGetLogsFilter(req.Params)
	if !ok {
		return nil, nil
	}

	// Blocked address -> serve an empty result without hitting a backend.
	if len(lim.blockedAddresses) > 0 && anyBlocked(f.addresses, lim.blockedAddresses) {
		log.Info("blocked eth_getLogs request for blocked address", "req_id", GetReqID(ctx))
		RecordEthGetLogsPolicy(ethGetLogsReasonBlockedAddress)
		RecordRPCForward(ctx, BackendProxyd, "eth_getLogs", RPCRequestSourceHTTP)
		return NewRPCRes(req.ID, emptyArrayResponse), nil
	}

	// Too many addresses in a single query.
	if lim.maxAddressCount > 0 && len(f.addresses) > lim.maxAddressCount {
		log.Info("eth_getLogs address count exceeds limit",
			"count", len(f.addresses), "limit", lim.maxAddressCount, "req_id", GetReqID(ctx))
		RecordEthGetLogsPolicy(ethGetLogsReasonAddressCountExceeded)
		return nil, ErrInvalidParams(fmt.Sprintf("%s (max %d addresses per query, got %d)",
			lim.errorMessage, lim.maxAddressCount, len(f.addresses)))
	}

	// Block range too large. A blockHash query targets a single block, so it has
	// no range to cap.
	if lim.maxBlockRange > 0 && f.blockHash == "" {
		if span, ok := blockSpan(f, s.headsForGroup(group)); ok && span > lim.maxBlockRange {
			log.Info("eth_getLogs block range exceeds limit",
				"span", span, "limit", lim.maxBlockRange, "req_id", GetReqID(ctx))
			RecordEthGetLogsPolicy(ethGetLogsReasonRangeExceeded)
			return nil, ErrInvalidParams(fmt.Sprintf("%s (max block range %d, got %d)",
				lim.errorMessage, lim.maxBlockRange, span))
		}
	}

	return nil, nil
}

// headsForGroup returns the latest/safe/finalized agreed block numbers for the
// backend group routing this method. The result has known=false when the group
// isn't consensus-aware or hasn't agreed on a head yet, so block tags are left
// unresolved (and the range simply not enforced) rather than guessed.
func (s *Server) headsForGroup(group string) consensusHeads {
	bg, ok := s.BackendGroups[group]
	if !ok || bg == nil || bg.Consensus == nil {
		return consensusHeads{}
	}
	latest := uint64(bg.Consensus.GetLatestBlockNumber())
	if latest == 0 {
		return consensusHeads{}
	}
	return consensusHeads{
		latest:    latest,
		safe:      uint64(bg.Consensus.GetSafeBlockNumber()),
		finalized: uint64(bg.Consensus.GetFinalizedBlockNumber()),
		known:     true,
	}
}
