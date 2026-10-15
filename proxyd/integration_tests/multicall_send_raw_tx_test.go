package integration_tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ethereum-optimism/infra/proxyd"
	"github.com/stretchr/testify/require"
)

// TestMulticallSendRawTransaction verifies the multicall_send_raw_transaction flag:
// eth_sendRawTransaction is broadcast to every backend in the group, while all other
// methods keep following the group's routing strategy (here, "fallback", which serves a
// read from a single backend). This lets an HA sequencer group route reads normally while
// guaranteeing every candidate block builder receives submitted transactions directly,
// instead of relying on p2p gossip.
func TestMulticallSendRawTransaction(t *testing.T) {
	node1 := NewMockBackend(SingleResponseHandler(200, txAccepted))
	node2 := NewMockBackend(SingleResponseHandler(200, txAccepted))
	node3 := NewMockBackend(SingleResponseHandler(200, txAccepted))
	defer node1.Close()
	defer node2.Close()
	defer node3.Close()

	require.NoError(t, os.Setenv("NODE1_URL", node1.URL()))
	require.NoError(t, os.Setenv("NODE2_URL", node2.URL()))
	require.NoError(t, os.Setenv("NODE3_URL", node3.URL()))

	config := ReadConfig("multicall_send_raw_tx")
	svr, shutdown, err := proxyd.Start(config)
	require.NoError(t, err)
	defer shutdown()

	bg := svr.BackendGroups["node"]
	require.NotNil(t, bg)
	require.Nil(t, bg.Consensus, "consensus should not be initialized for a fallback group")
	require.Equal(t, proxyd.FallbackRoutingStrategy, bg.GetRoutingStrategy())
	require.True(t, bg.MulticallSendRawTransaction(), "multicall_send_raw_transaction should be enabled")
	require.Equal(t, 3, len(bg.Backends))

	sendRPC := func(body []byte) *http.Response {
		req, _ := http.NewRequest("POST", "https://1.1.1.1:8080", bytes.NewReader(body))
		req.Header.Set("X-Forwarded-For", "203.0.113.1")
		rr := httptest.NewRecorder()
		svr.HandleRPC(rr, req)
		return rr.Result()
	}
	totalRequests := func() int {
		return len(node1.Requests()) + len(node2.Requests()) + len(node3.Requests())
	}

	t.Run("broadcasts eth_sendRawTransaction to all backends", func(t *testing.T) {
		node1.Reset()
		node2.Reset()
		node3.Reset()

		resp := sendRPC(makeSendRawTransaction(txHex1))
		defer resp.Body.Close()
		require.Equal(t, 200, resp.StatusCode)
		rpcRes := &proxyd.RPCRes{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(rpcRes))
		require.False(t, rpcRes.IsError())

		// Multicall dispatches to every backend concurrently and returns as soon as one
		// succeeds, so the others may still be in flight when the response is written.
		require.Eventually(t, func() bool {
			return len(node1.Requests()) == 1 &&
				len(node2.Requests()) == 1 &&
				len(node3.Requests()) == 1
		}, 5*time.Second, 10*time.Millisecond,
			"every backend should receive the raw transaction exactly once")
	})

	t.Run("does not broadcast reads", func(t *testing.T) {
		node1.Reset()
		node2.Reset()
		node3.Reset()

		body := []byte(`{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0x0000000000000000000000000000000000000000","data":"0x"},"latest"],"id":1}`)
		resp := sendRPC(body)
		defer resp.Body.Close()
		require.Equal(t, 200, resp.StatusCode)

		// A read must follow the fallback routing strategy: exactly one backend, never a
		// broadcast to all three.
		require.Eventually(t, func() bool { return totalRequests() == 1 },
			2*time.Second, 10*time.Millisecond, "a read should hit exactly one backend")
		require.Never(t, func() bool { return totalRequests() > 1 },
			500*time.Millisecond, 50*time.Millisecond, "a read must not be broadcast")
	})
}

// TestMulticallSendRawTransactionHonorsDeadline verifies that when the broadcast backends
// all stall past the server deadline, the client's wait is bounded by server.timeout_seconds
// (returning a gateway timeout) instead of blocking for the full backend response timeout.
// The fan-out delivery itself runs on a detached context and continues after this returns;
// only the wait for a response observes the deadline. Without that, this request would
// instead return a success once the backends wake after their stall.
func TestMulticallSendRawTransactionHonorsDeadline(t *testing.T) {
	hang := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Stall well past the 1s server deadline so the wait, not the backend, decides timing.
		time.Sleep(3 * time.Second)
		SingleResponseHandler(200, txAccepted)(w, r)
	})
	node1 := NewMockBackend(hang)
	node2 := NewMockBackend(hang)
	node3 := NewMockBackend(hang)
	defer node1.Close()
	defer node2.Close()
	defer node3.Close()

	require.NoError(t, os.Setenv("NODE1_URL", node1.URL()))
	require.NoError(t, os.Setenv("NODE2_URL", node2.URL()))
	require.NoError(t, os.Setenv("NODE3_URL", node3.URL()))

	config := ReadConfig("multicall_send_raw_tx_timeout")
	svr, shutdown, err := proxyd.Start(config)
	require.NoError(t, err)
	defer shutdown()

	require.True(t, svr.BackendGroups["node"].MulticallSendRawTransaction())

	req, _ := http.NewRequest("POST", "https://1.1.1.1:8080", bytes.NewReader(makeSendRawTransaction(txHex1)))
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	rr := httptest.NewRecorder()

	start := time.Now()
	svr.HandleRPC(rr, req)
	elapsed := time.Since(start)

	resp := rr.Result()
	defer resp.Body.Close()
	rpcRes := &proxyd.RPCRes{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(rpcRes))

	require.True(t, rpcRes.IsError(), "a stalled broadcast must return an error, not hang")
	require.Equal(t, proxyd.ErrGatewayTimeout.Code, rpcRes.Error.Code, "should be a gateway timeout")
	require.Less(t, elapsed, 2500*time.Millisecond,
		"wait must be bounded by server.timeout_seconds (1s), not the 3s backend stall")
}

// TestMulticallSendRawTransactionReturnsTimeoutAfterPartialFailure verifies that an
// early backend failure does not hide the deadline that ultimately ends the request.
func TestMulticallSendRawTransactionReturnsTimeoutAfterPartialFailure(t *testing.T) {
	hang := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
		SingleResponseHandler(200, txAccepted)(w, r)
	})
	node1 := NewMockBackend(SingleResponseHandler(http.StatusTooManyRequests, dummyRes))
	node2 := NewMockBackend(hang)
	node3 := NewMockBackend(hang)
	defer node1.Close()
	defer node2.Close()
	defer node3.Close()

	require.NoError(t, os.Setenv("NODE1_URL", node1.URL()))
	require.NoError(t, os.Setenv("NODE2_URL", node2.URL()))
	require.NoError(t, os.Setenv("NODE3_URL", node3.URL()))

	config := ReadConfig("multicall_send_raw_tx_timeout")
	svr, shutdown, err := proxyd.Start(config)
	require.NoError(t, err)
	defer shutdown()

	req, _ := http.NewRequest("POST", "https://1.1.1.1:8080", bytes.NewReader(makeSendRawTransaction(txHex1)))
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	rr := httptest.NewRecorder()

	start := time.Now()
	svr.HandleRPC(rr, req)
	elapsed := time.Since(start)

	resp := rr.Result()
	defer resp.Body.Close()
	rpcRes := &proxyd.RPCRes{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(rpcRes))

	require.Equal(t, http.StatusGatewayTimeout, resp.StatusCode)
	require.True(t, rpcRes.IsError())
	require.Equal(t, proxyd.ErrGatewayTimeout.Code, rpcRes.Error.Code)
	require.Less(t, elapsed, 2500*time.Millisecond,
		"an earlier backend failure must not mask the server deadline")
}

// TestMulticallSendRawTransactionRPCErrorCheck verifies multicall_rpc_error_check: a fast
// JSON-RPC error (e.g. "nonce too low") from one backend must not win over a slower
// backend that accepted the transaction. Without the flag the first answer wins.
func TestMulticallSendRawTransactionRPCErrorCheck(t *testing.T) {
	for _, tc := range []struct {
		config      string
		wantSuccess bool
	}{
		{"multicall_send_raw_tx", false},
		{"multicall_send_raw_tx_rpc_error_check", true},
	} {
		t.Run(tc.config, func(t *testing.T) {
			slowAccept := func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(300 * time.Millisecond)
				SingleResponseHandler(200, txAccepted)(w, r)
			}
			node1 := NewMockBackend(SingleResponseHandler(200, nonceErrorResponse))
			node2 := NewMockBackend(SingleResponseHandler(200, nonceErrorResponse))
			node3 := NewMockBackend(http.HandlerFunc(slowAccept))
			defer node1.Close()
			defer node2.Close()
			defer node3.Close()

			require.NoError(t, os.Setenv("NODE1_URL", node1.URL()))
			require.NoError(t, os.Setenv("NODE2_URL", node2.URL()))
			require.NoError(t, os.Setenv("NODE3_URL", node3.URL()))

			svr, shutdown, err := proxyd.Start(ReadConfig(tc.config))
			require.NoError(t, err)
			defer shutdown()

			req, _ := http.NewRequest("POST", "https://1.1.1.1:8080", bytes.NewReader(makeSendRawTransaction(txHex1)))
			req.Header.Set("X-Forwarded-For", "203.0.113.1")
			rr := httptest.NewRecorder()
			svr.HandleRPC(rr, req)

			rpcRes := &proxyd.RPCRes{}
			require.NoError(t, json.NewDecoder(rr.Result().Body).Decode(rpcRes))
			require.Equal(t, !tc.wantSuccess, rpcRes.IsError())
			if tc.wantSuccess {
				require.Equal(t, []string{"node/node3"}, rr.Result().Header["X-Served-By"])
			}
		})
	}
}
