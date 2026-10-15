package integration_tests

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path"
	"testing"

	"github.com/ethereum-optimism/infra/proxyd"
	ms "github.com/ethereum-optimism/infra/proxyd/tools/mockserver/handler"
	"github.com/stretchr/testify/require"
)

// TestMaxBlocksBack verifies that a backend with max_blocks_back only receives reads
// within that many blocks of the consensus head; older reads go to the other backends.
func TestMaxBlocksBack(t *testing.T) {
	dir, err := os.Getwd()
	require.NoError(t, err)
	balance := &ms.MethodTemplate{Method: "eth_getBalance", Response: `{"jsonrpc":"2.0","id":1,"result":"0x1"}`}
	newNode := func(env string) *MockBackend {
		h := &ms.MockedHandler{
			Overrides:    []*ms.MethodTemplate{balance},
			Autoload:     true,
			AutoloadFile: path.Join(dir, "testdata/consensus_responses.yml"), // head 0x101
		}
		node := NewMockBackend(http.HandlerFunc(h.Handler))
		require.NoError(t, os.Setenv(env, node.URL()))
		return node
	}
	node1, node2 := newNode("NODE1_URL"), newNode("NODE2_URL")
	defer node1.Close()
	defer node2.Close()

	svr, shutdown, err := proxyd.Start(ReadConfig("max_blocks_back"))
	require.NoError(t, err)
	defer shutdown()

	bg := svr.BackendGroups["node"]
	ctx := context.Background()
	for _, be := range bg.Backends {
		bg.Consensus.UpdateBackend(ctx, be)
	}
	bg.Consensus.UpdateBackendGroupConsensus(ctx)
	require.Equal(t, "0x101", bg.Consensus.GetLatestBlockNumber().String())
	require.Len(t, bg.Consensus.GetConsensusGroup(), 2)

	client := NewProxydClient("http://127.0.0.1:8545")
	balanceCalls := func(node *MockBackend) int {
		n := 0
		for _, r := range node.Requests() {
			if bytes.Contains(r.Body, []byte(`"eth_getBalance"`)) {
				n++
			}
		}
		return n
	}
	send := func(block string) {
		_, code, err := client.SendRPC("eth_getBalance", []interface{}{"0x0000000000000000000000000000000000000000", block})
		require.NoError(t, err)
		require.Equal(t, 200, code)
	}

	// 0xf0 is 17 blocks behind 0x101: outside node1's 16-block window.
	for i := 0; i < 20; i++ {
		send("0xf0")
	}
	require.Equal(t, 0, balanceCalls(node1))
	require.Equal(t, 20, balanceCalls(node2))

	// 0xf1 is exactly 16 blocks behind: both nodes are eligible (shuffled).
	for i := 0; i < 20; i++ {
		send("0xf1")
	}
	require.Positive(t, balanceCalls(node1))
}
