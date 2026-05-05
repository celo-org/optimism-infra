package integration_tests

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path"
	"testing"

	"github.com/ethereum-optimism/infra/proxyd"
	ms "github.com/ethereum-optimism/infra/proxyd/tools/mockserver/handler"
	"github.com/stretchr/testify/require"
)

func setupEspresso(t *testing.T) (map[string]nodeContext, *proxyd.BackendGroup, *ProxydHTTPClient, func()) {
	node1 := NewMockBackend(nil)
	node2 := NewMockBackend(nil)

	dir, err := os.Getwd()
	require.NoError(t, err)

	responses := path.Join(dir, "testdata/consensus_espresso_responses.yml")

	h1 := ms.MockedHandler{
		Overrides:    []*ms.MethodTemplate{},
		Autoload:     true,
		AutoloadFile: responses,
	}
	h2 := ms.MockedHandler{
		Overrides:    []*ms.MethodTemplate{},
		Autoload:     true,
		AutoloadFile: responses,
	}

	require.NoError(t, os.Setenv("NODE1_URL", node1.URL()))
	require.NoError(t, os.Setenv("NODE2_URL", node2.URL()))

	node1.SetHandler(http.HandlerFunc(h1.Handler))
	node2.SetHandler(http.HandlerFunc(h2.Handler))

	config := ReadConfig("consensus_espresso")
	svr, shutdown, err := proxyd.Start(config)
	require.NoError(t, err)

	client := NewProxydClient("http://127.0.0.1:8545")

	bg := svr.BackendGroups["node"]
	require.NotNil(t, bg)
	require.NotNil(t, bg.Consensus)
	require.Equal(t, 2, len(bg.Backends))

	nodes := map[string]nodeContext{
		"node1": {
			mockBackend: node1,
			backend:     bg.Backends[0],
			handler:     &h1,
		},
		"node2": {
			mockBackend: node2,
			backend:     bg.Backends[1],
			handler:     &h2,
		},
	}

	return nodes, bg, client, shutdown
}

func TestConsensusEspresso(t *testing.T) {
	nodes, bg, client, shutdown := setupEspresso(t)
	defer nodes["node1"].mockBackend.Close()
	defer nodes["node2"].mockBackend.Close()
	defer shutdown()

	ctx := context.Background()

	update := func() {
		for _, be := range bg.Backends {
			bg.Consensus.UpdateBackend(ctx, be)
		}
		bg.Consensus.UpdateBackendGroupConsensus(ctx)
	}

	reset := func() {
		for _, node := range nodes {
			node.handler.ResetOverrides()
			node.mockBackend.Reset()
			node.backend.ClearSlidingWindows()
		}
		bg.Consensus.ClearListeners()
		bg.Consensus.Reset()
	}

	override := func(node string, method string, block string, response string) {
		if _, ok := nodes[node]; !ok {
			t.Fatalf("node %s does not exist in the nodes map", node)
		}
		nodes[node].handler.AddOverride(&ms.MethodTemplate{
			Method:   method,
			Block:    block,
			Response: response,
		})
	}

	overrideBlock := func(node string, blockRequest string, blockResponse string) {
		override(node,
			"eth_getBlockByNumber",
			blockRequest,
			buildResponse(map[string]string{
				"number": blockResponse,
				"hash":   "hash_" + blockResponse,
			}))
	}

	t.Run("initial espresso consensus", func(t *testing.T) {
		reset()

		require.Equal(t, "0x0", bg.Consensus.GetEspressoBlockNumber().String())

		update()

		// both nodes default to espresso block 0xa0; standard blocks should also resolve
		require.Equal(t, "0xa0", bg.Consensus.GetEspressoBlockNumber().String())
		require.Equal(t, "0x101", bg.Consensus.GetLatestBlockNumber().String())
	})

	t.Run("use lowest espresso block across backends", func(t *testing.T) {
		reset()

		// node2 reports a higher espresso block than node1's default 0xa0
		overrideBlock("node2", "espresso", "0xb0")
		update()

		// consensus picks the minimum across healthy backends
		require.Equal(t, "0xa0", bg.Consensus.GetEspressoBlockNumber().String())
	})

	t.Run("espresso block advances when all nodes advance", func(t *testing.T) {
		reset()
		update()
		require.Equal(t, "0xa0", bg.Consensus.GetEspressoBlockNumber().String())

		overrideBlock("node1", "espresso", "0xb0")
		overrideBlock("node2", "espresso", "0xb0")
		update()

		require.Equal(t, "0xb0", bg.Consensus.GetEspressoBlockNumber().String())
	})

	t.Run("espresso block does not go backward", func(t *testing.T) {
		reset()

		overrideBlock("node1", "espresso", "0xd0")
		overrideBlock("node2", "espresso", "0xd0")
		update()
		require.Equal(t, "0xd0", bg.Consensus.GetEspressoBlockNumber().String())

		// both nodes report a lower espresso block (e.g. after a proxy restart)
		// 0x90 = 144, 0xd0 = 208
		overrideBlock("node1", "espresso", "0x90")
		overrideBlock("node2", "espresso", "0x90")
		update()

		// monotonicity guarantee: espresso block must not regress
		require.Equal(t, "0xd0", bg.Consensus.GetEspressoBlockNumber().String())
	})

	t.Run("rewrite eth_getBlockByNumber with espresso tag", func(t *testing.T) {
		reset()

		overrideBlock("node1", "espresso", "0xe0")
		override("node2", "net_peerCount", "", buildResponse("0x0"))
		update()

		require.Equal(t, "0xe0", bg.Consensus.GetEspressoBlockNumber().String())
		require.Equal(t, 1, len(bg.Consensus.GetConsensusGroup()))

		// clear request log so we can inspect only the client's request
		nodes["node1"].mockBackend.Reset()

		_, statusCode, err := client.SendRPC("eth_getBlockByNumber", []interface{}{"espresso", false})
		require.NoError(t, err)
		require.Equal(t, 200, statusCode)

		// make sure the response from proxyd has correct state
		var reqBody map[string]interface{}
		err = json.Unmarshal(nodes["node1"].mockBackend.Requests()[0].Body, &reqBody)
		require.NoError(t, err)
		require.Equal(t, "0xe0", reqBody["params"].([]interface{})[0])
	})

	t.Run("batch rewrite with espresso tag", func(t *testing.T) {
		reset()

		overrideBlock("node1", "espresso", "0xe0")
		override("node2", "net_peerCount", "", buildResponse("0x0"))
		update()
		require.Equal(t, "0xe0", bg.Consensus.GetEspressoBlockNumber().String())
		nodes["node1"].mockBackend.Reset()

		resRaw, statusCode, err := client.SendBatchRPC(
			NewRPCReq("1", "eth_getBlockByNumber", []interface{}{"espresso", false}),
			NewRPCReq("2", "eth_getBlockByNumber", []interface{}{"latest", false}),
		)
		require.NoError(t, err)
		require.Equal(t, 200, statusCode)

		var jsonMap []map[string]interface{}
		err = json.Unmarshal(resRaw, &jsonMap)
		require.NoError(t, err)
		require.Equal(t, 2, len(jsonMap))

		require.Equal(t, "0xe0", jsonMap[0]["result"].(map[string]interface{})["number"])
		require.Equal(t, "0x101", jsonMap[1]["result"].(map[string]interface{})["number"])
	})

	t.Run("eth_call with espresso block param", func(t *testing.T) {
		reset()

		overrideBlock("node1", "espresso", "0xe0")
		override("node2", "net_peerCount", "", buildResponse("0x0"))
		update()
		require.Equal(t, "0xe0", bg.Consensus.GetEspressoBlockNumber().String())
		nodes["node1"].mockBackend.Reset()

		_, statusCode, err := client.SendRPC("eth_call", []interface{}{map[string]string{}, "espresso"})
		require.NoError(t, err)
		require.Equal(t, 200, statusCode)

		var reqBody map[string]interface{}
		err = json.Unmarshal(nodes["node1"].mockBackend.Requests()[0].Body, &reqBody)
		require.NoError(t, err)
		require.Equal(t, "0xe0", reqBody["params"].([]interface{})[1])
	})

	t.Run("non-espresso tag is unaffected by espresso config", func(t *testing.T) {
		reset()

		override("node2", "net_peerCount", "", buildResponse("0x0"))
		update()
		nodes["node1"].mockBackend.Reset()

		_, statusCode, err := client.SendRPC("eth_getBlockByNumber", []interface{}{"latest", false})
		require.NoError(t, err)
		require.Equal(t, 200, statusCode)

		var reqBody map[string]interface{}
		err = json.Unmarshal(nodes["node1"].mockBackend.Requests()[0].Body, &reqBody)
		require.NoError(t, err)
		// "latest" rewrites to the consensus latest block, not the espresso block
		require.Equal(t, "0x101", reqBody["params"].([]interface{})[0])
	})
}
