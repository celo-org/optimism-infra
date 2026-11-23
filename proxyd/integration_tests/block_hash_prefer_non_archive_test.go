package integration_tests

import (
	"net/http"
	"os"
	"testing"

	"github.com/ethereum-optimism/infra/proxyd"
	"github.com/stretchr/testify/require"
)

// TestBlockHashPreferNonArchive verifies that an EIP-1898 {"blockHash": ...} read goes to
// the non-archive backend when block_hash_prefer_non_archive is set, and only to the
// archive backend (the default) when it isn't.
func TestBlockHashPreferNonArchive(t *testing.T) {
	ok := `{"jsonrpc":"2.0","id":1,"result":"0x1"}`
	full := NewMockBackend(SingleResponseHandler(200, ok))
	defer full.Close()
	archive := NewMockBackend(SingleResponseHandler(200, ok))
	defer archive.Close()
	require.NoError(t, os.Setenv("FULL_URL", full.URL()))
	require.NoError(t, os.Setenv("ARCHIVE_URL", archive.URL()))

	_, shutdown, err := proxyd.Start(ReadConfig("block_hash_prefer_non_archive"))
	require.NoError(t, err)
	defer shutdown()

	client := NewProxydClient("http://127.0.0.1:8545")
	pinned := map[string]interface{}{
		"blockHash":        "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
		"requireCanonical": true,
	}
	send := func(method string) {
		_, code, err := client.SendRPC(method, []interface{}{"0x0000000000000000000000000000000000000000", pinned})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
	}

	for i := 0; i < 5; i++ {
		send("eth_getBalance")
	}
	require.Len(t, full.Requests(), 5)
	require.Empty(t, archive.Requests())

	full.Reset()
	for i := 0; i < 5; i++ {
		send("eth_getCode")
	}
	require.Empty(t, full.Requests())
	require.Len(t, archive.Requests(), 5)
}
