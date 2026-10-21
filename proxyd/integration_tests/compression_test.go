package integration_tests

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/ethereum-optimism/infra/proxyd"
	"github.com/stretchr/testify/require"
)

// TestResponseCompression checks that with enable_response_compression proxyd gzips
// responses of 1 KiB or more for clients that accept gzip, and leaves the rest alone.
func TestResponseCompression(t *testing.T) {
	bigResult := "0x" + strings.Repeat("00", 2048)
	router := NewBatchRPCResponseRouter()
	router.SetFallbackRoute("eth_getBlockByNumber", bigResult)
	router.SetFallbackRoute("eth_chainId", "0x2a")
	backend := NewMockBackend(router)
	defer backend.Close()
	require.NoError(t, os.Setenv("GOOD_BACKEND_RPC_URL", backend.URL()))

	_, shutdown, err := proxyd.Start(ReadConfig("compression"))
	require.NoError(t, err)
	defer shutdown()

	// DisableCompression stops the client from adding Accept-Encoding and from decoding
	// gzip itself, so the test sees exactly what proxyd sends.
	client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	send := func(body, acceptEncoding string) (http.Header, []byte) {
		req, err := http.NewRequest("POST", "http://127.0.0.1:8545", strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		if acceptEncoding != "" {
			req.Header.Set("Accept-Encoding", acceptEncoding)
		}
		res, err := client.Do(req)
		require.NoError(t, err)
		defer res.Body.Close()
		raw, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		require.Equal(t, 200, res.StatusCode)
		require.Equal(t, strconv.Itoa(len(raw)), res.Header.Get("Content-Length"))
		require.Contains(t, res.Header.Values("Vary"), "Accept-Encoding")
		return res.Header, raw
	}
	gunzip := func(b []byte) []byte {
		zr, err := gzip.NewReader(bytes.NewReader(b))
		require.NoError(t, err)
		out, err := io.ReadAll(zr)
		require.NoError(t, err)
		return out
	}
	big := `{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["latest",false]}`
	small := `{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}`
	bigRes := `{"jsonrpc":"2.0","result":"` + bigResult + `","id":1}`

	t.Run("large response, gzip accepted", func(t *testing.T) {
		hdr, raw := send(big, "br, gzip")
		require.Equal(t, "gzip", hdr.Get("Content-Encoding"))
		require.Less(t, len(raw), len(bigRes)/10)
		RequireEqualJSON(t, []byte(bigRes), gunzip(raw))
	})

	t.Run("large batch, gzip accepted", func(t *testing.T) {
		hdr, raw := send("["+big+"]", "gzip")
		require.Equal(t, "gzip", hdr.Get("Content-Encoding"))
		RequireEqualJSON(t, []byte("["+bigRes+"]"), gunzip(raw))
	})

	t.Run("large response, no Accept-Encoding", func(t *testing.T) {
		hdr, raw := send(big, "")
		require.Empty(t, hdr.Get("Content-Encoding"))
		RequireEqualJSON(t, []byte(bigRes), raw)
	})

	t.Run("large response, gzip refused with q=0", func(t *testing.T) {
		hdr, raw := send(big, "gzip;q=0, br")
		require.Empty(t, hdr.Get("Content-Encoding"))
		RequireEqualJSON(t, []byte(bigRes), raw)
	})

	t.Run("small response stays uncompressed", func(t *testing.T) {
		hdr, raw := send(small, "gzip")
		require.Empty(t, hdr.Get("Content-Encoding"))
		RequireEqualJSON(t, []byte(`{"jsonrpc":"2.0","result":"0x2a","id":1}`), raw)
	})
}
