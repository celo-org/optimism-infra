package proxyd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/semaphore"
)

// Malformed backend responses must surface as errors, not panic the poller goroutine.
func TestConsensusPollerMalformedResponses(t *testing.T) {
	tests := []struct {
		name   string
		result string
		call   func(*ConsensusPoller, *Backend) error
	}{
		{"block number null", `{"number":null,"hash":"0xabc"}`, fetchBlockErr},
		{"block hash missing", `{"number":"0x1"}`, fetchBlockErr},
		{"block number not hex", `{"number":"0xzz","hash":"0xabc"}`, fetchBlockErr},
		{"peer count not hex", `"0xzz"`, peerCountErr},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":67,"result":` + tt.result + `}`))
			}))
			defer srv.Close()

			be := NewBackend("b", srv.URL, "", semaphore.NewWeighted(1))
			require.NotPanics(t, func() {
				require.Error(t, tt.call(&ConsensusPoller{}, be))
			})
		})
	}
}

func fetchBlockErr(cp *ConsensusPoller, be *Backend) error {
	_, _, err := cp.fetchBlock(context.Background(), be, "latest")
	return err
}

func peerCountErr(cp *ConsensusPoller, be *Backend) error {
	_, err := cp.getPeerCount(context.Background(), be)
	return err
}
