package observability

import (
	"encoding/json"
	"net/http"
)

// State is an operator-facing view of the active data plane and controller.
type State struct {
	SnapshotDigest      string           `json:"snapshot_digest"`
	Ready               bool             `json:"ready"`
	DeviceTLSExceptions int              `json:"device_tls_exceptions"`
	Listeners           []ListenerState  `json:"listeners"`
	Controller          *ControllerState `json:"controller,omitempty"`
}

type ListenerState struct {
	Port            uint16 `json:"port"`
	Mode            string `json:"mode"`
	OpenConnections int64  `json:"open_connections"`
}

type ControllerState struct {
	OperatorConfigGeneration string `json:"operator_config_generation"`
	OperatorConfigRejected   bool   `json:"operator_config_rejected"`
	ConfigErrors             uint64 `json:"config_errors"`
	APILastSyncTimestamp     int64  `json:"api_last_sync_timestamp"`
}

func StateHandler(state func() State) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		//nolint:errcheck // A failed response write cannot be recovered.
		_ = json.NewEncoder(w).Encode(state())
	}
}
