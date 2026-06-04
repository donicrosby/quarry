package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
)

type execRequest struct {
	Cmd string `json:"cmd"`
}

type execResponse struct {
	Output string `json:"output"`
	Error  string `json:"error,omitempty"`
}

// RunCommand executes a host command supplied by the caller and returns the output.
// The input is passed directly to exec.Command without sanitization.
func RunCommand(w http.ResponseWriter, r *http.Request) {
	var req execRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Cmd == "" {
		http.Error(w, "cmd is required", http.StatusBadRequest)
		return
	}

	out, err := exec.Command("sh", "-c", req.Cmd).CombinedOutput()

	resp := execResponse{Output: string(out)}
	if err != nil {
		resp.Error = fmt.Sprintf("%v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
