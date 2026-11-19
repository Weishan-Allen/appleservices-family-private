package dashboard

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Laky-64/appleservices/internal/control"
)

// The bridge is disabled unless explicitly configured. Keep it on the
// dashboard's loopback listener; a private tunnel may carry server requests.
type fiRequest struct {
	Account string `json:"account"`
	Target  string `json:"target"`
	Action  string `json:"action"`
}

type fiResponse struct {
	OK      bool                `json:"ok"`
	Message string              `json:"message"`
	Family  *control.FamilyInfo `json:"family,omitempty"`
}

func (s *Server) fiAccount(appleID string) (*Account, error) {
	if strings.TrimSpace(appleID) == "" {
		return nil, errors.New("Apple ID is required")
	}
	s.accountsMu.Lock()
	defer s.accountsMu.Unlock()
	var found *Account
	for _, account := range s.accounts {
		if strings.EqualFold(account.AppleID, appleID) {
			if found != nil {
				return nil, errors.New("Apple ID is not unique in the FI account pool")
			}
			found = account
		}
	}
	if found == nil {
		return nil, errors.New("Apple ID is not enrolled in the FI account pool")
	}
	return found, nil
}

func fiArguments(action string, account, target *Account) ([]string, error) {
	args := []string{"-dir", account.Dir, "-safe-json"}
	switch action {
	case "status":
	case "create":
		args = append(args, "-create-family")
	case "share":
		args = append(args, "-share-icloud-storage")
	case "join":
		args = append(args, "-join-shared-storage")
	case "accept":
		args = append(args, "-accept-invite", filepath.Join(account.Dir, "fi-family-invite.json"))
	case "invite", "add", "remove":
		if target == nil || target == account {
			return nil, errors.New("select a different FI account as member")
		}
		switch action {
		case "invite":
			args = append(args, "-invite-account-dir", target.Dir, "-invite-out", filepath.Join(target.Dir, "fi-family-invite.json"))
		case "add":
			// Uses the target's existing PET. No password crosses the bridge.
			args = append(args, "-add-pool-member-dir", target.Dir)
		case "remove":
			args = append(args, "-remove-pool-member-dir", target.Dir)
		}
	default:
		return nil, errors.New("unsupported FI action")
	}
	return args, nil
}

func (s *Server) serveFIAction(w http.ResponseWriter, r *http.Request) {
	secret := os.Getenv("FI_BRIDGE_TOKEN")
	provided := r.Header.Get("X-FI-Token")
	if len(secret) < 32 || len(provided) != len(secret) || subtle.ConstantTimeCompare([]byte(provided), []byte(secret)) != 1 || r.Header.Get("Origin") != "" {
		http.Error(w, `{"message":"FI bridge unavailable"}`, http.StatusForbidden)
		return
	}
	var request fiRequest
	if !readJSON(w, r, &request) {
		return
	}
	s.fiMu.Lock()
	defer s.fiMu.Unlock()
	account, err := s.fiAccount(request.Account)
	if err != nil {
		json.NewEncoder(w).Encode(fiResponse{Message: err.Error()})
		return
	}
	var target *Account
	if request.Target != "" {
		target, err = s.fiAccount(request.Target)
		if err != nil {
			json.NewEncoder(w).Encode(fiResponse{Message: err.Error()})
			return
		}
	}
	args, err := fiArguments(request.Action, account, target)
	if err != nil {
		json.NewEncoder(w).Encode(fiResponse{Message: err.Error()})
		return
	}
	if !acceptedCheckpointReady(account.Dir, account.AppleID) || (target != nil && !acceptedCheckpointReady(target.Dir, target.AppleID)) {
		json.NewEncoder(w).Encode(fiResponse{Message: "FI account has no accepted iCloud session"})
		return
	}
	helper := filepath.Join(filepath.Dir(s.config.Worker), "familyinspect.exe")
	if info, statErr := os.Stat(helper); statErr != nil || !info.Mode().IsRegular() {
		json.NewEncoder(w).Encode(fiResponse{Message: "FI familyinspect executable unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 110*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, helper, args...)
	command.Env = os.Environ()
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		// A transport failure can occur after Apple accepted a mutation. Never
		// expose raw output or invite codes, and never imply retry is safe.
		json.NewEncoder(w).Encode(fiResponse{Message: "FI action not confirmed; refresh both accounts before retrying"})
		return
	}
	family, err := parseFamilyStatus(output.String())
	if err != nil {
		json.NewEncoder(w).Encode(fiResponse{Message: "FI action returned no verified family status; refresh before retrying"})
		return
	}
	if _, err := writeFamilyCache(account, family); err != nil {
		json.NewEncoder(w).Encode(fiResponse{OK: true, Message: "FI action accepted; local status cache was not saved", Family: family})
		return
	}
	json.NewEncoder(w).Encode(fiResponse{OK: true, Message: "FI action accepted; verify the target account after member changes", Family: family})
}
