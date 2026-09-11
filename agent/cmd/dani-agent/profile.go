package main

// The PRODUCTION PROFILE is the one-switch guard against shipping a demo-postured deployment.
// Every dangerous convenience DANI offers for demos (code-executing /demo/verify, open CORS,
// auth-off console, auto-admitted enrollment, plaintext public gateway, in-memory audit) is
// individually flag-controlled — which means each one is individually forgettable. `--profile
// production` refuses to start until the posture is right, and reports EVERY violation at once
// (an operator fixes the whole checklist in one pass, not one restart per item).

import (
	"fmt"
	"strings"
)

// prodInputs is the posture snapshot the gate judges (pure data — fully unit-testable).
type prodInputs struct {
	demo          bool   // --demo: fan-out showcase; /demo/verify EXECUTES model output
	gwTLS         bool   // --gateway-tls enabled
	plainGateway  bool   // --plain-gateway-behind-ingress: operator states TLS terminates upstream
	consoleAuth   bool   // --console-auth: operator write actions need bearer tokens
	admit         string // enrollment admission: manual (SO approves) | auto (demo drain policy)
	statePath     string // --state: durable authority (CA survives restart; workers stay valid)
	auditDB       string // --audit-db: durable audit chain ("" = :memory: = lost on restart)
	kmsSpec       string // --kms: "" = software keystore
	backupDir     string // --backup-dir: scheduled snapshots
	replicateFrom string // --replicate-from: cross-site DR pull
}

// productionGate returns an aggregated error listing every HARD violation, plus advisory
// warnings for postures that are legal but worth an operator's eyes.
func productionGate(in prodInputs) (warnings []string, err error) {
	var violations []string
	if in.demo {
		violations = append(violations, "--demo is ON (the /demo/verify endpoint EXECUTES model-generated code and the gateway serves open CORS + extra lanes) — never in production")
	}
	if !in.gwTLS && !in.plainGateway {
		violations = append(violations, "gateway is plaintext — enable --gateway-tls, or pass --plain-gateway-behind-ingress if TLS genuinely terminates at your ingress")
	}
	if !in.consoleAuth {
		violations = append(violations, "console auth is OFF (--console-auth): any browser could drain/revoke nodes and sign models")
	}
	if in.admit != "manual" {
		violations = append(violations, fmt.Sprintf("enrollment admission is %q — production requires --admit manual (an operator approves every join; auto is the DEMO drain policy)", in.admit))
	}
	if in.statePath == "" {
		violations = append(violations, "no --state: a controller restart would mint a NEW CA and orphan every enrolled worker")
	}
	if in.auditDB == "" {
		violations = append(violations, "no --audit-db: the audit chain would live in :memory: and vanish on restart")
	}
	if len(violations) > 0 {
		return nil, fmt.Errorf("PRODUCTION profile refused — fix ALL of:\n  - %s", strings.Join(violations, "\n  - "))
	}
	if in.kmsSpec == "" {
		warnings = append(warnings, "software keystore in use — point --kms at an HSM/cloud-KMS for hardware-rooted signing")
	}
	if in.backupDir == "" {
		warnings = append(warnings, "no --backup-dir — scheduled consistent snapshots are OFF")
	}
	if in.replicateFrom == "" {
		warnings = append(warnings, "no --replicate-from — this site holds no warm copy of a peer site's state")
	}
	if in.plainGateway {
		warnings = append(warnings, "plaintext gateway accepted on your word that TLS terminates upstream — verify the ingress really does")
	}
	return warnings, nil
}
