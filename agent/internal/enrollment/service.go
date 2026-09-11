package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"dani.local/agent/internal/ca"
	pb "dani.local/agent/internal/gen/enrollmentv1"
	"dani.local/agent/internal/openid"
	"dani.local/agent/pkg/dani"
)

// Service implements the gRPC EnrollmentService (enrollment.proto) — the six-step handshake
// (DF-R11.2-01) over the pending-join queue. DEMO scope: Tier 0 attestation only (M5), manual
// batch-confirm approval (no auto-approval, Matrix #10).
type Service struct {
	pb.UnimplementedEnrollmentServiceServer
	mu            sync.Mutex
	ks            dani.KeyStore
	ca            *ca.CA
	deploymentID  string
	configVersion string

	handshakes map[string]*handshake    // request_id -> in-flight EnrollBegin context
	pending    map[string]*pendingEntry // request_id -> queued node
	consumed   map[string]bool          // token_id -> burned (single-use, DL-R11.2-04)
	enrolled   map[string]*enrolledNode // node_uuid -> admitted node (for renewal lookup)

	// Open-DANI permissionless join (nil in enterprise). When set, EnrollBegin verifies a
	// proof-of-work instead of a signed token and joins are auto-approved as open workers.
	openEnroll *openEnroll

	// OnApprove is called when a node is admitted (registry insert hook). Optional.
	OnApprove func(nodeUUID string, cert *x509.Certificate, roles []string, class, site string, caps []byte)
	// OnRenew is called after a successful renewal (registry update hook). Optional.
	OnRenew func(nodeUUID string, cert *x509.Certificate, generation int)
}

type handshake struct {
	nodeUUID      string
	declaredRoles []string
	declaredClass string
	tokenID       string
}

type pendingEntry struct {
	reqID         string
	nodeUUID      string
	tokenID       string
	achievedTier  dani.AttestationTier
	declaredRoles []string
	declaredClass string
	hwFprint      []byte
	pubDER        []byte
	caps          []byte
	state         string // waiting | approved | rejected | expired
	complete      *pb.EnrollComplete
	reject        string
	expiresAt     time.Time
}

// enrolledNode is an admitted node's authoritative attributes (basis for renewal, DL-R11.2-05).
type enrolledNode struct {
	roles      []string
	class      string
	site       string
	hwFprint   []byte
	serial     string
	generation int
	revoked    bool
}

// nowFn is the clock; a package var so tests can exercise the expiry branch.
var nowFn = time.Now

func New(ks dani.KeyStore, authority *ca.CA, deploymentID string) *Service {
	return &Service{
		ks: ks, ca: authority, deploymentID: deploymentID, configVersion: "1",
		handshakes: map[string]*handshake{}, pending: map[string]*pendingEntry{},
		consumed: map[string]bool{}, enrolled: map[string]*enrolledNode{},
	}
}

// Revoke marks an enrolled node as revoked (gossip marker would propagate this; DL-R11-07).
func (s *Service) Revoke(nodeUUID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if en := s.enrolled[nodeUUID]; en != nil {
		en.revoked = true
	}
}

// openEnroll holds the Open-DANI permissionless-join settings.
type openEnroll struct {
	powBits int
}

// EnableOpenEnroll switches this controller to Open-DANI permissionless join: no operator, no signed
// token — a self-minted node proves work (powBits difficulty) and is auto-approved as an open worker.
// Enterprise controllers never call this.
func (s *Service) EnableOpenEnroll(powBits int) {
	s.mu.Lock()
	s.openEnroll = &openEnroll{powBits: powBits}
	s.mu.Unlock()
}

// EnrollBegin — step 1->2. Enterprise: validate the bootstrap token. Open: verify the proof-of-work
// (carried in the token field) bound to the self-minted uuid. Then clock-sync (DL-R11.2-04).
func (s *Service) EnrollBegin(ctx context.Context, req *pb.EnrollBeginRequest) (*pb.EnrollChallenge, error) {
	tokenID := ""
	if s.openEnroll != nil {
		if !openid.IsOpenUUID(req.NodeUuid) {
			return nil, status.Error(codes.PermissionDenied, "open enrollment: node id must be self-minted (open-...)")
		}
		nonce, derr := openid.DecodeNonce(req.Token)
		if derr != nil {
			return nil, status.Errorf(codes.InvalidArgument, "open enrollment: %v", derr)
		}
		if !openid.Verify(s.deploymentID, req.NodeUuid, nonce, s.openEnroll.powBits) {
			return nil, status.Error(codes.PermissionDenied, "open enrollment: proof-of-work invalid or too weak")
		}
		tokenID = "open:" + req.NodeUuid // synthetic; open joins are not single-use tokens
	} else {
		p, err := VerifyToken(ctx, s.ks, s.deploymentID, req.Token)
		if err != nil {
			return nil, status.Errorf(codes.PermissionDenied, "enroll-begin rejected: %v", err)
		}
		tokenID = p.TokenID
	}
	now := time.Now().UTC()
	skew := false
	if t, err := time.Parse(rfc3339, req.NodeTime); err == nil {
		if d := now.Sub(t); d > 5*time.Minute || d < -5*time.Minute {
			skew = true
		}
	}
	reqID := randHex(8)
	s.mu.Lock()
	s.handshakes[reqID] = &handshake{nodeUUID: req.NodeUuid, declaredRoles: req.DeclaredRoles, declaredClass: req.DeclaredClass, tokenID: tokenID}
	s.mu.Unlock()
	return &pb.EnrollChallenge{ServerTime: now.Format(rfc3339), SkewWarning: skew, RequestId: reqID}, nil
}

// EnrollProof — step 3->4. Verify CSR (proves key possession), determine achieved tier, queue.
func (s *Service) EnrollProof(ctx context.Context, req *pb.EnrollProofRequest) (*pb.EnrollPending, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hs := s.handshakes[req.RequestId]
	if hs == nil {
		return nil, status.Error(codes.NotFound, "unknown request_id (restart from EnrollBegin)")
	}
	csr, err := x509.ParseCertificateRequest(req.CsrDer)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "bad CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "CSR possession proof failed: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal pubkey: %v", err)
	}
	// DEMO: Tier 0 (M5). No TPM, so the hardware fingerprint is a software identity hash of the key.
	achieved := dani.TierAdministrative
	hw := sha256.Sum256(pubDER)
	e := &pendingEntry{
		reqID: req.RequestId, nodeUUID: hs.nodeUUID, tokenID: hs.tokenID, achievedTier: achieved,
		declaredRoles: hs.declaredRoles, declaredClass: hs.declaredClass, hwFprint: hw[:], pubDER: pubDER,
		caps: req.CapabilityInventory, state: "waiting", expiresAt: time.Now().Add(24 * time.Hour),
	}
	s.pending[req.RequestId] = e

	// Open-DANI: the self-minted id must BIND to the key that just proved possession (no claiming
	// another node's open id), then the join is AUTO-APPROVED as an open worker — no operator.
	if s.openEnroll != nil {
		edpub, ok := csr.PublicKey.(ed25519.PublicKey)
		if !ok || !openid.BindsKey(hs.nodeUUID, edpub) {
			e.state, e.reject = "rejected", "open id does not bind to the presented key"
			return nil, status.Error(codes.PermissionDenied, "open enrollment: id/key mismatch")
		}
		if _, err := s.issueLocked(ctx, e, []string{"worker"}, openClass, openSite); err != nil {
			return nil, status.Errorf(codes.Internal, "open auto-approve: %v", err)
		}
		return &pb.EnrollPending{RequestId: req.RequestId, AchievedTier: pb.AttestationTier(achieved),
			Mode: pb.DrainMode_DRAIN_MODE_AUTO_POLICY, QueuePosition: 0}, nil
	}

	return &pb.EnrollPending{
		RequestId:     req.RequestId,
		AchievedTier:  pb.AttestationTier(achieved),
		Mode:          pb.DrainMode_DRAIN_MODE_BATCH_CONFIRM, // DEMO: manual approval (Matrix #10)
		QueuePosition: uint32(s.waitingCountLocked()),
	}, nil
}

// open worker attributes (Open-DANI auto-approval).
const (
	openClass = "unrestricted"
	openSite  = "open"
)

// EnrollPoll — step 5. Patient pollable state (DL-R11.2-04): node may disconnect/reconnect.
func (s *Service) EnrollPoll(ctx context.Context, req *pb.EnrollPollRequest) (*pb.EnrollPollResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.pending[req.RequestId]
	if e == nil {
		return &pb.EnrollPollResponse{Status: pb.EnrollPollResponse_STATUS_EXPIRED}, nil
	}
	switch e.state {
	case "approved":
		return &pb.EnrollPollResponse{Status: pb.EnrollPollResponse_STATUS_APPROVED, Complete: e.complete}, nil
	case "rejected":
		return &pb.EnrollPollResponse{Status: pb.EnrollPollResponse_STATUS_REJECTED, RejectReason: e.reject}, nil
	default:
		if nowFn().After(e.expiresAt) {
			e.state = "expired"
			return &pb.EnrollPollResponse{Status: pb.EnrollPollResponse_STATUS_EXPIRED}, nil
		}
		return &pb.EnrollPollResponse{Status: pb.EnrollPollResponse_STATUS_WAITING}, nil
	}
}

// Approve admits a queued node (the SO/console action — Mode 2 batch-confirm). It re-validates the
// token (DL-R11.2-04), issues the identity cert via the intermediate with the ASSIGNED attributes,
// burns the token on success, and builds EnrollComplete. Returns the completion.
func (s *Service) Approve(ctx context.Context, reqID string, assignedRoles []string, assignedClass, site string) (*pb.EnrollComplete, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.pending[reqID]
	if e == nil || e.state != "waiting" {
		return nil, errors.New("request not in waiting state")
	}
	if s.consumed[e.tokenID] { // re-validate at admission (DL-R11.2-04)
		e.state, e.reject = "rejected", "token already consumed"
		return nil, errors.New("token already consumed")
	}
	roles := assignedRoles
	if roles == nil {
		roles = e.declaredRoles
	}
	class := assignedClass
	if class == "" {
		class = e.declaredClass
	}
	return s.issueLocked(ctx, e, roles, class, site)
}

// issueLocked issues the identity cert, burns the token, records the enrolled node, and marks the
// entry approved. Caller holds s.mu. Shared by operator Approve and Open-DANI auto-approval.
func (s *Service) issueLocked(ctx context.Context, e *pendingEntry, roles []string, class, site string) (*pb.EnrollComplete, error) {
	claims := dani.DANIClaims{
		SchemaVersion: 1, Roles: roles, Classification: class, AttestationTier: e.achievedTier,
		HardwareFprint: e.hwFprint, EnrolledAt: time.Now().UTC().Format(rfc3339), SiteTag: site,
	}
	cert, err := s.ca.IssueNodeCert(ctx, ca.NodeCertParams{
		NodeUUID: e.nodeUUID, SiteOU: site, PubDER: e.pubDER, Claims: claims, NotAfter: time.Now().AddDate(0, 0, 90),
	})
	if err != nil {
		return nil, err
	}
	s.consumed[e.tokenID] = true // burn on SUCCESS only (DL-R11.2-04)
	s.enrolled[e.nodeUUID] = &enrolledNode{roles: roles, class: class, site: site, hwFprint: e.hwFprint, serial: cert.SerialNumber.String(), generation: 1}
	complete := s.buildCompleteLocked(cert)
	e.state, e.complete = "approved", complete
	if s.OnApprove != nil {
		s.OnApprove(e.nodeUUID, cert, roles, class, site, e.caps)
	}
	return complete, nil
}

// RenewCert — lightweight routine renewal over MUTUAL mTLS (DL-R11.2-05): no token, no human. The
// node proves possession via its existing client cert (peer cert CN must match node_uuid); the
// controller confirms good standing and reissues the same identity + attributes with a fresh window.
func (s *Service) RenewCert(ctx context.Context, req *pb.RenewRequest) (*pb.RenewResponse, error) {
	if err := requirePeer(ctx, req.NodeUuid); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	en := s.enrolled[req.NodeUuid]
	if en == nil {
		return nil, status.Error(codes.NotFound, "unknown node — broken trust funnels to full re-enrollment (DL-R11.2-05)")
	}
	if en.revoked {
		return nil, status.Error(codes.PermissionDenied, "node revoked — full re-enrollment required")
	}
	csr, err := x509.ParseCertificateRequest(req.CsrDer)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "bad CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "CSR possession proof failed: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal pubkey: %v", err)
	}
	claims := dani.DANIClaims{
		SchemaVersion: 1, Roles: en.roles, Classification: en.class, AttestationTier: dani.TierAdministrative,
		HardwareFprint: en.hwFprint, EnrolledAt: time.Now().UTC().Format(rfc3339), SiteTag: en.site,
	}
	cert, err := s.ca.IssueNodeCert(ctx, ca.NodeCertParams{
		NodeUUID: req.NodeUuid, SiteOU: en.site, PubDER: pubDER, Claims: claims, NotAfter: time.Now().AddDate(0, 0, 90),
	})
	if err != nil {
		return nil, err
	}
	en.generation++
	en.serial = cert.SerialNumber.String()
	if s.OnRenew != nil {
		s.OnRenew(req.NodeUuid, cert, en.generation)
	}
	return &pb.RenewResponse{NodeCert: cert.Raw, NotAfter: cert.NotAfter.UTC().Format(rfc3339)}, nil
}

// requirePeer enforces mutual mTLS: a verified client cert whose CN matches the node_uuid.
func requirePeer(ctx context.Context, nodeUUID string) error {
	pr, ok := peer.FromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no peer information")
	}
	ti, ok := pr.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.PeerCertificates) == 0 {
		return status.Error(codes.Unauthenticated, "renewal requires mutual mTLS (client certificate)")
	}
	if cn := ti.State.PeerCertificates[0].Subject.CommonName; cn != nodeUUID {
		return status.Errorf(codes.PermissionDenied, "peer cert CN %q does not match node_uuid %q", cn, nodeUUID)
	}
	return nil
}

// Reject denies a queued node.
func (s *Service) Reject(reqID, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.pending[reqID]
	if e == nil || e.state != "waiting" {
		return errors.New("request not in waiting state")
	}
	e.state, e.reject = "rejected", reason
	return nil
}

// Waiting returns the request_ids currently awaiting approval (for the console).
func (s *Service) Waiting() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for id, e := range s.pending {
		if e.state == "waiting" {
			out = append(out, id)
		}
	}
	return out
}

// PendingInfo is one queued join request, with what the node DECLARED (the SO decides what to
// actually assign at Approve — Mode-2 batch-confirm shows this to the operator).
type PendingInfo struct {
	ReqID         string    `json:"reqId"`
	NodeUUID      string    `json:"nodeUuid"`
	DeclaredRoles []string  `json:"declaredRoles"`
	DeclaredClass string    `json:"declaredClass"`
	Tier          int       `json:"tier"`
	ExpiresAt     time.Time `json:"expiresAt"`
}

// PendingList returns the queued join requests with their declared attributes (the console's
// approval screen; Waiting() stays for callers that only need ids).
func (s *Service) PendingList() []PendingInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []PendingInfo
	for id, e := range s.pending {
		if e.state != "waiting" {
			continue
		}
		out = append(out, PendingInfo{
			ReqID: id, NodeUUID: e.nodeUUID, DeclaredRoles: append([]string(nil), e.declaredRoles...),
			DeclaredClass: e.declaredClass, Tier: int(e.achievedTier), ExpiresAt: e.expiresAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeUUID < out[j].NodeUUID })
	return out
}

func (s *Service) waitingCountLocked() int {
	n := 0
	for _, e := range s.pending {
		if e.state == "waiting" {
			n++
		}
	}
	return n
}

func (s *Service) buildCompleteLocked(cert *x509.Certificate) *pb.EnrollComplete {
	var bundle bytes.Buffer
	for _, c := range s.ca.Bundle() { // [intermediate, root]
		_ = pem.Encode(&bundle, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	anchor := sha256.Sum256(s.ca.Root.Raw)
	return &pb.EnrollComplete{
		NodeCert:             cert.Raw,
		CaBundle:             bundle.Bytes(),
		TrustAnchor:          anchor[:],
		InitialConfigVersion: s.configVersion,
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
