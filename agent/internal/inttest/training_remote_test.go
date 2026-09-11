package inttest

import (
	"context"
	"net"
	"testing"
	"time"

	"dani.local/agent/internal/artifact"
	"dani.local/agent/internal/controller"
	"dani.local/agent/internal/enrollment"
	"dani.local/agent/internal/identity"
	"dani.local/agent/internal/ingest"
	"dani.local/agent/internal/modelreg"
	"dani.local/agent/internal/node"
	"dani.local/agent/internal/serving"
	"dani.local/agent/internal/training"
)

// mustEnrollRole enrolls + approves a node with an explicit role set (trainer nodes need "trainer").
func mustEnrollRole(t *testing.T, ctx context.Context, ctrl *controller.Controller, addr, uuid string, roles []string) *node.Identity {
	t.Helper()
	token, _, err := enrollment.IssueToken(ctx, ctrl.KS, "dep-1", roles, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	type res struct {
		id  *node.Identity
		err error
	}
	done := make(chan res, 1)
	go func() {
		id, err := node.Enroll(ctx, node.EnrollParams{
			Addr: addr, TrustRoot: ctrl.CA.Root, Token: token,
			NodeUUID: uuid, Roles: roles, Class: "restricted", Timeout: 10 * time.Second,
		})
		done <- res{id, err}
	}()
	deadline := time.Now().Add(8 * time.Second)
	for {
		if w := ctrl.Enroll.Waiting(); len(w) > 0 {
			if _, err := ctrl.Enroll.Approve(ctx, w[0], roles, "restricted", "site-hq"); err != nil {
				t.Fatal(err)
			}
		}
		select {
		case r := <-done:
			if r.err != nil {
				t.Fatalf("enroll %s: %v", uuid, r.err)
			}
			return r.id
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("enroll %s timed out", uuid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestRemoteTrainingEndToEnd proves D17 made physical over REAL mTLS: a dedicated trainer node
// (separate identity, own /train endpoint) executes the fine-tune ITSELF — the controller allocates
// it from the live trainer heartbeat joined with the Node Registry role, ships the staged dataset,
// streams checkpoints back, and lands the candidate in the Model Registry as a draft.
func TestRemoteTrainingEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctrl, err := controller.Genesis(ctx, "AcmeBank", "dep-1", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := ctrl.Serve(lis)
	defer srv.Stop()

	plane, err := serving.NewPlane(serving.Identity{
		LeafRaw: ctrl.Cert.Raw, InterRaw: ctrl.CA.Intermediate.Raw, Key: ctrl.Key, Root: ctrl.CA.Root, UUID: ctrl.ID,
	}, "site-hq")
	if err != nil {
		t.Fatal(err)
	}
	linkAddr, err := plane.ServeLink("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	// A dedicated trainer node: enrolled with the trainer role, serving /train over mTLS, and
	// heartbeating (Trainer-marked) to the controller's Link sink.
	trainerID := mustEnrollRole(t, ctx, ctrl, lis.Addr().String(), "trainer-nd", []string{"trainer"})
	ran := make(chan training.Spec, 1)
	nodeTrainer := trainerFunc(func(_ context.Context, spec training.Spec, on func(int, int)) (training.Result, error) {
		ran <- spec
		on(1, 1)
		return training.Result{Bytes: []byte("remote-adapter"), Evals: map[string]float64{"eval_loss": 0.5}}, nil
	})
	tn := serving.NewTrainerNode(serving.TrainerNodeConfig{
		Identity: servingIdentityFromNode(trainerID), Trainer: nodeTrainer,
		Class: "restricted", Site: "site-edge", AdvertiseHost: "127.0.0.1",
		ControllerURLs: []string{"https://" + linkAddr}, HeartbeatEvery: 200 * time.Millisecond,
		WorkDir: t.TempDir(),
	})
	go func() { _ = tn.Serve(ctx, "127.0.0.1:0") }()

	// Wait until the controller sees the live trainer heartbeat.
	deadline := time.Now().Add(8 * time.Second)
	for len(plane.ActiveTrainers()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("trainer heartbeat never arrived")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// The controller-side training subsystem: allocation joins live heartbeats + registry roles;
	// execution dispatches REMOTELY (the local trainer here would fail the test if used).
	store, err := artifact.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	models := modelreg.New(ctrl.KS, store)
	if err := models.InitSigners(ctx); err != nil {
		t.Fatal(err)
	}
	ident := identity.New("entra-id")
	ing := ingest.New()
	if _, err := ing.Ingest("legal"); err != nil {
		t.Fatal(err)
	}
	failLocal := trainerFunc(func(context.Context, training.Spec, func(int, int)) (training.Result, error) {
		t.Error("job must execute on the trainer node, not locally")
		return training.Result{}, nil
	})
	sub := training.New(training.Deps{
		Identity: serving.IdentAdapter{B: ident},
		Data:     serving.IngestAdapter{S: ing},
		Fleet:    serving.PlaneRegistryFleet{Plane: plane, Reg: ctrl.Registry},
		Registry: models,
		Store:    store,
		Trainer:  training.DispatchTrainer{Local: failLocal, Remote: training.RemoteTrainer{Client: plane.Dialer()}},
	})

	job, err := sub.Submit(ctx, training.Request{
		BaseModelID: "qwen2.5-0.5b", Collection: "legal", Method: "qlora", Engineer: "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	if job.State != "completed" {
		t.Fatalf("job %s: state=%s err=%s", job.ID, job.State, job.Err)
	}
	if job.TrainerUUID != "trainer-nd" {
		t.Fatalf("allocated %q, want trainer-nd", job.TrainerUUID)
	}
	// The node itself ran it, on the shipped dataset.
	select {
	case spec := <-ran:
		if spec.DatasetID != job.DatasetID || spec.DatasetFile == "" {
			t.Fatalf("node ran wrong spec: %+v", spec)
		}
	default:
		t.Fatal("trainer node never executed the job")
	}
	// Candidate landed with the remotely-produced bytes, and promotes to routable.
	cand := models.Get(job.Candidate)
	if cand == nil || cand.State != "draft" || cand.Evals["eval_loss"] != 0.5 {
		t.Fatalf("candidate wrong: %+v", cand)
	}
	got, err := store.Get(cand.Artifact.Hash)
	if err != nil || string(got) != "remote-adapter" {
		t.Fatalf("artifact should be the node's adapter bytes: %q %v", got, err)
	}
	for _, role := range []modelreg.Role{modelreg.RoleSecurity, modelreg.RoleGovernance, modelreg.RoleAdmin} {
		if _, err := models.Sign(ctx, job.Candidate, role); err != nil {
			t.Fatal(err)
		}
	}
	if models.Resolve(job.Candidate) == nil {
		t.Fatal("promoted remotely-trained model must route")
	}
}

// trainerFunc adapts a func to training.Trainer.
type trainerFunc func(context.Context, training.Spec, func(int, int)) (training.Result, error)

func (f trainerFunc) Run(ctx context.Context, s training.Spec, on func(int, int)) (training.Result, error) {
	return f(ctx, s, on)
}
