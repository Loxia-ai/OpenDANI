// Command dani-econsim estimates the EMERGENT behavior of Open-DANI's contribution economy
// (internal/ledger + the utilization admission gate) — without a live fleet. It answers the two
// questions that decide whether the design is sound:
//
//  1. Do CLIENTS stay happy?  (what fraction of best-effort/tourist requests get served)
//  2. Do CONTRIBUTORS get the full power?  (do priority requests essentially always get served)
//  3. The growth loop: as more users contribute (bring a worker), does TOTAL served work rise for
//     EVERYONE — including tourists — because the contributors added the very capacity they use?
//
// Model (deliberately simple, matches the real rule in ledger_gate.go):
//   - N users. A fraction `contribFrac` run a worker (add capacity AND earn priority); the rest are
//     tourists (consume only, best-effort).
//   - Each tick, every user submits a request with probability `demand`. Each contributor's worker
//     provides `slotsPerWorker` serving slots; total capacity = contributors * slotsPerWorker
//     (+ a fixed operator seed capacity).
//   - Admission = the real rule: priority requests fill up to full capacity; best-effort requests are
//     admitted only while utilization < (1 - reserveFrac).
//   - We report steady-state service rates. This is a mean-field estimate, not the wire path — the
//     wire path is covered by the unit/integration tests; this estimates behavior AT SCALE.
package main

import (
	"flag"
	"fmt"
	"math"
)

type params struct {
	users          int
	contribFrac    float64
	demand         float64 // P(a user submits a request this tick)
	slotsPerWorker int
	seedSlots      int // operator-run baseline capacity
	reserveFrac    float64
	ticks          int
}

type result struct {
	capacity                   int
	touristReqs, touristServed int
	contribReqs, contribServed int
	totalServed                int
}

// simulate runs a simple deterministic mean-field model (no RNG — reproducible; "randomness" is
// folded into expected counts) and returns the steady-state served/offered tallies.
func simulate(p params) result {
	contributors := int(math.Round(float64(p.users) * p.contribFrac))
	tourists := p.users - contributors
	capacity := contributors*p.slotsPerWorker + p.seedSlots

	var r result
	r.capacity = capacity
	for t := 0; t < p.ticks; t++ {
		// expected offered load this tick (fractional -> we tally expectations * ticks at the end by
		// working in per-tick expected counts as floats, then round into the result).
		contribOffered := float64(contributors) * p.demand
		touristOffered := float64(tourists) * p.demand

		// priority fills first, up to full capacity.
		contribServed := math.Min(contribOffered, float64(capacity))
		remaining := float64(capacity) - contribServed
		// best-effort may use capacity only up to the (1-reserve) line, and only what priority left.
		bestEffortCeiling := float64(capacity)*(1-p.reserveFrac) - contribServed
		if bestEffortCeiling < 0 {
			bestEffortCeiling = 0
		}
		touristServed := math.Min(touristOffered, math.Min(remaining, bestEffortCeiling))

		r.contribReqs += int(math.Round(contribOffered))
		r.touristReqs += int(math.Round(touristOffered))
		r.contribServed += int(math.Round(contribServed))
		r.touristServed += int(math.Round(touristServed))
	}
	r.totalServed = r.contribServed + r.touristServed
	return r
}

func pctStr(a, b int) string {
	if b == 0 {
		return "  n/a" // no requests of this kind in this scenario
	}
	return fmt.Sprintf("%.1f", 100*float64(a)/float64(b))
}

func main() {
	users := flag.Int("users", 1000, "population size")
	demand := flag.Float64("demand", 0.6, "P(a user requests each tick) — 0.6 = heavy load")
	slots := flag.Int("slots-per-worker", 2, "serving slots each contributor's worker adds")
	seed := flag.Int("seed-slots", 20, "operator-run baseline capacity")
	reserve := flag.Float64("reserve", 0.25, "capacity fraction held for contributors")
	ticks := flag.Int("ticks", 500, "simulation ticks")
	flag.Parse()

	fmt.Printf("Open-DANI contribution economy — emergent behavior\n")
	fmt.Printf("users=%d demand=%.2f slots/worker=%d seed=%d reserve=%.2f\n\n", *users, *demand, *slots, *seed, *reserve)
	fmt.Printf("%-8s %-9s %-13s %-13s %-12s\n", "contrib%", "capacity", "contrib srv%", "tourist srv%", "total served")
	fmt.Printf("%s\n", "-------- --------- ------------- ------------- ------------")
	for _, cf := range []float64{0.0, 0.05, 0.10, 0.25, 0.50, 0.75, 1.0} {
		r := simulate(params{users: *users, contribFrac: cf, demand: *demand,
			slotsPerWorker: *slots, seedSlots: *seed, reserveFrac: *reserve, ticks: *ticks})
		fmt.Printf("%-8.0f %-9d %-13s %-13s %-12d\n",
			cf*100, r.capacity, pctStr(r.contribServed, r.contribReqs), pctStr(r.touristServed, r.touristReqs), r.totalServed)
	}
	fmt.Printf("\nReads: contributors should sit near 100%% served (full power); tourist%% rising with\n")
	fmt.Printf("contrib%% is the GROWTH LOOP — more contributors add capacity that lifts EVERYONE.\n")
}
