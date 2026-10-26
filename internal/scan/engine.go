package scan

import (
	"context"
	"os/exec"
	"sync"
)

type checkFn func(ctx context.Context, s *Scan, e emitter)

type checkDef struct {
	name    string
	stage   int // stage 0 runs first; stage 1 needs the open-port list from stage 0
	enabled func(Options) bool
	run     checkFn
}

func have(bin ...string) bool {
	for _, b := range bin {
		if _, err := exec.LookPath(b); err == nil {
			return true
		}
	}
	return false
}

var checks = []checkDef{
	{"Puertos TCP", 0, nil, checkPorts},
	{"DNS", 0, nil, checkDNS},
	{"Fuentes pasivas", 0, func(o Options) bool { return o.Passive }, checkPassive},
	{"Docker local", 0, func(o Options) bool { return o.Local }, checkLocalDocker},
	{"TLS", 1, nil, checkTLS},
	{"HTTP / cabeceras", 1, nil, checkHTTP},
	{"Rutas sensibles", 1, nil, checkPaths},
	{"Servicios web", 1, nil, checkServices},
	{"SSH", 1, nil, checkSSH},
	{"nmap", 1, func(Options) bool { return have("nmap") }, checkNmap},
	{"nuclei", 1, func(Options) bool { return have("nuclei") }, checkNuclei},
	{"testssl.sh", 1, func(Options) bool { return have("testssl.sh", "testssl") }, checkTestSSL},
}

// Plan lists the checks that will run with the given options, in order.
func Plan(o Options) []string {
	var names []string
	for _, c := range checks {
		if c.enabled == nil || c.enabled(o) {
			names = append(names, c.name)
		}
	}
	return names
}

// Start runs every enabled check and streams events; the channel is closed at the end.
func Start(ctx context.Context, t Target, o Options) <-chan Event {
	ch := make(chan Event, 256)
	go func() {
		defer close(ch)
		s := &Scan{T: t, O: o}
		seen := &sync.Map{}
		for stage := 0; stage <= 1; stage++ {
			var wg sync.WaitGroup
			for _, c := range checks {
				if c.stage != stage || (c.enabled != nil && !c.enabled(o)) {
					continue
				}
				wg.Add(1)
				go func(c checkDef) {
					defer wg.Done()
					e := emitter{ctx: ctx, ch: ch, check: c.name, seen: seen}
					e.status("iniciando…")
					c.run(ctx, s, e)
					e.send(Event{Kind: EvDone})
				}(c)
			}
			wg.Wait()
			if ctx.Err() != nil {
				return
			}
		}
	}()
	return ch
}
