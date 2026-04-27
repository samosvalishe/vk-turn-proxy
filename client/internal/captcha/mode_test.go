package captcha

import "testing"

func TestBuildChain(t *testing.T) {
	t.Parallel()

	t.Run("default flow", func(t *testing.T) {
		t.Parallel()
		c := BuildChain(false, true)
		expect := []SolveMode{SolveModeAuto, SolveModeSliderPOC, SolveModeManual}
		if c.Len() != len(expect) {
			t.Fatalf("len=%d want %d", c.Len(), len(expect))
		}
		for i, want := range expect {
			s, ok := c.Solver(i)
			if !ok {
				t.Fatalf("attempt %d: missing solver", i)
			}
			if s.Mode() != want {
				t.Fatalf("attempt %d: mode=%v want %v", i, s.Mode(), want)
			}
		}
		if _, ok := c.Solver(3); ok {
			t.Fatal("expected no fourth attempt")
		}
	})

	t.Run("manual only flow", func(t *testing.T) {
		t.Parallel()
		c := BuildChain(true, true)
		s, ok := c.Solver(0)
		if !ok || s.Mode() != SolveModeManual {
			t.Fatalf("attempt 0: mode=%v ok=%v", s, ok)
		}
		if _, ok := c.Solver(1); ok {
			t.Fatal("expected only one attempt in manual-only flow")
		}
	})

	t.Run("flow without slider poc", func(t *testing.T) {
		t.Parallel()
		c := BuildChain(false, false)
		expect := []SolveMode{SolveModeAuto, SolveModeManual}
		if c.Len() != len(expect) {
			t.Fatalf("len=%d want %d", c.Len(), len(expect))
		}
		for i, want := range expect {
			s, ok := c.Solver(i)
			if !ok || s.Mode() != want {
				t.Fatalf("attempt %d: mode=%v want %v ok=%v", i, s, want, ok)
			}
		}
		if _, ok := c.Solver(2); ok {
			t.Fatal("expected only two attempts when slider POC is disabled")
		}
	})
}
