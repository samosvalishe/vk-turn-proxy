// Package captcha — Solver chain.
//
// Chain декаплит auth-цикл от выбора captcha-стратегии. vkauth.getTokenChain
// получает Solver через Chain.Solver(attempt), вызывает Solve и не знает про
// конкретные реализации (auto/slider/manual).
package captcha

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/cacggghp/vk-turn-proxy/client/internal/appcfg"
	prof "github.com/cacggghp/vk-turn-proxy/client/internal/profile"

	tlsclient "github.com/bogdanfinn/tls-client"
)

// SolveDeps — runtime-зависимости solver'ов. Заполняются caller'ом
// (vkauth) на каждый Solve.
type SolveDeps struct {
	Client   tlsclient.HttpClient
	Profile  prof.Profile
	StreamID int
	Cfg      *appcfg.Config
}

// SolveResult — результат одной попытки. Token/Key взаимоисключающие
// (HTTP-форма captcha_img возвращает Key, остальные — successToken).
type SolveResult struct {
	SuccessToken string
	CaptchaKey   string
}

type Solver interface {
	Mode() SolveMode
	Label() string
	Solve(ctx context.Context, captchaErr *VkCaptchaError, deps SolveDeps) (SolveResult, error)
}

type Chain struct {
	solvers []Solver
}

// BuildChain — порядок попыток.
//
// manualOnly=true       → [manual]
// enableSliderPOC=true  → [auto, slider, manual]
// enableSliderPOC=false → [auto, manual]
func BuildChain(manualOnly, enableSliderPOC bool) *Chain {
	if manualOnly {
		return &Chain{solvers: []Solver{manualSolver{}}}
	}
	solvers := []Solver{autoSolver{useSlider: false}}
	if enableSliderPOC {
		solvers = append(solvers, autoSolver{useSlider: true})
	}
	solvers = append(solvers, manualSolver{})
	return &Chain{solvers: solvers}
}

// Solver возвращает solver для попытки attempt (0-based) либо ok=false если
// цепочка исчерпана.
func (c *Chain) Solver(attempt int) (Solver, bool) {
	if attempt < 0 || attempt >= len(c.solvers) {
		return nil, false
	}
	return c.solvers[attempt], true
}

// Len — длина цепочки.
func (c *Chain) Len() int { return len(c.solvers) }

// --- autoSolver: SolveVkCaptcha (sliderPOC флаг разделяет два варианта) ---

type autoSolver struct {
	useSlider bool
}

func (a autoSolver) Mode() SolveMode {
	if a.useSlider {
		return SolveModeSliderPOC
	}
	return SolveModeAuto
}

func (a autoSolver) Label() string {
	if a.useSlider {
		return "auto captcha slider POC"
	}
	return "auto captcha"
}

func (a autoSolver) Solve(ctx context.Context, captchaErr *VkCaptchaError, deps SolveDeps) (SolveResult, error) {
	if captchaErr.SessionToken == "" || captchaErr.RedirectURI == "" {
		return SolveResult{}, fmt.Errorf("missing fields for %s", a.Label())
	}
	token, err := SolveVkCaptcha(ctx, captchaErr, deps.StreamID, deps.Client, deps.Profile, a.useSlider)
	if err != nil {
		return SolveResult{}, err
	}
	return SolveResult{SuccessToken: token}, nil
}

// --- manualSolver: WebView reverse-proxy либо HTTP-form ---

type manualSolver struct{}

func (manualSolver) Mode() SolveMode { return SolveModeManual }
func (manualSolver) Label() string   { return "manual captcha" }

const manualCaptchaTimeout = 3 * time.Minute

func (manualSolver) Solve(ctx context.Context, captchaErr *VkCaptchaError, deps SolveDeps) (SolveResult, error) {
	log.Printf("[STREAM %d] [Captcha] Triggering manual captcha fallback...", deps.StreamID)

	// context.Background не наследует короткий deadline парента — manual ждёт
	// человека, до 3 минут, независимо от auth-таймаута.
	mctx, cancel := context.WithTimeout(context.Background(), manualCaptchaTimeout)
	defer cancel()

	type mres struct {
		token string
		key   string
		err   error
	}
	resCh := make(chan mres, 1)
	go func() {
		var t, k string
		var e error
		switch {
		case captchaErr.RedirectURI != "":
			t, e = SolveViaProxy(captchaErr.RedirectURI, deps.Cfg)
		case captchaErr.CaptchaImg != "":
			k, e = SolveViaHTTP(captchaErr.CaptchaImg)
		default:
			e = fmt.Errorf("no redirect_uri or captcha_img")
		}
		resCh <- mres{t, k, e}
	}()

	select {
	case r := <-resCh:
		// Token может прийти даже при err != nil (srv.Shutdown timeout на iSH
		// после получения токена). Непустой token/key = успех.
		if r.token != "" || r.key != "" {
			if r.err != nil {
				log.Printf("[STREAM %d] [Captcha] Token received (ignoring cleanup error: %v)", deps.StreamID, r.err)
			}
			log.Printf("[STREAM %d] [Captcha] Successfully got token from browser", deps.StreamID)
			return SolveResult{SuccessToken: r.token, CaptchaKey: r.key}, nil
		}
		if r.err != nil {
			return SolveResult{}, r.err
		}
		return SolveResult{}, fmt.Errorf("manual captcha returned empty result")
	case <-mctx.Done():
		if mctx.Err() == context.DeadlineExceeded {
			return SolveResult{}, fmt.Errorf("manual captcha timed out after %v", manualCaptchaTimeout)
		}
		// Parent ctx нельзя отменить отсюда (mctx — Background), но если caller
		// прокинет cancellation через Solve(ctx,...) — обработать.
		select {
		case <-ctx.Done():
			return SolveResult{}, fmt.Errorf("manual captcha interrupted: %w", ctx.Err())
		default:
			return SolveResult{}, fmt.Errorf("manual captcha interrupted: %w", mctx.Err())
		}
	}
}
