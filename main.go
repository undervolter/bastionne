package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"

	_ "net/http/pprof"

	"krushitel/core/config"
	"krushitel/core/crash"
	"krushitel/core/scanner"
	"krushitel/core/tui"
	"krushitel/core/update"
)

func usage() {
	fmt.Printf("[%s] bastionne v%s (by undervolter)\n\n", time.Now().Format("15:04"), update.FullVersion())
	fmt.Println("Usage:")
	fmt.Println("  bastionne                     show this help menu")
	fmt.Println("  bastionne [options]           start scanning")
	fmt.Println("  bastionne resume [options]    resume last session")
	fmt.Println("  bastionne update              check and install updates")
	fmt.Println()
	fmt.Println("Options:")
	rows := [][2]string{
		{"  -i, --input FILE/PREFIX", "input: serials/prefixes, or results.csv for titles/clean/guard/masks"},
		{"  -o, --output DIR", "directory to save results"},
		{"  -t, --threads N", "worker threads (default 16)"},
		{"  -m, --mode MODE", "mode: exploit (default) | titles | clean | guard | masks | ironscan | tgbot"},
		{"  -p, --port PORT", "port for ironscan (default 37777)"},
		{"      --interval N", "OSD guard re-apply interval in seconds (default 300)"},
		{"      --osd-guard N", "alias for --interval"},
		{"      --frame", "masks mode: black letterbox bars on every channel"},
		{"      --unmask", "clean/masks mode: drop all covers"},
		{"      --antiwhite", "exploit: restore colors and strip white covers after pwn"},
		{"      --geo ES,PT", "filter cameras by country (ISO-2 comma-separated)"},
		{"      --exclude UA,RU", "exclude countries (ISO-2 comma-separated)"},
		{"      --check-update", "check for updates on startup"},
		{"      --auto-update", "download and install updates automatically"},
		{"  -f, --fresh", "ignore previous session state and start fresh"},
		{"  --headless", "plain console output without interactive TUI"},
		{"  -plain, --no-tui", "alias for --headless"},
		{"  -tg, --tgbot", "run in Telegram bot mode"},
		{"  -h, --help", "show this help and exit"},
	}
	for _, r := range rows {
		fmt.Printf("%-32s %s\n", r[0], r[1])
	}
	fmt.Println("\nresume restores input/output/threads from the last session (config.toml).")
	fmt.Println("TUI controls: Space / P — pause, Ctrl+C — exit")
}

func splitCountries(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t'
	})
}

func flagWasSet(fs *flag.FlagSet, names ...string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		for _, n := range names {
			if f.Name == n {
				set = true
			}
		}
	})
	return set
}

func exitApp(code int) {
	waitExitIfExplorer()
	os.Exit(code)
}

func main() {
	if len(os.Args) == 1 {
		usage()
		exitApp(0)
	}

	if addr := os.Getenv("KRUSH_PPROF"); addr != "" {
		go func() { _ = http.ListenAndServe(addr, nil) }()
	} else if addr := os.Getenv("BASTIONNE_PPROF"); addr != "" {
		go func() { _ = http.ListenAndServe(addr, nil) }()
	}

	lf, lerr := os.OpenFile("crash.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if lerr == nil {
		defer lf.Close()
		redirectToCrashLog(lf)
	}

	scanner.FatalHook = func(reason string, stack []byte) {
		crash.Fatal(reason, stack)
	}
	defer func() {
		if r := recover(); r != nil {
			crash.Fatal(scanner.PanicReason(r), debug.Stack())
		}
	}()

	args := os.Args[1:]
	resumeCmd := false
	if len(args) > 0 && strings.EqualFold(args[0], "resume") {
		resumeCmd = true
		args = args[1:]
	}

	fs := flag.NewFlagSet("bastionne", flag.ContinueOnError)
	fs.Usage = usage

	inFile := fs.String("i", "", "input file, results.csv, or prefix")
	fs.StringVar(inFile, "input", "", "alias for -i")

	outDir := fs.String("o", "", "output directory")
	fs.StringVar(outDir, "output", "", "alias for -o")

	threads := fs.Int("t", 16, "threads")
	fs.IntVar(threads, "threads", 16, "alias for -t")

	mode := fs.String("m", "exploit", "mode: exploit | titles | clean | guard | masks | ironscan | tgbot")
	fs.StringVar(mode, "mode", "exploit", "alias for -m")

	port := fs.Int("p", 37777, "port for ironscan")
	fs.IntVar(port, "port", 37777, "alias for -p")

	interval := fs.Int("interval", 300, "OSD guard interval, seconds")
	fs.IntVar(interval, "osd-guard", 300, "alias for --interval")

	frame := fs.Bool("frame", false, "masks mode: letterbox bars")
	unmask := fs.Bool("unmask", false, "clean/masks mode: drop all covers")
	antiwhite := fs.Bool("antiwhite", false, "exploit: fix colors and white covers after pwn")

	geoAllow := fs.String("geo", "", "only cameras from these countries (ISO-2)")
	exclude := fs.String("exclude", "", "exclude these countries (ISO-2)")

	checkUpdate := fs.Bool("check-update", false, "check for updates at startup")
	autoUpdate := fs.Bool("auto-update", false, "install updates and restart")

	fresh := fs.Bool("f", false, "fresh start without resume")
	fs.BoolVar(fresh, "fresh", false, "alias for -f")

	headless := fs.Bool("headless", false, "headless mode")
	plain := fs.Bool("plain", false, "alias for --headless")
	fs.BoolVar(plain, "no-tui", false, "alias for --headless")

	tgFlag := fs.Bool("tg", false, "telegram bot mode")
	fs.BoolVar(tgFlag, "tgbot", false, "alias for -tg")

	helpFlag := fs.Bool("h", false, "show help")
	fs.BoolVar(helpFlag, "help", false, "alias for -h")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			exitApp(0)
		}
		exitApp(2)
	}

	if *helpFlag {
		usage()
		exitApp(0)
	}

	if len(fs.Args()) > 0 {
		switch strings.ToLower(fs.Args()[0]) {
		case "update":
			if v := os.Getenv("KRUSHITEL_JUST_UPDATED"); v != "" {
				_ = os.Unsetenv("KRUSHITEL_JUST_UPDATED")
				fmt.Printf("Updated to v%s.\n", v)
				exitApp(0)
			}
			exitApp(runUpdateCommand())
		default:
			fmt.Fprintf(os.Stderr, "[!] unknown command: %s\n\n", fs.Args()[0])
			usage()
			exitApp(2)
		}
	}

	if *tgFlag {
		*mode = "tgbot"
	}
	*mode = strings.ToLower(strings.TrimSpace(*mode))
	switch *mode {
	case "exploit", "titles", "clean", "guard", "masks", "ironscan", "tgbot":
	default:
		fmt.Fprintf(os.Stderr, "[!] unknown mode: %s\n\n", *mode)
		usage()
		exitApp(2)
	}
	if *mode == "masks" && !*frame && !*unmask {
		fmt.Fprintln(os.Stderr, "[!] masks mode needs --frame and/or --unmask")
		exitApp(2)
	}
	if *mode == "exploit" && (*frame || *unmask) {
		fmt.Fprintln(os.Stderr, "[!] --frame/--unmask are for -m masks (--unmask is also valid for -m clean)")
		exitApp(2)
	}
	if *interval <= 0 {
		*interval = 300
	}

	cfg := config.Load()

	if flagWasSet(fs, "geo") || flagWasSet(fs, "exclude") {
		allow := cfg.GeoAllow
		deny := cfg.GeoDeny
		if flagWasSet(fs, "geo") {
			allow = splitCountries(*geoAllow)
		}
		if flagWasSet(fs, "exclude") {
			deny = splitCountries(*exclude)
		}

		config.SetGeo("", allow, deny, cfg.GeoDenyUnknown)
	}

	if resumeCmd {
		*mode = "exploit"
		*fresh = false
		lr := config.LoadLastRun()
		if !flagWasSet(fs, "i", "input") {
			*inFile = lr.Input
		}
		if !flagWasSet(fs, "o", "output") {
			*outDir = lr.OutDir
		}
		if !flagWasSet(fs, "t", "threads") && lr.Threads > 0 {
			*threads = lr.Threads
		}

		geoCLI := flagWasSet(fs, "geo", "exclude")
		if !geoCLI && (len(lr.GeoAllow) > 0 || len(lr.GeoDeny) > 0) {
			config.SetGeo("", lr.GeoAllow, lr.GeoDeny, cfg.GeoDenyUnknown)
		}
		if *inFile == "" {
			fmt.Fprintln(os.Stderr, "[!] err: no saved session found to resume")
			fmt.Fprintln(os.Stderr, "Usage: bastionne -i <file/prefix>")
			exitApp(2)
		}
		if *outDir != "" {
			fmt.Printf("[*] resume: %s -> %s\n", *inFile, *outDir)
		} else {
			fmt.Printf("[*] resume: %s\n", *inFile)
		}
	}

	if *inFile == "" && *mode != "tgbot" {
		fmt.Fprintln(os.Stderr, "[!] err: input file or prefix required (-i/--input)")
		fmt.Fprintln(os.Stderr, "Run 'bastionne -h' for help.")
		exitApp(2)
	}

	isHeadless := *headless || *plain || !tui.IsTerminal()

	exitApp(runMain(isHeadless, *inFile, *outDir, *mode, *threads, *port, *fresh,
		*checkUpdate || cfg.CheckUpdate, *autoUpdate || cfg.AutoUpdate,
		*interval, *frame, *unmask, *antiwhite))
}
