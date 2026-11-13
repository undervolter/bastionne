package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"krushitel/core/update"
)

const updateCheckTimeout = 5 * time.Second

func selfUpdateCheck(auto, force bool) (*update.Release, error) {
	update.Sweep()

	ctx, cancel := context.WithTimeout(context.Background(), updateCheckTimeout)
	rel, err := update.Check(ctx)
	cancel()
	if err != nil {
		return nil, err
	}
	if rel == nil {
		return nil, nil
	}
	if !auto {
		return rel, nil
	}

	marker := updateMarker(rel.Version)
	if !force {
		if _, err := os.Stat(marker); err == nil {
			return nil, nil
		}
	}

	fmt.Printf("Installing update v%s...\n", rel.Version)
	instCtx, instCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	update.Install(instCtx, rel)
	instCancel()

	stage, _, _, uerr, _ := update.St.Snap()
	if stage == update.StageErr || uerr != nil {
		if uerr == nil {
			uerr = fmt.Errorf("stage=%s", stage)
		}
		fmt.Fprintf(os.Stderr, "[!] update failed: %v\n", uerr)
		return rel, fmt.Errorf("install: %w", uerr)
	}

	if err := os.WriteFile(marker, []byte(rel.Version), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "[!] update marker: %v\n", err)
	}

	_ = os.Setenv("KRUSHITEL_JUST_UPDATED", rel.Version)
	if err := update.Restart(os.Stdout, os.Stderr); err != nil {
		_ = os.Remove(marker)
		_ = os.Unsetenv("KRUSHITEL_JUST_UPDATED")
		fmt.Fprintf(os.Stderr, "[!] restart failed: %v\n", err)
		return rel, fmt.Errorf("restart: %w", err)
	}
	os.Exit(0)
	return nil, nil
}

func runUpdateCommand() int {
	rel, err := selfUpdateCheck(true, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] update: %v\n", err)
		return 1
	}
	if rel == nil {
		fmt.Printf("No updates available (v%s is latest).\n", update.CurrentVersion)
		return 0
	}
	fmt.Fprintf(os.Stderr, "[!] update to v%s failed\n", rel.Version)
	return 1
}

func updateMarker(version string) string {
	safe := strings.NewReplacer("/", "_", `\`, "_", ":", "_").Replace(version)
	return filepath.Join(os.TempDir(), "krushitel-updated-"+safe)
}

func updateLine(rel *update.Release) string {
	return fmt.Sprintf("New update is available! (v%s >> v%s)", update.CurrentVersion, rel.Version)
}
