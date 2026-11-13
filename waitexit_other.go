//go:build !windows

package main

func isLaunchedByExplorer() bool {
	return false
}

func waitExitIfExplorer() {}
