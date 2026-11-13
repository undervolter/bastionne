//go:build !windows

package crash

func TermWidth() int {
	return 0
}
