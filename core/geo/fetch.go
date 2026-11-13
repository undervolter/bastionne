package geo

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const DefaultMirrorURL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"

const maxmindURL = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=%s&suffix=tar.gz"

type FetchOptions struct {
	Path       string
	URL        string
	LicenseKey string
	MaxAge     time.Duration
	Logf       func(string, ...any)
}

func EnsureDB(ctx context.Context, opt FetchOptions) error {
	if strings.TrimSpace(opt.Path) == "" {
		return fmt.Errorf("geo: пустой путь к базе")
	}
	if st, err := os.Stat(opt.Path); err == nil && st.Size() > 0 {
		if opt.MaxAge <= 0 || time.Since(st.ModTime()) < opt.MaxAge {
			return nil
		}
	}

	urlStr := strings.TrimSpace(opt.URL)
	official := false
	if key := strings.TrimSpace(opt.LicenseKey); key != "" {
		urlStr = fmt.Sprintf(maxmindURL, url.QueryEscape(key))
		official = true
	}
	if urlStr == "" {
		urlStr = DefaultMirrorURL
	}

	logf := opt.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	logf("geo: скачиваю базу %s", opt.Path)

	ext := filepath.Ext(opt.Path)
	if ext == "" {
		ext = ".mmdb"
	}
	tmp, err := os.CreateTemp(filepath.Dir(opt.Path), ".geo-*"+ext)
	if err != nil {
		return fmt.Errorf("geo: temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		tmp.Close()
		return fmt.Errorf("geo: запрос: %w", err)
	}
	req.Header.Set("User-Agent", "krushitel-geo/1.0")
	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		tmp.Close()
		return fmt.Errorf("geo: download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		tmp.Close()
		return fmt.Errorf("geo: download: http %d", resp.StatusCode)
	}

	if official || strings.HasSuffix(strings.ToLower(urlStr), ".tar.gz") {
		if err := extractMMDB(resp.Body, tmp); err != nil {
			tmp.Close()
			return err
		}
	} else {
		if _, err := io.Copy(tmp, resp.Body); err != nil {
			tmp.Close()
			return fmt.Errorf("geo: download: %w", err)
		}
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("geo: temp close: %w", err)
	}

	f, err := Open(tmpName, nil, nil, false)
	if err != nil {
		return fmt.Errorf("geo: проверка базы: %w", err)
	}
	ok := f.Enabled()
	_ = f.Close()
	if !ok {
		return fmt.Errorf("geo: скачанный файл не похож на базу")
	}

	_ = os.Chmod(tmpName, 0644)
	_ = os.Remove(opt.Path)
	if err := os.Rename(tmpName, opt.Path); err != nil {
		return fmt.Errorf("geo: замена базы: %w", err)
	}
	logf("geo: база обновлена: %s", opt.Path)
	return nil
}

func extractMMDB(r io.Reader, out io.Writer) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("geo: gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("geo: tar: %w", err)
		}
		if hdr.FileInfo().IsDir() || !strings.HasSuffix(hdr.Name, "GeoLite2-Country.mmdb") {
			continue
		}
		if _, err := io.Copy(out, tr); err != nil {
			return fmt.Errorf("geo: tar copy: %w", err)
		}
		return nil
	}
	return fmt.Errorf("geo: в архиве нет GeoLite2-Country.mmdb")
}
