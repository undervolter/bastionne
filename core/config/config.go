package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
	"krushitel/core/dhip"
	"krushitel/core/fwd"
	"krushitel/core/i18n"
	"krushitel/core/scanner"
)

type Settings struct {
	Snaps  bool `json:"snaps" toml:"snaps"`
	XML    bool `json:"xml" toml:"xml"`
	Titles bool `json:"titles" toml:"titles"`

	SkipShitty bool `json:"skip_shitty" toml:"skip_shitty"`
	WipeUsers  bool `json:"wipe_users" toml:"wipe_users"`

	LastInput   string `json:"last_input" toml:"last_input"`
	LastOut     string `json:"last_out" toml:"last_out"`
	LastThreads int    `json:"last_threads" toml:"last_threads"`

	Lang        string `json:"lang" toml:"lang"`
	IsActivated bool   `json:"isActivated" toml:"isActivated"`

	Debug bool `json:"debug" toml:"debug"`

	ChannelText string    `json:"channel_text" toml:"channel_text"`
	CustomTexts [4]string `json:"custom_texts" toml:"custom_texts"`

	OSDColor string `json:"osd_color" toml:"osd_color"`
	Text     string `json:"text,omitempty" toml:"text,omitempty"`

	DummyLogin string `json:"dummy_login" toml:"dummy_login"`
	DummyPass  string `json:"dummy_pass" toml:"dummy_pass"`

	BrutePasswords []string `json:"brute_passwords" toml:"brute_passwords"`

	TgBotToken string   `json:"tg_bot_token" toml:"tg_bot_token"`
	TgChatIDs  []string `json:"tg_chat_ids" toml:"tg_chat_ids"`

	DiscordRPC bool `json:"discord_rpc" toml:"discord_rpc"`

	Governor    bool `json:"governor" toml:"governor"`
	GovernorCap int  `json:"governor_cap" toml:"governor_cap"`

	GeoDB          string   `json:"geo_db" toml:"geo_db"`
	GeoAllow       []string `json:"geo_allow" toml:"geo_allow"`
	GeoDeny        []string `json:"geo_deny" toml:"geo_deny"`
	GeoDenyUnknown bool     `json:"geo_deny_unknown" toml:"geo_deny_unknown"`
	GeoDBURL       string   `json:"geo_db_url" toml:"geo_db_url"`

	CheckUpdate bool `json:"check_update" toml:"check_update"`
	AutoUpdate  bool `json:"auto_update" toml:"auto_update"`
}

const (
	ConfigFile     = "config.toml"
	ConfigFileJSON = "config.json"
	LastRunFile    = "last_run.json"
)

type LastRun struct {
	Input    string   `json:"input"`
	OutDir   string   `json:"out_dir"`
	Threads  int      `json:"threads"`
	GeoAllow []string `json:"geo_allow,omitempty"`
	GeoDeny  []string `json:"geo_deny,omitempty"`
}

const (
	defaultDummyLogin = "krushitel"
	defaultDummyPass  = "TancuiPantera1337"

	channelTextLimit = 32
	customTextLimit  = 22
)

func defaultSettings() Settings {
	return Settings{
		Snaps:       true,
		XML:         false,
		Titles:      false,
		SkipShitty:  true,
		Lang:        "ru",
		IsActivated: false,
		ChannelText: "",
		CustomTexts: [4]string{},
		OSDColor:    "255,255,255",
		DummyLogin:  defaultDummyLogin,
		DummyPass:   defaultDummyPass,
		Governor:    true,
		GovernorCap: 0,
		GeoDB:       "GeoLite2-Country.mmdb",
		CheckUpdate: true,
	}
}

var cfg = defaultSettings()

func Load() Settings {
	if data, err := os.ReadFile(ConfigFile); err == nil {
		s := defaultSettings()
		var raw map[string]any
		if uerr := toml.Unmarshal(data, &raw); uerr != nil {
			fmt.Fprintf(os.Stderr, "[!] config.toml: %v (применены дефолты)\n", uerr)
		} else {
			applyTomlMap(raw, &s)
		}
		sanitizeSettings(&s)
		cfg = s
	} else if data, err := os.ReadFile(ConfigFileJSON); err == nil {
		s := defaultSettings()
		if jerr := json.Unmarshal(data, &s); jerr != nil {
			fmt.Fprintf(os.Stderr, "[!] config.json: %v (применены дефолты)\n", jerr)
		} else {
			sanitizeSettings(&s)
			cfg = s
		}
		Save()
	}
	_ = fwd.SetProfile("smartpss")
	fwd.SetDefaultCreds("", mergeBrutePasswords(cfg.BrutePasswords))
	scanner.GovernorOn = cfg.Governor
	scanner.GovernorCap = cfg.GovernorCap
	return cfg
}

func Get() Settings {
	return cfg
}

func SetGeo(db string, allow, deny []string, denyUnknown bool) {
	if db = strings.TrimSpace(db); db != "" {
		cfg.GeoDB = db
	}
	cfg.GeoAllow = append([]string{}, allow...)
	cfg.GeoDeny = append([]string{}, deny...)
	cfg.GeoDenyUnknown = denyUnknown
}

func ApplyLang() {
	i18n.SetLang(cfg.Lang)
}

func RememberRun(inFile, outDir string, threads int) {
	if inFile != "" {
		cfg.LastInput = inFile
	}
	if outDir != "" {
		cfg.LastOut = outDir
	}
	if threads > 0 {
		cfg.LastThreads = threads
	}

	b, err := json.MarshalIndent(LastRun{
		Input:    cfg.LastInput,
		OutDir:   cfg.LastOut,
		Threads:  cfg.LastThreads,
		GeoAllow: append([]string{}, cfg.GeoAllow...),
		GeoDeny:  append([]string{}, cfg.GeoDeny...),
	}, "", "  ")
	if err == nil {
		_ = os.WriteFile(LastRunFile, b, 0644)
	}
}

func LoadLastRun() LastRun {
	var lr LastRun
	if data, err := os.ReadFile(LastRunFile); err == nil {
		if json.Unmarshal(data, &lr) == nil && lr.Input != "" {
			return lr
		}
	}
	return LastRun{Input: cfg.LastInput, OutDir: cfg.LastOut, Threads: cfg.LastThreads}
}

func Save() {
	data, err := toml.Marshal(cfg)
	if err != nil {
		return
	}
	_ = os.WriteFile(ConfigFile, data, 0644)
}

func applyTomlMap(m map[string]any, s *Settings) {
	if m == nil {
		return
	}
	getBool := func(key string, dst *bool) {
		if b, ok := m[key].(bool); ok {
			*dst = b
		}
	}
	getBool("snaps", &s.Snaps)
	getBool("xml", &s.XML)
	getBool("titles", &s.Titles)
	getBool("skip_shitty", &s.SkipShitty)
	getBool("wipe_users", &s.WipeUsers)
	getBool("isActivated", &s.IsActivated)
	getBool("debug", &s.Debug)
	getBool("discord_rpc", &s.DiscordRPC)
	getBool("governor", &s.Governor)
	getBool("geo_deny_unknown", &s.GeoDenyUnknown)
	getBool("check_update", &s.CheckUpdate)
	getBool("auto_update", &s.AutoUpdate)

	getStr := func(key string, dst *string) {
		if v, ok := m[key].(string); ok {
			*dst = v
		}
	}
	getStr("last_input", &s.LastInput)
	getStr("last_out", &s.LastOut)
	getStr("lang", &s.Lang)
	getStr("channel_text", &s.ChannelText)
	getStr("text", &s.Text)
	getStr("dummy_login", &s.DummyLogin)
	getStr("dummy_pass", &s.DummyPass)
	getStr("tg_bot_token", &s.TgBotToken)
	getStr("osd_color", &s.OSDColor)
	getStr("geo_db", &s.GeoDB)
	getStr("geo_db_url", &s.GeoDBURL)

	getInt := func(key string, dst *int) {
		switch v := m[key].(type) {
		case int:
			*dst = v
		case int64:
			*dst = int(v)
		case uint64:
			*dst = int(v)
		case float64:
			if v == float64(int(v)) {
				*dst = int(v)
			}
		}
	}
	getInt("last_threads", &s.LastThreads)
	getInt("governor_cap", &s.GovernorCap)

	if arr, ok := m["custom_texts"].([]any); ok {
		var out [4]string
		for i := 0; i < len(arr) && i < 4; i++ {
			if str, ok := arr[i].(string); ok {
				out[i] = str
			}
		}
		s.CustomTexts = out
	}
	if arr, ok := m["brute_passwords"].([]any); ok {
		var out []string
		for _, v := range arr {
			if str, ok := v.(string); ok {
				if str = strings.TrimSpace(str); str != "" {
					out = append(out, str)
				}
			}
		}
		s.BrutePasswords = out
	}
	getStrSlice := func(key string, dst *[]string) {
		arr, ok := m[key].([]any)
		if !ok {
			return
		}
		out := make([]string, 0, len(arr))
		for _, v := range arr {
			if str, ok := v.(string); ok {
				if str = strings.TrimSpace(str); str != "" {
					out = append(out, str)
				}
			}
		}
		*dst = out
	}
	getStrSlice("geo_allow", &s.GeoAllow)
	getStrSlice("geo_deny", &s.GeoDeny)
	if arr, ok := m["tg_chat_ids"].([]any); ok {
		var out []string
		for _, v := range arr {
			switch t := v.(type) {
			case string:
				if t = strings.TrimSpace(t); t != "" {
					out = append(out, t)
				}
			case int64:
				out = append(out, strconv.FormatInt(t, 10))
			case uint64:
				out = append(out, strconv.FormatUint(t, 10))
			case float64:
				if t == float64(int64(t)) {
					out = append(out, strconv.FormatInt(int64(t), 10))
				}
			}
		}
		s.TgChatIDs = out
	}
}

func sanitizeSettings(s *Settings) {
	s.OSDColor = dhip.SetOSDColor(strings.TrimSpace(s.OSDColor))
	s.ChannelText = truncateRunes(s.ChannelText, channelTextLimit)
	for i := range s.CustomTexts {
		s.CustomTexts[i] = truncateRunes(s.CustomTexts[i], customTextLimit)
	}
	if s.Lang != "ru" && s.Lang != "en" {
		s.Lang = "ru"
	}
	if s.LastThreads < 0 {
		s.LastThreads = 0
	}
	if s.GovernorCap < 0 {
		s.GovernorCap = 0
	}
	if s.DummyLogin == "" {
		s.DummyLogin = defaultDummyLogin
	}
	if s.DummyPass == "" {
		s.DummyPass = defaultDummyPass
	}
	var brute []string
	for _, p := range s.BrutePasswords {
		if p = strings.TrimSpace(p); p != "" {
			brute = append(brute, p)
		}
	}
	s.BrutePasswords = brute
	var chats []string
	for _, c := range s.TgChatIDs {
		if c = strings.TrimSpace(c); c != "" {
			chats = append(chats, c)
		}
	}
	s.TgChatIDs = chats
	if s.ChannelText == "" && s.Text != "" {
		s.ChannelText = truncateRunes(s.Text, channelTextLimit)
		s.CustomTexts[0] = truncateRunes(s.Text, customTextLimit)
		s.Text = ""
	}
}

func truncateRunes(s string, n int) string {
	if n < 0 {
		return ""
	}
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

func mergeBrutePasswords(custom []string) []string {
	out := make([]string, 0, len(custom))
	seen := make(map[string]struct{})
	for _, p := range custom {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	if len(out) > 0 {
		return out
	}
	return fwd.GetDefaultPasswordsBase()
}
