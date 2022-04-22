package settings

import (
	"crypto/rand"
	"strings"

	"github.com/filebrowser/filebrowser/v2/rules"
)

// AuthMethod describes an authentication method.
type AuthMethod string

// Settings contain the main settings of the application.
type Settings struct {
	Key           []byte              `json:"key"`
	Signup        bool                `json:"signup"`
	CreateUserDir bool                `json:"createUserDir"`
	Defaults      UserDefaults        `json:"defaults"`
	AuthMethod    AuthMethod          `json:"authMethod"`
	Branding      Branding            `json:"branding"`
	Commands      map[string][]string `json:"commands"`
	Shell         []string            `json:"shell"`
	Rules         []rules.Rule        `json:"rules"`
	Ldap          Ldap                `json:"ldap"`
}

// GetRules implements rules.Provider.
func (s *Settings) GetRules() []rules.Rule {
	return s.Rules
}

type Ldap struct {
	Url              string `json:"url"`
	BindDN           string `json:"bind-dn"`
	BindPassword     string `json:"bind-password"`
	SearchBase       string `json:"search-base"`
	SearchScope      string `json:"search-scope"`
	SearchFilter     string `json:"ldap.search-filter"`
	MemberofProperty string `json:"ldap.property-memberof"`
	UsernameProperty string `json:"ldap.property-username"`
}

// Server specific settings.
type Server struct {
	Root                  string `json:"root"`
	BaseURL               string `json:"baseURL"`
	Socket                string `json:"socket"`
	TLSKey                string `json:"tlsKey"`
	TLSCert               string `json:"tlsCert"`
	Port                  string `json:"port"`
	Address               string `json:"address"`
	Log                   string `json:"log"`
	EnableThumbnails      bool   `json:"enableThumbnails"`
	ResizePreview         bool   `json:"resizePreview"`
	EnableExec            bool   `json:"enableExec"`
	TypeDetectionByHeader bool   `json:"typeDetectionByHeader"`
}

// Clean cleans any variables that might need cleaning.
func (s *Server) Clean() {
	s.BaseURL = strings.TrimSuffix(s.BaseURL, "/")
}

// GenerateKey generates a key of 512 bits.
func GenerateKey() ([]byte, error) {
	b := make([]byte, 64) //nolint:gomnd
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}
