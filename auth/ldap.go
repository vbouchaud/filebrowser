package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
	ldapv3 "github.com/go-ldap/ldap/v3"
)

// MethodLdapAuth is used to identify json auth.
const MethodLdapAuth settings.AuthMethod = "ldap"

// LdapAuth is a proxy implementation of an auther.
type LdapAuth struct {
	Ldap      Ldap
	ReCaptcha *ReCaptcha `json:"recaptcha" yaml:"recaptcha"`
}

const (
	ScopeBaseObject   = "base"
	ScopeSingleLevel  = "single"
	ScopeWholeSubtree = "sub"
)

var scopeMap = map[string]int{
	ScopeBaseObject:   0,
	ScopeSingleLevel:  1,
	ScopeWholeSubtree: 2,
}

type UserInfo struct {
	UID      string
	Username string
	Groups   []string
}

type Ldap struct {
	LdapURL          string
	BindDN           string
	BindPassword     string
	SearchBase       string
	SearchScope      string
	SearchFilter     string
	MemberofProperty string
	UsernameProperty string
}

func sanitize(a []string) []string {
	var res []string

	for _, item := range a {
		res = append(res, strings.ToLower(item))
	}

	return res
}

func (s *Ldap) Search(username, password string) (*UserInfo, error) {
	l, err := ldapv3.DialURL(s.LdapURL)
	if err != nil {
		return nil, err
	}

	err = l.Bind(s.BindDN, s.BindPassword)
	if err != nil {
		return nil, err
	}

	defer l.Close()

	searchRequest := ldapv3.NewSearchRequest(
		s.SearchBase,
		scopeMap[s.SearchScope],
		ldapv3.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf(s.SearchFilter, username),
		[]string{s.UsernameProperty, s.MemberofProperty},
		nil,
	)

	result, err := l.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("user not found")
	} else if len(result.Entries) > 1 {
		return nil, fmt.Errorf("too many entries returned")
	}

	err = l.Bind(result.Entries[0].DN, password)
	if err != nil {
		return nil, err
	}

	user := &UserInfo{
		UID:      strings.ToLower(result.Entries[0].DN),
		Username: strings.ToLower(result.Entries[0].GetAttributeValue(s.UsernameProperty)),
		Groups:   sanitize(result.Entries[0].GetAttributeValues(s.MemberofProperty)),
	}

	return user, nil
}

func (s LdapAuth) Auth(r *http.Request, sto users.Store, root string, settings *settings.Settings) (*users.User, error) {
	var cred Cred

	if r.Body == nil {
		return nil, os.ErrPermission
	}

	err := json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		return nil, os.ErrPermission
	}

	// If ReCaptcha is enabled, check the code.
	if s.ReCaptcha != nil && len(s.ReCaptcha.Secret) > 0 {
		ok, err := s.ReCaptcha.Ok(cred.ReCaptcha) //nolint:govet

		if err != nil {
			return nil, err
		}

		if !ok {
			return nil, os.ErrPermission
		}
	}

	ldapUser, err := s.Ldap.Search(cred.Username, cred.Password)
	if err != nil {
		return nil, os.ErrPermission
	}

	u, err := sto.Get(root, cred.Username)
	if err != nil {
		// user do not exist yet

		u := &users.User{
			Username: ldapUser.Username,
			Password: cred.Password,
		}

		settings.Defaults.Apply(u)
		userHome, err := settings.MakeUserDir(u.Username, u.Scope, root)
		if err != nil {
			return nil, err
		}
		u.Scope = userHome

		err = sto.Save(u)
		if err != nil {
			return nil, err
		}
	}

	return u, nil
}

// LoginPage tells that ldap auth require a login page.
func (s LdapAuth) LoginPage() bool {
	return true
}
