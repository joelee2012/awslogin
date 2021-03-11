package awslogin

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/Azure/go-ntlmssp"

	"github.com/aws/aws-sdk-go/aws"
	// "github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"gopkg.in/go-ini/ini.v1"
)


type Input struct {
	Value string `xml:"value,attr"`
}
type SAMLResponseHTML struct {
	XMLName xml.Name `xml:"html"`
	Input   Input    `xml:"body>form>input"`
}

type SAMLResponseXML struct {
	XMLName    xml.Name    `xml:"Response"`
	Attributes []Attribute `xml:"Assertion>AttributeStatement>Attribute"`
}

type Attribute struct {
	Name            string   `xml:"Name,attr"`
	AttributeValues []string `xml:"AttributeValue"`
}

type Client struct {
	url, user, passowrd, assertion string
	raw []byte
}

func NewClient(url, user, passowrd string) *Client {
	return &Client{
		url:       url,
		user:      user,
		passowrd:  passowrd,
		assertion: "",
		raw:       []byte{},
	}
}

func (s *Client) Login() error {
	client := &http.Client{
		Transport: ntlmssp.Negotiator{
			RoundTripper: &http.Transport{},
		},
	}
	req, err := http.NewRequest("GET", s.url, nil)
	if err != nil {
		return fmt.Errorf("new request to %s failed with error: %v", s.url, err)
	}
	req.SetBasicAuth(s.user, s.passowrd)
	v := req.URL.Query()
	v.Add("loginToRp", "urn:amazon:webservices")
	req.URL.RawQuery = v.Encode()
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("do request to %s failed with error: %v", s.url, err)
	}
	defer resp.Body.Close()
	s.raw, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body failed error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("request %s failed with code %d and content %q", s.url, resp.StatusCode, s.raw)
	}
	return nil
}

// ParseSAMLResponse parse saml response from html
func (s *Client) ParseResponse() error {
	var samlHTML SAMLResponseHTML
	if err := xml.Unmarshal(s.raw, &samlHTML); err != nil {
		return  fmt.Errorf("unmarshal html %q failed with error: %v", s.raw, err)
	}
	s.assertion = samlHTML.Input.Value
	return nil
}

func (s *Client) GetArnRoles() ([]string, error) {
	var samlXML SAMLResponseXML
	decStr, err := base64.StdEncoding.DecodeString(s.assertion)
	if err != nil {
		return nil, fmt.Errorf("deccode %q failed with error: %v", s.assertion, err)
	}
	if err := xml.Unmarshal(decStr, &samlXML); err != nil {
		return nil, fmt.Errorf("unmarshal xml %q failed with error: %v", decStr, err)
	}
	var roles []string
	for _, att := range samlXML.Attributes {
		if strings.HasSuffix(att.Name, "Role") {
			for _, v := range att.AttributeValues {
				roles = append(roles, v)
			}
		}
	}
	return roles, nil
}

func (s *Client) GetSTSCredential(principalArn, roleArn string) (*sts.AssumeRoleWithSAMLOutput, error) {
	svc := sts.New(session.New())
	input := &sts.AssumeRoleWithSAMLInput{
		DurationSeconds: aws.Int64(3600),
		PrincipalArn:    aws.String(principalArn),
		RoleArn:         aws.String(roleArn),
		SAMLAssertion:   aws.String(s.assertion),
	}
	return svc.AssumeRoleWithSAML(input)
}

func (s *Client) WriteCredentialToIni(token *sts.AssumeRoleWithSAMLOutput, file string) error {
	cfg := ini.Empty()
	sec, err := cfg.NewSection("saml")
	if err != nil {
		return fmt.Errorf("get/create section 'saml' failed with error: %v", err)
	}
	var data = map[string]string{
		"output": "json",
		"aws_access_key_id": *token.Credentials.AccessKeyId,
		"aws_secret_access_key": *token.Credentials.SecretAccessKey,
		"aws_session_token": *token.Credentials.SessionToken,
	}
	for key, value := range data {
		if _, err := sec.NewKey(key, value); err !=nil {
			return fmt.Errorf("set new key %q failed with error: %v",  key, err)
		}
	}
	return cfg.SaveTo(file)
}