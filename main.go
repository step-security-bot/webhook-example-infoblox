package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"

	ibclient "github.com/infobloxopen/infoblox-go-client/v2"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.

	cmd.RunWebhookServer(GroupName,
		&customDNSProviderSolver{},
	)
}

// customDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/jetstack/cert-manager/pkg/acme/webhook.Solver`
// interface.
type customDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	client *kubernetes.Clientset
}

// customDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type customDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	Host                string                   `json:"host"`
	Version             string                   `json:"version"             default:"2.5"`
	Port                string                   `json:"port"                default:"443"`
	UsernameSecretRef   cmmeta.SecretKeySelector `json:"usernameSecretRef"`
	PasswordSecretRef   cmmeta.SecretKeySelector `json:"passwordSecretRef"`
	View                string                   `json:"view"`
	SslVerify           bool                     `json:"sslVerify"           default:"false"`
	HttpRequestTimeout  int                      `json:"httpRequestTimeout"  default:"60"`
	HttpPoolConnections int                      `json:"httpPoolConnections" default:"10"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *customDNSProviderSolver) Name() string {
	return "infoblox-wapi"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *customDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	// Initialize ibclient
	ib, err := c.getIbClient(&cfg, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	// Find or create TXT record
	recordName := c.DeDot(ch.ResolvedFQDN)

	recordRef, err := c.GetTXTRecord(ib, recordName, ch.Key, cfg.View)
	if err != nil {
		return nil
	}

	if recordRef != "" {
		logf.V(logf.InfoLevel).InfoS("TXT record already present", "name", recordName, "ref", recordRef)
	} else {
		recordRef, err := c.CreateTXTRecord(ib, recordName, ch.Key, cfg.View)
		if err != nil {
			return err
		}
		logf.V(logf.InfoLevel).InfoS("Created new TXT record", "name", recordName, "ref", recordRef)
	}

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *customDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	// Initialize ibclient
	ib, err := c.getIbClient(&cfg, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	// Find and delete TXT record
	recordName := c.DeDot(ch.ResolvedFQDN)

	recordRef, err := c.GetTXTRecord(ib, recordName, ch.Key, cfg.View)
	if err != nil {
		return err
	}

	if recordRef == "" {
		logf.V(logf.InfoLevel).InfoS("TXT record not found, skipping deletion", "name", recordName, "text", ch.Key)
		return nil
	}

	err = c.DeleteTXTRecord(ib, recordRef)
	if err != nil {
		return err
	}
	logf.V(logf.InfoLevel).InfoS("Deleted TXT record", "name", recordName, "ref", recordRef)

	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// ibections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *customDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl

	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *apiextensionsv1.JSON) (customDNSProviderConfig, error) {
	cfg := customDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

// Initialize and return infoblox client connector
// Configuration can be set in the webhook `config` section.
// Two secretRefs are needed to securely pass infoblox credentials
func (c *customDNSProviderSolver) getIbClient(cfg *customDNSProviderConfig, namespace string) (ibclient.IBConnector, error) {

	// Find secret credentials
	username, err := c.getSecret(cfg.UsernameSecretRef, namespace)
	if err != nil {
		return nil, err
	}

	password, err := c.getSecret(cfg.PasswordSecretRef, namespace)
	if err != nil {
		return nil, err
	}

	// Set default values if needed
	_t := reflect.TypeOf(customDNSProviderConfig{})
	if cfg.Port == "" {
		_f, _ := _t.FieldByName("Port")
		cfg.Port = _f.Tag.Get("default")
	}
	if cfg.Version == "" {
		_f, _ := _t.FieldByName("Version")
		cfg.Version = _f.Tag.Get("default")
	}
	if cfg.HttpRequestTimeout <= 0 {
		_f, _ := _t.FieldByName("HttpRequestTimeout")
		if i, err := strconv.Atoi(_f.Tag.Get("default")); err == nil {
			cfg.HttpRequestTimeout = i
		}
	}
	if cfg.HttpPoolConnections <= 0 {
		_f, _ := _t.FieldByName("HttpPoolConnections")
		if i, err := strconv.Atoi(_f.Tag.Get("default")); err == nil {
			cfg.HttpPoolConnections = i
		}
	}

	// Initialize ibclient
	hostConfig := ibclient.HostConfig{
		Host:     cfg.Host,
		Version:  cfg.Version,
		Port:     cfg.Port,
		Username: username,
		Password: password,
	}

	transportConfig := ibclient.NewTransportConfig(strconv.FormatBool(cfg.SslVerify), cfg.HttpRequestTimeout, cfg.HttpPoolConnections)
	requestBuilder := &ibclient.WapiRequestBuilder{}
	requestor := &ibclient.WapiHttpRequestor{}

	ib, err := ibclient.NewConnector(hostConfig, transportConfig, requestBuilder, requestor)
	if err != nil {
		return nil, err
	}

	return ib, nil
}

// Resolve the value of a secret given a SecretKeySelector with name and key parameters
func (c *customDNSProviderSolver) getSecret(sel cmmeta.SecretKeySelector, namespace string) (string, error) {
	secret, err := c.client.CoreV1().Secrets(namespace).Get(context.Background(), sel.Name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}

	secretData, ok := secret.Data[sel.Key]
	if !ok {
		return "", err
	}

	return strings.TrimSuffix(string(secretData), "\n"), nil
}

// Get the ref for TXT record in InfoBlox given its name, text and view
func (c *customDNSProviderSolver) GetTXTRecord(ib ibclient.IBConnector, name string, text string, view string) (string, error) {
	var records []ibclient.RecordTXT
	recordTXT := ibclient.NewRecordTXT(ibclient.RecordTXT{})
	params := map[string]string{
		"name": name,
		"text": text,
		"view": view,
	}
	err := ib.GetObject(recordTXT, "", ibclient.NewQueryParams(false, params), &records)

	if len(records) > 0 {
		return records[0].Ref, err
	} else {
		return "", err
	}
}

// Create a TXT record in Infoblox
func (c *customDNSProviderSolver) CreateTXTRecord(ib ibclient.IBConnector, name string, text string, view string) (string, error) {
	recordTXT := ibclient.NewRecordTXT(ibclient.RecordTXT{
		Name: name,
		Text: text,
		View: view,
	})

	return ib.CreateObject(recordTXT)
}

// Delete a TXT record in Infoblox by ref
func (c *customDNSProviderSolver) DeleteTXTRecord(ib ibclient.IBConnector, ref string) error {
	_, err := ib.DeleteObject(ref)

	return err
}

// Remove trailing dot
func (c *customDNSProviderSolver) DeDot(string string) string {
	result := strings.TrimSuffix(string, ".")

	return result
}
