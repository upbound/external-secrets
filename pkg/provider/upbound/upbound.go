/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package upbound

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	"github.com/external-secrets/external-secrets/pkg/feature"
)

var (
	errMissingStore           = fmt.Errorf("missing store provider")
	errMissingUpboundProvider = fmt.Errorf("missing store provider upboundspaces")

	logger = ctrl.Log.WithName("provider").WithName("upboundspaces")

	kubeconfig string
	namespace  string

	gvk = schema.GroupVersionKind{Group: "spaces.upbound.io", Version: "v1alpha1", Kind: "SharedSecretStore"}
)

type Provider struct {
	hcClient  client.Client
	namespace string
}

func (p *Provider) NewClient(ctx context.Context, store esv1beta1.GenericStore, _ client.Client, _ string) (esv1beta1.SecretsClient, error) {
	ctpstore, err := p.getCtpStore(store)
	if err != nil {
		return nil, err
	}
	ctpprovider, err := esv1beta1.GetProvider(ctpstore)
	if err != nil {
		return nil, err
	}
	return ctpprovider.NewClient(ctx, ctpstore, p.hcClient, p.namespace)
}

func (p *Provider) getCtpStore(store esv1beta1.GenericStore) (esv1beta1.GenericStore, error) {
	sp, err := getProvider(store)
	if err != nil {
		return nil, err
	}
	u := &unstructured.Unstructured{}
	u.SetName(sp.StoreRef.Name)
	u.SetGroupVersionKind(gvk)
	ctx := context.Background()
	defer ctx.Done()

	if err := p.hcClient.Get(ctx, types.NamespacedName{Name: sp.StoreRef.Name, Namespace: p.namespace}, u); err != nil {
		return nil, err
	}
	ctpstore := &esv1beta1.SecretStore{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sp.StoreRef.Name,
			Namespace: p.namespace,
		},
	}
	ctpstoreprovider, found, err := unstructured.NestedFieldCopy(u.Object, "spec", "provider")
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("no spec.provider found in ControlPlaneSecretStore: %v", u.Object)
	}
	b, err := json.Marshal(ctpstoreprovider)
	if err != nil {
		return nil, err
	}

	ssprovider := &esv1beta1.SecretStoreProvider{}
	if err := json.Unmarshal(b, ssprovider); err != nil {
		return nil, err
	}
	ctpstore.Spec.Provider = ssprovider

	return ctpstore, nil
}

func (p *Provider) ValidateStore(_ esv1beta1.GenericStore) error {
	return nil
}

func (p *Provider) Capabilities() esv1beta1.SecretStoreCapabilities {
	return esv1beta1.SecretStoreReadOnly
}

func getProvider(store esv1beta1.GenericStore) (*esv1beta1.UpboundProvider, error) {
	if store == nil {
		return nil, errMissingStore
	}
	spc := store.GetSpec()
	if spc == nil || spc.Provider == nil || spc.Provider.Upboundspaces == nil {
		return nil, errMissingUpboundProvider
	}
	return spc.Provider.Upboundspaces, nil
}

func init() {
	fs := pflag.NewFlagSet("upbound", pflag.ExitOnError)
	fs.StringVar(&namespace, "hc-namespace", "", "hostcluster namespace where to look for controlplane secret stores")
	fs.StringVar(&kubeconfig, "hc-kubeconfig", "", "hostcluster kubeconfig")

	lateInit := func() {
		if namespace == "" {
			logger.Info("hostcluster namespace not provided, upbound provider remains inactive")
			return
		}
		config, err := restConfig()
		if err != nil {
			logger.Error(err, "unable to determine hostcluster config")
			os.Exit(1)
		}

		hcc, err := client.New(config, client.Options{})
		if err != nil {
			logger.Error(err, "unable to create hostcluster client")
			os.Exit(1)
		}
		esv1beta1.Register(&Provider{hcClient: hcc, namespace: namespace}, &esv1beta1.SecretStoreProvider{
			Upboundspaces: &esv1beta1.UpboundProvider{},
		})
		logger.Info("Upboundspaces provider initialized")
	}

	feature.Register(feature.Feature{
		Flags:      fs,
		Initialize: lateInit,
	})
}

func restConfig() (*rest.Config, error) {
	if kubeconfig != "" {
		return restConfigForKubeconfigFile(kubeconfig)
	}
	logger.Info("hostcluster kubeconfig not provided, assuming in-cluster configuration.")
	return rest.InClusterConfig()
}

func restConfigForKubeconfigFile(kubeconfig string) (*rest.Config, error) {
	ac, err := clientcmd.LoadFromFile(kubeconfig)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load kubeconfig")
	}
	return restConfigFromAPIConfig(ac)
}

func restConfigFromAPIConfig(c *api.Config) (*rest.Config, error) {
	if c.CurrentContext == "" {
		return nil, errors.New("currentContext not set in kubeconfig")
	}
	ctx := c.Contexts[c.CurrentContext]
	cluster := c.Clusters[ctx.Cluster]
	if cluster == nil {
		return nil, errors.Errorf("cluster for currentContext (%s) not found", c.CurrentContext)
	}
	user := c.AuthInfos[ctx.AuthInfo]
	if user == nil {
		// We don't require a user because it's possible user
		// authorization configuration will be loaded from a separate
		// set of identity credentials (e.g. Google Application Creds).
		user = &api.AuthInfo{}
	}
	return &rest.Config{
		Host:            cluster.Server,
		Username:        user.Username,
		Password:        user.Password,
		BearerToken:     user.Token,
		BearerTokenFile: user.TokenFile,
		Impersonate: rest.ImpersonationConfig{
			UserName: user.Impersonate,
			Groups:   user.ImpersonateGroups,
			Extra:    user.ImpersonateUserExtra,
		},
		AuthProvider: user.AuthProvider,
		ExecProvider: user.Exec,
		TLSClientConfig: rest.TLSClientConfig{
			Insecure:   cluster.InsecureSkipTLSVerify,
			ServerName: cluster.TLSServerName,
			CertData:   user.ClientCertificateData,
			KeyData:    user.ClientKeyData,
			CAData:     cluster.CertificateAuthorityData,
		},
	}, nil
}
