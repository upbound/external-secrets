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

package commontest

import (
	"context"
	"fmt"
	"time"

	"github.com/google/go-cmp/cmp"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CreateNamespace creates a new namespace in the cluster.
func CreateNamespace(baseName string, c client.Client) (string, error) {
	return CreateNamespaceWithLabels(baseName, c, map[string]string{})
}

func CreateNamespaceWithLabels(baseName string, c client.Client, labels map[string]string) (string, error) {
	genName := fmt.Sprintf("ctrl-test-%v", baseName)
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: genName,
			Labels:       labels,
		},
	}

	err := wait.PollUntilContextTimeout(context.Background(), time.Second, 10*time.Second, true, func(ctx context.Context) (done bool, err error) {
		err = c.Create(ctx, ns)
		if err != nil {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return "", err
	}
	return ns.Name, nil
}

func HasOwnerRef(meta metav1.ObjectMeta, kind, name string) bool {
	for _, ref := range meta.OwnerReferences {
		if ref.Kind == kind && ref.Name == name {
			return true
		}
	}
	return false
}

func HasFieldOwnership(meta metav1.ObjectMeta, mgr, expected string) string {
	for _, ref := range meta.ManagedFields {
		if ref.Manager == mgr {
			if diff := cmp.Diff(string(ref.FieldsV1.Raw), expected); diff != "" {
				return fmt.Sprintf("(-got, +want)\n%s", diff)
			}
			return ""
		}
	}
	return fmt.Sprintf("No managed fields managed by %s", mgr)
}
