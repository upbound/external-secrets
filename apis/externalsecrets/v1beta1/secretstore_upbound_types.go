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

package v1beta1

// UpboundProvider configures a store to sync secrets with Upbound Spaces
type UpboundProvider struct {
	// StoreRef holds ref to Upbound Spaces secret store
	StoreRef UpboundStoreRef `json:"storeRef"`
}

// UpboundStoreRef holds ref to Upbound Spaces secret store
type UpboundStoreRef struct {
	// Name of the secret store on Upbound Spaces
	Name string `json:"name"`
}
