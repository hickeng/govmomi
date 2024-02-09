/*
Copyright (c) 2024-2024 VMware, Inc. All Rights Reserved.

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

package interpose

import (
	"bytes"
	"html/template"
	"log"
	"testing"

	"github.com/stretchr/testify/require"
)

// Reference command:
//
//	esxcli --formatter=keyvalue network ip interface ipv4 get
func TestEsxcliIpTemplate(t *testing.T) {
	tmpl, err := template.New("esxcli-network-ip-interface-ipv4-get-keyvalue-tmp.tmpl").ParseFiles("esxcli-network-ip-interface-ipv4-get-keyvalue-tmp.tmpl")
	require.Nil(t, err, "expected to cleanly load template")

	type esxcli struct {
		Name          string
		DHCPAddress   bool
		DHCPDNS       bool
		Gateway       string
		IPv4Address   string
		IPv4Broadcast string
		IPv4Netmask   string
	}

	data := []esxcli{
		{
			Name:          "vmk0",
			DHCPAddress:   true,
			DHCPDNS:       true,
			Gateway:       "",
			IPv4Address:   "1.2.3.4",
			IPv4Broadcast: "1.2.3.255",
			IPv4Netmask:   "255.255.255.0",
		},
	}

	render := bytes.Buffer{}
	err = tmpl.Execute(&render, data)
	require.Nil(t, err, "template must process cleanly")

	log.Println("hello")
	output := string(render.Bytes())
	log.Println(output)
	log.Println("goodbye")
}
