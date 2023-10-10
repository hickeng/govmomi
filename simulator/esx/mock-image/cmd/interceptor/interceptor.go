/*
Copyright (c) 2023-2023 VMware, Inc. All Rights Reserved.

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

package main

import (
	"flag"
)

// --install --target / --default-source /.shadow/content --override-source /.shadow/overrides --config /.shadow/meta/esx-filesystem-manifest.json
func main() {
	flag.Bool("create-reflection", false, "If specified, interceptor will create reflections of source in target as indicated by config")
	flag.String("target", "/", "Specify the location in which intercepted reflections will be created. Directory path.")
	flag.String("source", "/.shadow/content", "The location of files to reflect into target. Directory path.")
	flag.String("config", "/.shadow/meta/interceptor-config.json", "Path to the config file")

	flag.Parse()
}
