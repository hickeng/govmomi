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
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
)

/* Test for how the various options for getting executable behave under hard links/symlinks

ln -s /.interpose/bin/interpose /bin/test-bin
ln /.interpose/bin/interpose /bin/test-bin-hard

root [ /bin ]# cd /tmp && test-bin
ident: test-bin, executable: /.interpose/bin/interpose, path: /.interpose/bin
root [ /tmp ]# cd /tmp && test-bin-hard
ident: test-bin-hard, executable: /usr/bin/test-bin-hard, path: /usr/bin

Looks like the only option here without substantial effort is to use a hardlink if we need the full path.
If willing to put the effort in, then we can detect when it's an unqualified path

1. if identity is hardlink
	? can we just check the os.Executable is NOT the interpose path?
	- use os.Executable
2. if identity is symlink
	- if absolute
		- use identity as is
	- if dirpath is non-null
		- canonicalize resolvePath+identity
	- else
		- use resolvePath to look up identity

exec.LookPath does basically this.
There's a quirk where you specify an abs path that goes via a symlink dir - the directory isn't canonicalized.

*/

func main() {
	// determine normalized invocation path
	identity := os.Args[0]
	lookPath, _ := exec.LookPath(identity)
	canonicalizedDir, _ := filepath.EvalSymlinks(path.Dir(lookPath))
	absDir, _ := filepath.Abs(canonicalizedDir)
	invocation := fmt.Sprintf("%s/%s", absDir, path.Base(lookPath))

	fmt.Printf("Invocation path: %s", invocation)

	// if invoked directly, process flags
	// - optional - we can just synthesize this through manual symlinks initially
	// - may be best to defer until home as this part depends on manifest for input

	// expose Server port for interpose controller to connect to (vcsim)
	// - may want to defer the Server approach
	// - it'll be particularly useful if using remote container hosts, but for now requires:
	//   - a continuous presence to Serve an endpoint
	//   - a means for each interpose instance to connect to that server and obtain direct

	// call out to a defined interpose endpoint (vcsim) to get instructions
	// - take the endpoint config as part of the interpose spec or env var
	// - Server runs in vcsim which is already a continuous presence

	// invoke target per interpose instructions

	os.Exit(0)
}
