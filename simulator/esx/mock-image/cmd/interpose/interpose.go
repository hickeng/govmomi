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
	"os"

	"github.com/vmware/govmomi/simulator/interpose"
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
	pwd, _ := os.Getwd()
	interpose.Interpose(os.Args[0], os.Args, os.Environ(), pwd)

	os.Exit(0)
}
