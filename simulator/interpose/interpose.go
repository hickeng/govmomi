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

package interpose

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"syscall"
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

const (
	InterposePath        = "/.shadow"
	InterposeMetaPath    = InterposePath + "/meta"
	InterposeContentPath = InterposePath + "/content"

	interposeClientConfigPath = InterposeMetaPath + "/interpose-client.config"
)

func cleanInvocationPath(dirty string) string {
	canonicalizedDir, _ := filepath.EvalSymlinks(path.Dir(dirty))
	absDir, _ := filepath.Abs(canonicalizedDir)
	return filepath.Join(absDir, path.Base(dirty))
}

func directInvocation() {
	fmt.Printf("Direct invocation of interpose - processing flags\n")

	// - optional - we can just synthesize this through manual symlinks initially
	// - may be best to defer until home as this part depends on manifest for input
	// --install --target / --default-source /.shadow/content --override-source /.shadow/overrides --config /.shadow/meta/esx-filesystem-manifest.json
	flag.Bool("create-reflection", false, "If specified, interceptor will create reflections of source in target as indicated by config")
	flag.String("target", "/", "Specify the location in which intercepted reflections will be created. Directory path.")
	flag.String("source", "/.shadow/content", "The location of files to reflect into target. Directory path.")
	flag.String("config", "/.shadow/meta/interceptor-config.json", "Path to the config file")

	flag.Parse()

	path := InterposeContentPath + "/bin"
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}

	fileInfo, err := f.Readdir(-1)
	f.Close()
	if err != nil {
		panic(err)
	}

	fmt.Println("File Name\t\tSize\t\tIsDir\t\tModified Time")
	for _, file := range fileInfo {
		target := ""
		if file.Mode()&os.ModeSymlink != 0 {
			linkTarget, err := os.Readlink(filepath.Join(path, file.Name()))
			if err != nil {
				panic(err)
			}

			target = fmt.Sprintf(" -> %s", linkTarget)
		}

		fmt.Printf("%v%v\n", file.Name(), target)
	}
}

func Interpose(exe string, args []string, env []string, pwd string) {
	// determine normalized invocation path
	identity := exe
	lookPath, _ := exec.LookPath(identity)

	// expose Server port for interpose controller to connect to (vcsim)
	// - may want to defer the Server approach
	// - it'll be particularly useful if using remote container hosts, but for now requires:
	//   - a continuous presence to Serve an endpoint
	//   - a means for each interpose instance to connect to that server and obtain direct

	// call out to a defined interpose endpoint (vcsim) to get instructions
	// - take the endpoint config as part of the interpose spec or env var
	// - Server runs in vcsim which is already a continuous presence

	// invoke target per interpose instructions
	//! Remember this is just a hack until we have the manifest providing the actual interpose mapping. Don't go overboard on making it polished.

	invocation := cleanInvocationPath(lookPath)
	var target string
	for ; !strings.HasPrefix(target, InterposeContentPath); invocation = cleanInvocationPath(target) {

		fmt.Printf("Invocation path: %s, identity: %s\n", invocation, identity)

		// if invoked directly, process flags
		if path.Dir(invocation) == InterposeMetaPath {
			directInvocation()
			break
		}

		target = filepath.Clean(InterposeContentPath + "/" + invocation)
		fileInfo, err := os.Lstat(target)
		if err != nil {
			log.Fatalf("Unable to stat invocation target: %s, %s", target, err)
		}

		if fileInfo.Mode()&os.ModeSymlink != 0 {
			// check for recursion otherwise running the following can result in an infinite loop because the shadow content is a symlink back to interprose with the same argv[0]
			// 		docker run -it --entrypoint=/bin/ls sim-host-dev -l /bin/ls

			// NOTE: we don't bother with full recursive resolution which will involve tracking which names we've seen before.
			// It's something we can add if we ever find the need. A single layer check should suffice for the interpose->sym-util->sym-toybox->interpose-as-toybox
			target2, err := os.Readlink(target)
			if err != nil {
				log.Fatalf("Unable to determine final invocation from symlink target: %s, %s", target, err)
			}

			// symlinks are evaled relative to their location unless explicitly absolute.
			// "target" is abs at this point, so the join will force the target to absolute
			if !filepath.IsAbs(target2) {
				target2 = filepath.Join(filepath.Dir(target), target2)
			}

			// If the target of the symlink is not in the shadow content, then skip one level of links.
			// This is done so we don't find ourselves invoking interprose with the same argv[0]
			// As a specific example, instead of seeing /.s/c/bin/ls -> /usr/bin/toybox this will map directly to /.s/c/usr/bin/toybox
			if !strings.HasPrefix(target2, InterposeContentPath) {
				target = target2
			}
		}
	}

	//ldLibraryPath, _ := os.LookupEnv("LD_LIBRARY_PATH")
	//env = append(env, "LD_DEBUG=files,libs")
	//fmt.Printf("execing %s with LD_LIBRARY_PATH: %s\n", target, ldLibraryPath)

	style, session, err := newClient(context.Background(), target, args, env, pwd)
	if err != nil {
		panic(err)
	}

	if style == PASSTHROUGH {
		execErr := syscall.Exec(target, args, env)
		if execErr != nil {
			// TODO: log failure to server
			panic(execErr)
		}
		// cannot reach here
	}

	// remote
	_ = session
	// TODO: relay stdin to remote
	// TODO: capture signals to relay to remote
	// TODO: relay stdout to caller
	// TODO: relay stderr to caller

	// TODO: get exit code from remote
	os.Exit(0)
}
