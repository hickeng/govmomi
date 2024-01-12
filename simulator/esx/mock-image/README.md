# Mock ESXi image

The purpose of this container image is to provide a mock environment for the container-backed hosts created by vcsim that is _sufficiently_ similar to an ESX to work as a test environment for ESXi binaries and scripts.

To allow proper unit test usage it's necessary to support an interpose mechansim, allowing a testcase to perform:
* fault injection
* command interception and response rewriting
* interception of general file IO
* logging of file access/execution

Most mock function shouldn't require the above capabilities, but instead can be achieved by mock versions of the CLI utilities, however I want to avoid test authors needing to modify the mock image under most circumstances as that adds substantial logistical complexity to testing.


## Function to mock

This is a shortlist of executables warranting mocking
* /bin/configstorecli
* /bin/esxcfg-advcfg
* /bin/localcli
* /bin/vmkfstools
* /bin/vmkload_mod
* /bin/vsish
* /usr/lib/vmware/vds-vsip/bin/vds-vsipioctl
* /bin/esxcli

## Generation of a file listing from ESX


## Mock image construction

The basics of mocking an ESX filesystem environment where we need some approximation of executable function requires:
1. knowledge of what an ESX environment looks like
2. knowledge of how to get a linux executable to fill the role of the original ESX binary

I have used the following command to generate a file listing from ESX as a reference of what's expected and fills part of (1). It doesn't capture anything about the functional surface of executables, but likely that's not needed.:
```bash
(
    echo "["
    find . | xargs stat -c '{ "hstat": "%A", "stat": "%a", "owner": "%U", "group": "%G", "path": "%n" },' *| sed 's/\.[[:digit:]]\+[ ]\+-[[:digit:]]\+/ /'
    echo "]"
) > esx-file-list.json
```
It would be interesting to capture the full help output for every executable, assuming they provide it, as an informal record of self-described semantics. However not all executables have help output and some, eg. `vds-vsipioctl`, have incomplete output. As such it's probably not useful.

For (2) we need:
1. locations from which we can install executables
2. mapping from ESX binary to mock binary
   * default transforms for input/output

Test case specific interpose logic, such as fault injection or output rewrite, should not be part of the image as that causes us to trend towards an image build step per test case.
However a general transform of input/output to improve the fidelity of mocking for a given binary makes sense to have present in the image. Any per-test transform should be handled post these per-image transforms if mutating as that keeps the mutation expression as close to that needed for real ESX as possible.
We can look at later optimization for pre-image transform in the case all output is to be be discarded to avoid disposable work.

Finally we need to replace mock executables with a mechanism allowing test logic to interpose in the call path.

## Live interpose

When the container is created from our mock image, vcsim needs to inject the callback destination to which interpose must connect.
We should look at an optimization to allow expression of interpose config via manifest that can be referenced per-test, per-testsuite, etc. This is to allow for config-as-data and avoid all hooks being configured via code.
We can look at optimization that push transformation and hook processing into interpose, but should not do so initially. This mechanism must be present in vcsim in order to allow for arbitrary per-test mutations, so duplicating it in the container interpose logic is purely an optimization to reduce traffic.

vcsim:
1. injects callback endpoint into the container for interpose to use
2. retrieves image-level config-as-data for input/output transforms

In vcsim, we need interpose to:
1. Report the pending invocation
2. Process any registered pre-hooks
3. Instruct interpose on whether to invoke or return
3a. If invoking, stream or batch output to test, or keep local
4. Collect exit code and output of invocation
5. Instruct interpose on what to return

This requires:
1. Server in vcsim
2. Message definitions suited for interaction
3. Mechanism for registering hooks by path, arg patterns, “host”, “invoker” (to allow only hooking spherelet calls)
4. Mechanism for listing and deregistering hooks


The manifest used to control the filesystem presented by the mock image allows expression of:
* a path on ESX
* the source of the file for the image (could be from repo, path location in container image eg. /.shadow/content/path, etc)
* logging config - details about what/how to log any interaction with this file
* intercept config - what to do during read/write/exec (expressed)
  * read/write interception will require a FUSE integration so is likely a longer term goal. This would be particularly useful in the VM backing for allowing extension into sophisticated configs such as PCI pass-through.
  * netfilter - if it's possible to intercept the open of `AF_VSOCK` via netfilter, that may be a neat way of capturing the VMCI channel

To allow the interpose mechanism to be accessible within testcases there will need to be a network connection.
We will assume it's network rather than unix domain socket as that allows for remote container hosts.

The mock image will open a server port allowing the test to connect to the interpose mechanism as it's substantially simpler to allow the vcsim logic to determine IP/port for such an endpoint than to try and communicate an endpoint hosted by vcsim instance.

The port serving interpose can be annotated by label and discovered by vcsim, overridden if needed via the same advanced config mechanism used to specify the container image backing.

### 2023-10-31

We need expressions for the following:
1. files that should be present in the image
  * presentation path -? can we usefully separate this from reference path, or should the interpose conceptually _move_ the file out of place?
    * reference path
  * origin/acquisition - rpm install? copy-from-image? mocks?
2. interpose mechanism (exec, read/write, ...)
  * path to interpose on
  * triggers and behaviour - the interpose mechanism dictates possible values, so they're tightly coupled

?? Do we interpose on _every_ executable file and just not do anything except log? That allows arbitrary runtime flexibility in vcsim, but each invocation comes with cost.
  -> While it initially seems sensible to only interpose where needed, that starts to push towards building a mock image for every different interpose config. If we interpose everything but as a "noop" passthrough if no action is configured then we can have a common image.

If we interpose every executable, then we can separate the filesystem construction from the interpose logic completely. They could be separate manifests.

That would allow an easier expression of:
1. Package install to x/y/z
2. Hard link or symlink from presentation a/b/c to package file x/y/z/blah to get the “ESX” surface
If x/y/z is hardcoded to the content directory then transforming the manifest gathered from ESX is a matter of adding tend package name to each file.
More complexity may be needed for file content not from rpm (vmodl, xml, etc) but perhaps those can be pulled from the ESX in question? Live as part of the build? —> figure out what build workflow makes sense for users of vcsim.

Then a second round to replace executables from prior phase with interpose. That’s a little less “efficient” than applying the interpose directly but allows for a sort of concept separation:
a. Mock the file system content
b. Install interpose

The next layer would be configuration of interpose, which really just means providing a manifest of triggers/actions, probably with defaults for logging or noop.
Do we even need local logging and config in interpose? Simplest is to forward every invocation to vcsim and process there. This basically removes any manifest parsing from interpose, as it does the same thing for every execution.

All of the above is image build.



## Notes

* LD_LIBRARY_PATH - it may be necessary to inject `/.shadow/...` paths into the execution of binaries to avoid needing to present shared library dependencies in "visible" locations that don't exist on ESX.