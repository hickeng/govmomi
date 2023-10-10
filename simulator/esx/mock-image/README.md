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

I have used the following command to generate a file listing from ESX as a reference of what's expected:
```bash
(
    echo "["
    find . | xargs stat -c '{ "hstat": "%A", "stat": "%a", "owner": "%U", "group": "%G", "path": "%n" },' *| sed 's/\.[[:digit:]]\+[ ]\+-[[:digit:]]\+/ /'
    echo "]"
) > esx-file-list.json
```

## Mock image manifest

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


## Notes

* LD_LIBRARY_PATH - it may be necessary to inject `/.shadow/...` paths into the execution of binaries to avoid needing to present shared library dependencies in "visible" locations that don't exist on ESX.