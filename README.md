# 🏭 Copacetic Scanner Plugin for Harbor

This is a fork of the template repo for creating a harbor scanner plugin for [Copacetic](https://github.com/project-copacetic/copacetic).

Learn more about Copacetic's scanner plugins [here](https://project-copacetic.github.io/copacetic/scanner-plugins).

## Development

These instructions are for developing a new scanner plugin for [Copacetic](https://github.com/project-copacetic/copacetic) from this template.

- [x] Clone this repo
- [x] Rename the `scanner-plugin-template` repo to the name of your plugin
- [x] Update applicable types for [`harborReport`](types.go) to match your scanner's structure
- [x] Update [`parse`](main.go) to parse your scanner's report format accordingly
- [x] Update `CLI_BINARY` in the [`Makefile`](Makefile) to match your scanner's CLI binary name (resulting binary must be prefixed with `copa-`)
- [] Update this [`README.md`](README.md) to match your plugin's usage
- [ ] Test plugin outwith go test framework (e.g. with `copa patch` and a report file)

## Development Pre-requisites

> [!NOTE]
> You may have different pre-requisites for your scanner plugin, you are not required to use these tools.

The following tools are required to build and run this template:

- `git`: for cloning this repo
- `Go`: for building the plugin
- `make`: for the Makefile

## Example Development Workflow

This is an example development workflow for this template.

```shell
# clone this repo
git clone https://github.com/project-copacetic/scanner-plugin-harbor.git

# change directory to the repo
cd scanner-plugin-harbor

# build the copa-harbor binary
make

# add copa-harbor binary to PATH
export PATH=$PATH:dist/linux_amd64/release/

# test plugin with example config
copa-harbor testdata/harbor_report.json
# this will print the report in JSON format
# {"apiVersion":"v1alpha1","metadata":{"os":{"type":"harborOS","version":"42"},"config":{"arch":"amd64"}},"updates":[{"name":"foo","installedVersion":"1.0.0","fixedVersion":"1.0.1","vulnerabilityID":"VULN001"},{"name":"bar","installedVersion":"2.0.0","fixedVersion":"2.0.1","vulnerabilityID":"VULN002"}]}

# run copa with the scanner plugin (copa-harbor) and the report file
copa patch -i $IMAGE -r testdata/harbor_report.json --scanner harbor
# this is for illustration purposes only
# it will fail with "Error: unsupported osType harborOS specified"
```