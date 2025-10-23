# @strongdm/leash

The official npm distribution of the `leash` CLI. This package ships prebuilt binaries for macOS and Linux across amd64 and arm64 hardware targets and provides a lightweight Node-based launcher that mirrors the behaviour of the standalone binary release.

## Installation

```bash
npm install -g @strongdm/leash
# or
npx @strongdm/leash --version
```

## Usage

Once installed, invoke the CLI exactly as you would the native binary:

```bash
leash --help
leash ssh my-server
```

The launcher resolves the bundled binary for your current `process.platform` and `process.arch` combination, forwards standard input/output, and exits with the wrapped process status code.

## Supported Platforms

- macOS on Apple silicon (`darwin`, `arm64`)
- macOS on Intel (`darwin`, `x64`)
- Linux on Intel (`linux`, `x64`)
- Linux on ARM (`linux`, `arm64`)

> **Note:** Windows users can download and run the Linux binary through WSL.

## Repository

Source code and issue tracking live in [strongdm/leash](https://github.com/strongdm/leash). Contributions should target that repository; this npm package is generated automatically by the release pipeline.

## License

Distributed under the [Apache 2.0 License](../../LICENSE).
