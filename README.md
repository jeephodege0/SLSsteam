# **SLSsteam - Steamclient Modification for Linux**

## Index

1. [Downloading and Compiling](#downloading-and-compiling)
2. [Usage](#usage)
3. [Configuration](#configuration)
4. [Installation and Uninstallation](#installation-and-uninstallation)
5. [Updating](#updating)
6. [Credits](#credits)

## Downloading and Compiling

If you're on a pretty up to date distro you can go to
[Releases](https://github.com/AceSLS/SLSsteam/releases) instead.
Afterwards skip straight to [Usage](#usage) or [Installation and Uninstallation](#installation-and-uninstallation)

Requires: 32 bit versions of g++, OpenSSL & pkg-config

Then run:

```bash
git clone "https://github.com/AceSLS/SLSsteam"
cd SLSsteam
make
```

## Usage

```bash
LD_AUDIT="/full/path/to/SLSsteam.so" steam
```

## Configuration

Configuration gets created at ~/.config/SLSsteam/config.yaml during first run

## Installation and Uninstallation

```bash
./setup.sh install
./setup.sh uninstall
```

## NixOS

Add this to your flake inputs

```nix
sls-steam = {
  url = "github:AceSLS/SLSsteam";
  inputs.nixpkgs.follows = "nixpkgs";
};
```

Then, add it to your packages and run it with `SLSsteam` from the terminal

```nix
environment.systemPackages = [inputs.sls-steam.packages.${pkgs.system}.wrapped];
```

Alternatively, to have it run with steam on any launch,
add it to your steam environment variables

```nix
programs.steam.package = pkgs.steam.override {
  extraEnv = {
    LD_AUDIT = "${inputs.sls-steam.packages.${pkgs.system}.sls-steam}/SLSsteam.so";
  };
};
```

<details>
<summary>Configuration on NixOS</summary>

You can configure SLSsteam declaratively using the home-manager module

Add the module to your imports

```nix
imports = [inputs.sls-steam.homeModules.sls-steam];
```

Then configure it through `services.sls-steam.config`. For example:

```nix
services.sls-steam.config = {
  PlayNotOwnedGames = true;
  AdditionalApps = [
    3769130
  ];
};
```

You can find further details in the [definition file](nix-modules/home.nix)

</details>

## Updating

```bash
git pull
make rebuild
```

Afterwards run the installer again if that's what you've been using to launch SLSsteam

## Credits

- Special thanks to all the staff members of the Anti Denuvo Sanctuary
  for all the hard work they do. They also found a way to use SLSsteam
  I didn't even intend to, so shoutout to them
- [DeveloperMikey](https://github.com/DeveloperMikey): Added Nix support 
- Riku_Wayfinder: Being extremely supportive and lightening my workload by a lot.
  So show him some love my guys <3
- thismanq: Informing me that DisableFamilyShareLockForOthers is possible
- Gnanf: Helping me test the Family Sharing bypass
- rdbo: For his great libmem library, which saved me a
  lot of development and learning time
- oleavr and all the other awesome people working on Frida
  for easy instrumentation which helps a lot in analyzing, testing and debugging
- All the folks working on Ghidra,
  this was my first project using it and I'm in love with it!

