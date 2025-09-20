# **SLSsteam - Steamclient Modification for Linux**
![](https://github.com/AceSLS/SLSsteam/blob/dev/res/banner.png?raw=true "SLSsteam")

## Index

1. [Downloading and Compiling](#downloading-and-compiling)
2. [Usage](#usage)
3. [Configuration](#configuration)
4. [Installation and Uninstallation](#installation-and-uninstallation)
5. [Updating](#updating)
6. [Hall of Fame 👑](#hall-of-fame-aka-credits)
7. [Hall of Shame 🚨](#hall-of-shame-aka-scammers-leechers-etc)

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

This is only for people not wanting to use an installer. If you do read Configuration, then Installation and Uninstallation
```bash
LD_AUDIT="/full/path/to/SLSsteam.so" steam
```

## Configuration

Configuration gets created at ~/.config/SLSsteam/config.yaml during first run

## Installation and Uninstallation

### Any distro:

```bash
./setup.sh install
./setup.sh uninstall
```
Afterwards start steam from your Desktop's kickstarter and SLSsteam should get loaded

### Arch Linux:

Download latest SLSsteam-Arch.pkg.tar.zst then run:
```bash
sudo pacman -U SLSsteam-Arch.pkg.tar.zst
```
Afterwards start SLSsteam from your Desktop's kickstarter

### NixOS:

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

## Hall of Fame aka Credits

Contributors:
- [amione](https://github.com/xamionex/): Creating the SLSsteam banner & logo the instant he found out I was looking around for one <3
- [DeveloperMikey](https://github.com/DeveloperMikey): Added Nix support 
- thismanq: Informing me that DisableFamilyShareLockForOthers is possible

Others:
- All the staff members of the Anti Denuvo Sanctuary for all their hard work they do. They also found a way to use SLSsteam I didn't even intend to, so shoutout to them
- Riku_Wayfinder: Being extremely supportive and lightening my workload by a lot. So show him some love my guys <3
- Gnanf: Helping me test the Family Sharing bypass
- rdbo: For his great libmem library, which saved me a lot of development and learning time
- jbeder: For the awesome yaml-cpp library which allowed me to easily add a configuration file
- oleavr and all the other awesome people working on Frida for easy instrumentation which helps a lot in analyzing, testing and debugging
- All the folks working on Ghidra, this was my first project using it and I'm in love with it!
- And many more I can't possibly list here for reporting bugs and giving feedback! Thank you guys <3


## Hall of Shame aka Scammers, Leechers, etc

🚨This list exists purely for educational and entertainmnent purposes!
Please do not seek out Projects listed here!
If you decide to ignore the aformened warning you do so on your own risk!🚨

OnetapBeta by Hammer Steam: Resells Steamless & SLSsteam. Intellectually went far enough to rename SLSsteam to deckloader2, that's about as far as their skill extends.
