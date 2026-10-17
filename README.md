# Control FOV Tool — Source and Build Instructions

This public source repository contains the PowerShell user interface and FOV controller, the C# Windows GUI launcher, the application icon, and a local build script. It does not include a compiled executable.

## Build requirements

- Windows 10 or later
- Windows PowerShell 5.1 (64-bit)
- .NET Framework 4.x C# compiler, normally included with Windows

## Build

Open 64-bit Windows PowerShell 5.1 in this folder and run:

```powershell
.\Build-Control-FOV-Tool.ps1
```

The build script compiles the launcher, embeds `Control-FOV-Tool.ps1`, applies `ControlFOV.ico`, and writes the executable to `dist\Control FOV Tool.exe`.

## Game path detection

The utility detects the running `Control_DX11` or `Control_DX12` process and reads its executable path to locate the game folder. It does not assume a Steam drive or require the user to enter an install path. The detected folder is saved in the utility's local settings so the selected multiplier can be written to that installation's `renderer.ini` when the game closes.

## What the program does

The utility applies the selected FOV multiplier while Control is running and reapplies it during camera updates. Before its first edit to `renderer.ini`, it creates a backup named `renderer.ini.control-fov.bak`. The program does not include or require Cheat Engine.

Default hotkeys: Page Up (increase), Page Down (decrease), F2 (enable), and F3 (disable and restore 1.00). Hotkeys are registered only while the Control window is focused. Settings and hotkey assignments save automatically.

## Source files

- `Control-FOV-Tool.ps1` — interface, localization, hotkeys, and FOV control logic
- `ControlFOVLauncher.cs` — Windows GUI entry point that embeds and runs the PowerShell script
- `ControlFOV.ico` — application icon
- `Build-Control-FOV-Tool.ps1` — local build script
