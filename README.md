# Control FOV Tool — Source and Build Instructions

This source bundle contains the PowerShell user interface and FOV controller, the small C# Windows GUI launcher, and the application icon. It does not include a compiled executable.

## Build requirements

- Windows 10 or later
- Windows PowerShell 5.1 (64-bit)
- .NET Framework 4.x C# compiler, normally included with Windows

## Build

Open 64-bit Windows PowerShell 5.1 in this folder and run:

```powershell
.\Build-Control-FOV-Tool.ps1
```

The build script invokes the .NET Framework C# compiler, embeds `Control-FOV-Tool.ps1` into the launcher, applies `ControlFOV.ico`, and writes the executable to `dist\Control FOV Tool.exe`.

## What the program does

The utility locates Control's DX11 or DX12 process and applies the selected FOV multiplier while the game is running. It updates the camera behavior to keep the chosen value during gameplay. On game exit, it saves the selected multiplier to `renderer.ini`; before its first edit, it creates a backup named `renderer.ini.control-fov.bak`. The program does not include or require Cheat Engine.

Default hotkeys are Page Up (increase), Page Down (decrease), F2 (enable), and F3 (disable and restore 1.00). Hotkeys are registered only while the Control window is focused. Settings and hotkey assignments are saved automatically.

## Source files

- `Control-FOV-Tool.ps1` — interface, localization, hotkeys, and FOV control logic
- `ControlFOVLauncher.cs` — Windows GUI entry point that embeds and runs the PowerShell script
- `ControlFOV.ico` — application icon
- `Build-Control-FOV-Tool.ps1` — reproducible local build script
