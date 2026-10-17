# Control FOV Tool — compact bilingual WPF utility
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Xaml
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class ControlFovHotkeys {
  [DllImport("user32.dll", SetLastError=true)] public static extern bool RegisterHotKey(IntPtr hWnd, int id, uint modifiers, uint vk);
  [DllImport("user32.dll", SetLastError=true)] public static extern bool UnregisterHotKey(IntPtr hWnd, int id);
  [DllImport("user32.dll")] public static extern short GetAsyncKeyState(int virtualKey);
  [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);
  public static int GetForegroundProcessId() {
    uint processId; GetWindowThreadProcessId(GetForegroundWindow(), out processId); return (int)processId;
  }
}
public static class ControlFovMemory {
  const uint PROCESS_ACCESS = 0x0438;
  const uint MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000, MEM_RELEASE = 0x8000;
  const uint PAGE_EXECUTE_READWRITE = 0x40, PAGE_GUARD = 0x100, PAGE_NOACCESS = 0x01;
  [StructLayout(LayoutKind.Sequential)] struct MEMORY_BASIC_INFORMATION {
    public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect; public ushort PartitionId;
    public UIntPtr RegionSize; public uint State; public uint Protect; public uint Type;
  }
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] buffer, UIntPtr size, out UIntPtr read);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool WriteProcessMemory(IntPtr process, IntPtr address, byte[] buffer, UIntPtr size, out UIntPtr written);
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr VirtualAllocEx(IntPtr process, IntPtr address, UIntPtr size, uint allocationType, uint protect);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool VirtualFreeEx(IntPtr process, IntPtr address, UIntPtr size, uint freeType);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool VirtualProtectEx(IntPtr process, IntPtr address, UIntPtr size, uint protect, out uint oldProtect);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool FlushInstructionCache(IntPtr process, IntPtr address, UIntPtr size);
  [DllImport("kernel32.dll", SetLastError=true)] static extern UIntPtr VirtualQueryEx(IntPtr process, IntPtr address, out MEMORY_BASIC_INFORMATION info, UIntPtr length);

  public static IntPtr Open(int pid) { return OpenProcess(PROCESS_ACCESS, false, pid); }
  public static void Close(IntPtr process) { if (process != IntPtr.Zero) CloseHandle(process); }
  static bool Read(IntPtr process, long address, byte[] buffer) {
    UIntPtr read; return ReadProcessMemory(process, new IntPtr(address), buffer, new UIntPtr((uint)buffer.Length), out read) && read.ToUInt64() == (ulong)buffer.Length;
  }
  static bool Write(IntPtr process, long address, byte[] buffer) {
    UIntPtr written; return WriteProcessMemory(process, new IntPtr(address), buffer, new UIntPtr((uint)buffer.Length), out written) && written.ToUInt64() == (ulong)buffer.Length;
  }
  public static long FindUniquePattern(IntPtr process, long start, int length, byte[] pattern) {
    long end = start + length, cursor = start, found = 0; int matches = 0;
    while (cursor < end) {
      MEMORY_BASIC_INFORMATION info;
      if (VirtualQueryEx(process, new IntPtr(cursor), out info, new UIntPtr((uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)))).ToUInt64() == 0) break;
      long regionStart = Math.Max(cursor, info.BaseAddress.ToInt64());
      long regionEnd = Math.Min(end, info.BaseAddress.ToInt64() + (long)info.RegionSize.ToUInt64());
      if (regionEnd <= cursor) break;
      if (info.State == MEM_COMMIT && (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0) {
        long position = regionStart; byte[] carry = new byte[0];
        while (position < regionEnd) {
          int count = (int)Math.Min(1024 * 1024, regionEnd - position); byte[] chunk = new byte[count];
          if (Read(process, position, chunk)) {
            byte[] scan = new byte[carry.Length + chunk.Length]; Buffer.BlockCopy(carry, 0, scan, 0, carry.Length); Buffer.BlockCopy(chunk, 0, scan, carry.Length, chunk.Length);
            for (int i = 0; i <= scan.Length - pattern.Length; i++) {
              bool equal = true; for (int j = 0; j < pattern.Length; j++) if (scan[i + j] != pattern[j]) { equal = false; break; }
              if (equal) { found = position - carry.Length + i; if (++matches > 1) return 0; }
            }
            int keep = Math.Min(pattern.Length - 1, scan.Length); carry = new byte[keep]; if (keep > 0) Buffer.BlockCopy(scan, scan.Length - keep, carry, 0, keep);
          } else carry = new byte[0];
          position += count;
        }
      }
      cursor = regionEnd;
    }
    return matches == 1 ? found : 0;
  }
  static IntPtr AllocateNear(IntPtr process, long target) {
    const long granularity = 0x10000, maxDistance = 0x7FFF0000;
    long aligned = target & ~(granularity - 1);
    for (long delta = 0; delta < maxDistance; delta += granularity) {
      long low = aligned - delta;
      if (low > 0) { IntPtr result = VirtualAllocEx(process, new IntPtr(low), new UIntPtr(0x1000u), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); if (result != IntPtr.Zero) return result; }
      long high = aligned + delta;
      IntPtr upper = VirtualAllocEx(process, new IntPtr(high), new UIntPtr(0x1000u), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); if (upper != IntPtr.Zero) return upper;
    }
    return IntPtr.Zero;
  }
  static byte[] RelativeJump(byte opcode, long from, long to) {
    long displacement = to - (from + 5); if (displacement < Int32.MinValue || displacement > Int32.MaxValue) throw new InvalidOperationException("The camera hook is outside the supported address range.");
    byte[] result = new byte[5]; result[0] = opcode; Buffer.BlockCopy(BitConverter.GetBytes((int)displacement), 0, result, 1, 4); return result;
  }
  public static long InstallHook(IntPtr process, long target, float initialFov) {
    byte[] original = new byte[] { 0xF3, 0x0F, 0x59, 0x43, 0x10 }, current = new byte[5];
    if (!Read(process, target, current) || !Equal(current, original)) throw new InvalidOperationException("The Control camera code does not match this supported build.");
    IntPtr allocation = AllocateNear(process, target); if (allocation == IntPtr.Zero) throw new InvalidOperationException("Could not allocate the small camera bridge near Control.");
    long code = allocation.ToInt64(), slot = code + 32, desiredFov = code + 40;
    byte[] bridge = new byte[48];
    bridge[0]=0x48; bridge[1]=0x89; bridge[2]=0x1D; Buffer.BlockCopy(BitConverter.GetBytes((int)(slot-(code+7))),0,bridge,3,4);
    bridge[7]=0x50; bridge[8]=0x8B; bridge[9]=0x05; Buffer.BlockCopy(BitConverter.GetBytes((int)(desiredFov-(code+14))),0,bridge,10,4);
    bridge[14]=0x89; bridge[15]=0x43; bridge[16]=0x10; bridge[17]=0x58;
    Buffer.BlockCopy(original,0,bridge,18,5); bridge[23]=0xE9; Buffer.BlockCopy(BitConverter.GetBytes((int)(target+5-(code+28))),0,bridge,24,4);
    Buffer.BlockCopy(BitConverter.GetBytes(initialFov),0,bridge,40,4);
    if (!Write(process, code, bridge)) { VirtualFreeEx(process, allocation, UIntPtr.Zero, MEM_RELEASE); throw new InvalidOperationException("Could not write the camera bridge."); }
    FlushInstructionCache(process, allocation, new UIntPtr((uint)bridge.Length));
    uint old; if (!VirtualProtectEx(process, new IntPtr(target), new UIntPtr(5u), PAGE_EXECUTE_READWRITE, out old)) { VirtualFreeEx(process, allocation, UIntPtr.Zero, MEM_RELEASE); throw new InvalidOperationException("Could not prepare the camera instruction for patching."); }
    bool patched = Write(process, target, RelativeJump(0xE9, target, code));
    if (!patched) Write(process, target, original);
    VirtualProtectEx(process, new IntPtr(target), new UIntPtr(5u), old, out old); FlushInstructionCache(process, new IntPtr(target), new UIntPtr(5u));
    if (!patched) { VirtualFreeEx(process, allocation, UIntPtr.Zero, MEM_RELEASE); throw new InvalidOperationException("Could not activate the camera bridge."); }
    return allocation.ToInt64();
  }
  public static bool RestoreHook(IntPtr process, long target, long allocation) {
    if (process == IntPtr.Zero || target == 0 || allocation == 0) return true;
    byte[] original = new byte[] { 0xF3, 0x0F, 0x59, 0x43, 0x10 }; uint old;
    if (!VirtualProtectEx(process, new IntPtr(target), new UIntPtr(5u), PAGE_EXECUTE_READWRITE, out old)) return false;
    bool restored = Write(process, target, original); VirtualProtectEx(process, new IntPtr(target), new UIntPtr(5u), old, out old); FlushInstructionCache(process, new IntPtr(target), new UIntPtr(5u));
    if (restored) VirtualFreeEx(process, new IntPtr(allocation), UIntPtr.Zero, MEM_RELEASE);
    return restored;
  }
  public static long ReadPointer(IntPtr process, long address) { byte[] bytes = new byte[8]; return Read(process,address,bytes) ? BitConverter.ToInt64(bytes,0) : 0; }
  public static bool WriteFloat(IntPtr process, long address, float value) { return Write(process,address,BitConverter.GetBytes(value)); }
  static bool Equal(byte[] left, byte[] right) { if (left.Length != right.Length) return false; for(int i=0;i<left.Length;i++) if(left[i]!=right[i]) return false; return true; }
}
'@

$script:prefsPath = Join-Path $env:LOCALAPPDATA 'ControlFOVTool\settings.json'
$script:prefsDir = Split-Path $script:prefsPath
if (!(Test-Path $script:prefsDir)) { New-Item -ItemType Directory -Path $script:prefsDir -Force | Out-Null }
$script:prefs = if (Test-Path $script:prefsPath) { try { Get-Content $script:prefsPath -Raw | ConvertFrom-Json } catch { $null } } else { $null }
$script:gameDir = [string]$script:prefs.GameDir
if ($script:gameDir -and (Test-Path -LiteralPath $script:gameDir -PathType Container)) {
    $script:iniPath = Join-Path $script:gameDir 'renderer.ini'
} else {
    $script:gameDir = ''
    $script:iniPath = ''
}
$script:gamePathPid = 0
$script:languageOptions = [ordered]@{
    en='English'; ar='العربية'; es='Español'; tr='Türkçe'; 'zh-CN'='简体中文'; fr='Français'; de='Deutsch'; pt='Português'; ja='日本語'; ko='한국어'; ru='Русский'; hi='हिन्दी'
}
$script:systemLanguageMap = @{ en='en'; ar='ar'; es='es'; tr='tr'; zh='zh-CN'; fr='fr'; de='de'; pt='pt'; ja='ja'; ko='ko'; ru='ru'; hi='hi' }
$savedLanguage = [string]$script:prefs.Language
$systemLanguage = [Globalization.CultureInfo]::CurrentUICulture.TwoLetterISOLanguageName
$script:language = if ($script:languageOptions.Contains($savedLanguage)) { $savedLanguage } elseif ($script:systemLanguageMap.ContainsKey($systemLanguage)) { $script:systemLanguageMap[$systemLanguage] } else { 'en' }
$script:darkMode = if ($null -ne $script:prefs.DarkMode) { [bool]$script:prefs.DarkMode } else { $true }
$script:enabled = if ($null -ne $script:prefs.Enabled) { [bool]$script:prefs.Enabled } else { $null }
$script:step = if ($script:prefs.Step -in @(0.01,0.02,0.05,0.1,0.2)) { [double]$script:prefs.Step } else { 0.05 }
$script:hotkeys = [ordered]@{
    Up      = if ($script:prefs.Up)      { [string]$script:prefs.Up }      else { 'PageUp' }
    Down    = if ($script:prefs.Down)    { [string]$script:prefs.Down }    else { 'PageDown' }
    Enable  = if ($script:prefs.Enable)  { [string]$script:prefs.Enable }  else { 'F2' }
    Disable = if ($script:prefs.Disable) { [string]$script:prefs.Disable } else { 'F3' }
}
$script:fov = if ($script:prefs.Fov -and [double]$script:prefs.Fov -ge 0.50 -and [double]$script:prefs.Fov -le 2.00) { [double]$script:prefs.Fov } else { 1.0 }
if ($script:iniPath -and (Test-Path -LiteralPath $script:iniPath)) {
    $match = [regex]::Match([IO.File]::ReadAllText($script:iniPath), '"m_fFOVMultiplier"\s*:\s*([0-9]+(?:\.[0-9]+)?)')
    if ($match.Success -and !$script:prefs.Fov) { $script:fov = [double]::Parse($match.Groups[1].Value,[cultureinfo]::InvariantCulture) }
}
if ($null -eq $script:enabled) { $script:enabled = ($script:fov -ne 1.0) }
$script:lastEnabledFov = if ($script:prefs.LastEnabledFov -and [double]$script:prefs.LastEnabledFov -ge 0.50 -and [double]$script:prefs.LastEnabledFov -le 2.00) { [double]$script:prefs.LastEnabledFov } elseif ($script:fov -ne 1.0) { $script:fov } else { 1.10 }
$script:hotkeyHandle = [IntPtr]::Zero
$script:hotkeySource = $null
$script:hotkeyHook = $null
$script:registeredIds = @()
$script:hotkeysActive = $false
$script:hotkeyFocusTimer = $null
$script:captureTarget = $null
$script:captureName = ''
$script:captureTimer = $null
$script:pressedVirtualKeys = @{}
$script:livePid = 0
$script:controlPid = 0
$script:liveHandle = [IntPtr]::Zero
$script:liveHookAddress = 0L
$script:liveBridgeAddress = 0L
$script:liveFieldAddress = 0L
$script:liveLastWrittenAddress = 0L
$script:liveFailedPid = 0

$script:text = @{
    en = @{
        title='CONTROL FOV'; subtitle='FIELD OF VIEW'; current='FOV MULTIPLIER'; step='Step'; enabled='FOV adjustments enabled'; disabled='FOV adjustments disabled'; enable='Enable FOV'; disable='Disable FOV';
        shortcuts='HOTKEYS'; key='HOTKEY'; action='ACTION'; increase='Increase FOV'; decrease='Decrease FOV'; enableAction='Enable FOV'; disableAction='Disable FOV';
        save='Save settings'; restart='FOV changes apply live while Control is running.'; saved='FOV setting saved for the next launch.'; gameRunning='Control detected. Waiting for its camera to initialize.'; live='Live FOV applied to Control.'; notRunning='Start Control to apply FOV live.'; memoryError='Could not connect to this Control build.';
        missing='Could not find renderer.ini in the configured game folder.'; invalid='Could not update the FOV setting in renderer.ini.'; conflict='A hotkey is already in use or duplicated. Choose different keys.';
        language='العربية'; theme='Light mode'; about='About'; close='Close'; minimize='Minimize'; aboutCreator='Created by Khalid Alsahari'; aboutWebsite='Website'; aboutInstagram='Instagram';
        hint='Hotkeys activate only while Control is focused.'; range='Allowed multiplier: 0.50 – 2.00';
    }
    ar = @{
        title='مجال الرؤية CONTROL'; subtitle='مجال الرؤية'; current='قيمة مجال الرؤية'; step='مقدار التغيير'; enabled='تعديل مجال الرؤية مفعّل'; disabled='تعديل مجال الرؤية معطّل'; enable='تفعيل المجال'; disable='تعطيل المجال';
        shortcuts='الاختصارات'; key='الاختصار'; action='الإجراء'; increase='زيادة مجال الرؤية'; decrease='إنقاص مجال الرؤية'; enableAction='تفعيل مجال الرؤية'; disableAction='تعطيل مجال الرؤية';
        save='حفظ الإعدادات'; restart='يُطبّق مجال الرؤية مباشرة أثناء تشغيل Control.'; saved='تم حفظ المجال للتشغيل القادم.'; gameRunning='تم رصد Control. بانتظار تهيئة الكاميرا.'; live='تم تطبيق مجال الرؤية مباشرة.'; notRunning='شغّل Control لتطبيق المجال مباشرة.'; memoryError='تعذر الاتصال بهذا الإصدار من Control.';
        missing='لم يتم العثور على renderer.ini في مجلد اللعبة المحدد.'; invalid='تعذر تحديث إعداد مجال الرؤية في renderer.ini.'; conflict='الاختصار مستخدم أو مكرر. اختر اختصارات أخرى.';
        language='English'; theme='الوضع الفاتح'; about='حول'; close='إغلاق'; minimize='تصغير'; aboutCreator='إعداد Khalid Alsahari'; aboutWebsite='الموقع'; aboutInstagram='إنستغرام';
        hint='تعمل الاختصارات عندما تكون نافذة Control نشطة فقط.'; range='النطاق المسموح: 0.50 – 2.00';
    }
    es = @{
        title='CONTROL FOV'; subtitle='CAMPO DE VISIÓN'; current='MULTIPLICADOR DE FOV'; step='Incremento'; enabled='Ajustes de FOV activados'; disabled='Ajustes de FOV desactivados'; enable='Activar FOV'; disable='Desactivar FOV';
        shortcuts='ATAJOS'; key='TECLA'; action='ACCIÓN'; increase='Aumentar FOV'; decrease='Reducir FOV'; enableAction='Activar FOV'; disableAction='Desactivar FOV';
        save='Guardar ajustes'; restart='Los cambios se aplican mientras Control está en ejecución.'; saved='Ajuste guardado para el próximo inicio.'; gameRunning='Control detectado. Esperando a que se inicialice la cámara.'; live='FOV aplicado en directo a Control.'; notRunning='Inicia Control para aplicar el FOV en directo.'; memoryError='No se pudo conectar con esta versión de Control.';
        missing='No se encontró renderer.ini en la carpeta del juego configurada.'; invalid='No se pudo actualizar el FOV en renderer.ini.'; conflict='La tecla ya está en uso o duplicada. Elige otra.';
        language='Idioma'; theme='Modo claro'; about='Acerca de'; close='Cerrar'; minimize='Minimizar'; aboutCreator='Creado por Khalid Alsahari'; aboutWebsite='Sitio web'; aboutInstagram='Instagram';
        hint='Los atajos solo se activan cuando Control está en primer plano.'; range='Rango permitido: 0.50 – 2.00';
    }
    tr = @{
        title='CONTROL FOV'; subtitle='GÖRÜŞ ALANI'; current='GÖRÜŞ ALANI ÇARPANI'; step='Artış'; enabled='Görüş alanı ayarı açık'; disabled='Görüş alanı ayarı kapalı'; enable='Görüş alanını aç'; disable='Görüş alanını kapat';
        shortcuts='KISAYOLLAR'; key='TUŞ'; action='İŞLEM'; increase='Görüş alanını artır'; decrease='Görüş alanını azalt'; enableAction='Görüş alanını aç'; disableAction='Görüş alanını kapat';
        save='Ayarları kaydet'; restart='Control çalışırken görüş alanı değişiklikleri anında uygulanır.'; saved='Görüş alanı ayarı sonraki açılış için kaydedildi.'; gameRunning='Control algılandı. Kamera başlatılıyor.'; live='Görüş alanı Control oyununa anında uygulandı.'; notRunning='Görüş alanını anında uygulamak için Control oyununu başlat.'; memoryError='Bu Control sürümüne bağlanılamadı.';
        missing='Seçilen oyun klasöründe renderer.ini bulunamadı.'; invalid='renderer.ini içindeki görüş alanı ayarı güncellenemedi.'; conflict='Kısayol kullanımda veya yinelenmiş. Başka bir tuş seç.';
        language='Dil'; theme='Açık tema'; about='Hakkında'; close='Kapat'; minimize='Küçült'; aboutCreator='Hazırlayan: Khalid Alsahari'; aboutWebsite='Web sitesi'; aboutInstagram='Instagram';
        hint='Kısayollar yalnızca Control ön plandayken etkinleşir.'; range='İzin verilen aralık: 0.50 – 2.00';
    }
    'zh-CN' = @{
        title='CONTROL 视野'; subtitle='视野调节'; current='视野倍率'; step='调整步长'; enabled='视野调整已启用'; disabled='视野调整已停用'; enable='启用视野调整'; disable='停用视野调整';
        shortcuts='快捷键'; key='按键'; action='操作'; increase='增加视野'; decrease='减少视野'; enableAction='启用视野'; disableAction='停用视野';
        save='保存设置'; restart='Control 运行时会实时应用视野变化。'; saved='视野设置已保存，将在下次启动时使用。'; gameRunning='已检测到 Control，正在等待相机初始化。'; live='视野已实时应用到 Control。'; notRunning='启动 Control 以实时应用视野。'; memoryError='无法连接到此版本的 Control。';
        missing='在指定的游戏文件夹中找不到 renderer.ini。'; invalid='无法更新 renderer.ini 中的视野设置。'; conflict='快捷键已被占用或重复，请选择其他按键。';
        language='语言'; theme='浅色模式'; about='关于'; close='关闭'; minimize='最小化'; aboutCreator='作者：Khalid Alsahari'; aboutWebsite='网站'; aboutInstagram='Instagram';
        hint='仅当 Control 窗口处于前台时快捷键才生效。'; range='允许范围：0.50 – 2.00';
    }
    fr = @{
        title='CONTROL FOV'; subtitle='CHAMP DE VISION'; current='MULTIPLICATEUR FOV'; step='Pas'; enabled='Réglage du champ de vision activé'; disabled='Réglage du champ de vision désactivé'; enable='Activer le FOV'; disable='Désactiver le FOV';
        shortcuts='RACCOURCIS'; key='TOUCHE'; action='ACTION'; increase='Augmenter le FOV'; decrease='Réduire le FOV'; enableAction='Activer le FOV'; disableAction='Désactiver le FOV';
        save='Enregistrer les paramètres'; restart='Les changements sont appliqués en direct pendant que Control est lancé.'; saved='Réglage enregistré pour le prochain lancement.'; gameRunning='Control détecté. Initialisation de la caméra en attente.'; live='FOV appliqué en direct à Control.'; notRunning='Lancez Control pour appliquer le FOV en direct.'; memoryError='Impossible de se connecter à cette version de Control.';
        missing='renderer.ini introuvable dans le dossier du jeu choisi.'; invalid='Impossible de modifier le FOV dans renderer.ini.'; conflict='Raccourci déjà utilisé ou en double. Choisissez une autre touche.';
        language='Langue'; theme='Mode clair'; about='À propos'; close='Fermer'; minimize='Réduire'; aboutCreator='Créé par Khalid Alsahari'; aboutWebsite='Site web'; aboutInstagram='Instagram';
        hint='Les raccourcis fonctionnent uniquement lorsque Control est au premier plan.'; range='Plage autorisée : 0.50 – 2.00';
    }
    de = @{
        title='CONTROL FOV'; subtitle='SICHTFELD'; current='SICHTFELDFAKTOR'; step='Schritt'; enabled='Sichtfeldanpassung aktiviert'; disabled='Sichtfeldanpassung deaktiviert'; enable='Sichtfeld aktivieren'; disable='Sichtfeld deaktivieren';
        shortcuts='TASTENKÜRZEL'; key='TASTE'; action='AKTION'; increase='Sichtfeld erhöhen'; decrease='Sichtfeld verringern'; enableAction='Sichtfeld aktivieren'; disableAction='Sichtfeld deaktivieren';
        save='Einstellungen speichern'; restart='Änderungen werden während Control läuft sofort angewendet.'; saved='Sichtfeld für den nächsten Start gespeichert.'; gameRunning='Control erkannt. Kamera wird initialisiert.'; live='Sichtfeld live auf Control angewendet.'; notRunning='Starte Control, um das Sichtfeld live anzuwenden.'; memoryError='Verbindung mit dieser Control-Version fehlgeschlagen.';
        missing='renderer.ini wurde im ausgewählten Spielordner nicht gefunden.'; invalid='Sichtfeld in renderer.ini konnte nicht geändert werden.'; conflict='Taste ist bereits belegt oder doppelt. Bitte andere Taste wählen.';
        language='Sprache'; theme='Heller Modus'; about='Info'; close='Schließen'; minimize='Minimieren'; aboutCreator='Erstellt von Khalid Alsahari'; aboutWebsite='Webseite'; aboutInstagram='Instagram';
        hint='Tastenkürzel sind nur aktiv, wenn Control im Vordergrund ist.'; range='Zulässiger Bereich: 0.50 – 2.00';
    }
    pt = @{
        title='CONTROL FOV'; subtitle='CAMPO DE VISÃO'; current='MULTIPLICADOR DE FOV'; step='Incremento'; enabled='Ajuste de FOV ativado'; disabled='Ajuste de FOV desativado'; enable='Ativar FOV'; disable='Desativar FOV';
        shortcuts='ATALHOS'; key='TECLA'; action='AÇÃO'; increase='Aumentar FOV'; decrease='Diminuir FOV'; enableAction='Ativar FOV'; disableAction='Desativar FOV';
        save='Guardar definições'; restart='As alterações são aplicadas enquanto Control está em execução.'; saved='Definição guardada para a próxima inicialização.'; gameRunning='Control detetado. A aguardar a inicialização da câmara.'; live='FOV aplicado em direto ao Control.'; notRunning='Inicie o Control para aplicar o FOV em direto.'; memoryError='Não foi possível ligar a esta versão do Control.';
        missing='renderer.ini não foi encontrado na pasta de jogo selecionada.'; invalid='Não foi possível atualizar o FOV em renderer.ini.'; conflict='A tecla já está em uso ou repetida. Escolha outra.';
        language='Idioma'; theme='Modo claro'; about='Sobre'; close='Fechar'; minimize='Minimizar'; aboutCreator='Criado por Khalid Alsahari'; aboutWebsite='Site'; aboutInstagram='Instagram';
        hint='Os atalhos só são ativados quando Control está em primeiro plano.'; range='Intervalo permitido: 0.50 – 2.00';
    }
    ja = @{
        title='CONTROL FOV'; subtitle='視野角'; current='視野倍率'; step='変更幅'; enabled='視野調整が有効です'; disabled='視野調整が無効です'; enable='視野調整を有効化'; disable='視野調整を無効化';
        shortcuts='ショートカット'; key='キー'; action='操作'; increase='視野を広げる'; decrease='視野を狭める'; enableAction='視野調整を有効化'; disableAction='視野調整を無効化';
        save='設定を保存'; restart='Control の実行中に視野の変更が反映されます。'; saved='次回起動用の視野設定を保存しました。'; gameRunning='Control を検出しました。カメラの初期化を待っています。'; live='視野を Control に適用しました。'; notRunning='視野を適用するには Control を起動してください。'; memoryError='このバージョンの Control に接続できませんでした。';
        missing='指定したゲームフォルダーに renderer.ini が見つかりません。'; invalid='renderer.ini の視野設定を更新できませんでした。'; conflict='キーが使用中か重複しています。別のキーを選んでください。';
        language='言語'; theme='ライトモード'; about='このツールについて'; close='閉じる'; minimize='最小化'; aboutCreator='作成者：Khalid Alsahari'; aboutWebsite='ウェブサイト'; aboutInstagram='Instagram';
        hint='Controlが前面にあるときだけショートカットが有効になります。'; range='設定可能範囲：0.50 – 2.00';
    }
    ko = @{
        title='CONTROL FOV'; subtitle='시야각'; current='시야 배율'; step='변경 폭'; enabled='시야 조정 켜짐'; disabled='시야 조정 꺼짐'; enable='시야 조정 켜기'; disable='시야 조정 끄기';
        shortcuts='단축키'; key='키'; action='동작'; increase='시야 넓히기'; decrease='시야 좁히기'; enableAction='시야 조정 켜기'; disableAction='시야 조정 끄기';
        save='설정 저장'; restart='Control 실행 중에 시야 변경이 실시간 적용됩니다.'; saved='다음 실행을 위한 시야 설정을 저장했습니다.'; gameRunning='Control을 감지했습니다. 카메라 초기화를 기다리는 중입니다.'; live='Control에 시야를 실시간 적용했습니다.'; notRunning='시야를 적용하려면 Control을 실행하세요.'; memoryError='이 Control 버전에 연결할 수 없습니다.';
        missing='지정한 게임 폴더에서 renderer.ini를 찾을 수 없습니다.'; invalid='renderer.ini의 시야 설정을 업데이트할 수 없습니다.'; conflict='키가 이미 사용 중이거나 중복되었습니다. 다른 키를 선택하세요.';
        language='언어'; theme='라이트 모드'; about='정보'; close='닫기'; minimize='최소화'; aboutCreator='제작: Khalid Alsahari'; aboutWebsite='웹사이트'; aboutInstagram='Instagram';
        hint='Control 창이 활성화된 경우에만 단축키가 작동합니다.'; range='허용 범위: 0.50 – 2.00';
    }
    ru = @{
        title='CONTROL FOV'; subtitle='УГОЛ ОБЗОРА'; current='МНОЖИТЕЛЬ FOV'; step='Шаг'; enabled='Настройка угла обзора включена'; disabled='Настройка угла обзора выключена'; enable='Включить FOV'; disable='Выключить FOV';
        shortcuts='ГОРЯЧИЕ КЛАВИШИ'; key='КЛАВИША'; action='ДЕЙСТВИЕ'; increase='Увеличить FOV'; decrease='Уменьшить FOV'; enableAction='Включить FOV'; disableAction='Выключить FOV';
        save='Сохранить настройки'; restart='Изменения применяются сразу во время работы Control.'; saved='Настройка FOV сохранена для следующего запуска.'; gameRunning='Control обнаружена. Ожидание запуска камеры.'; live='FOV применён к Control в реальном времени.'; notRunning='Запустите Control для применения FOV.'; memoryError='Не удалось подключиться к этой версии Control.';
        missing='В выбранной папке игры не найден файл renderer.ini.'; invalid='Не удалось изменить настройку FOV в renderer.ini.'; conflict='Клавиша уже используется или повторяется. Выберите другую.';
        language='Язык'; theme='Светлая тема'; about='О программе'; close='Закрыть'; minimize='Свернуть'; aboutCreator='Автор: Khalid Alsahari'; aboutWebsite='Сайт'; aboutInstagram='Instagram';
        hint='Горячие клавиши работают, только когда окно Control активно.'; range='Допустимый диапазон: 0.50 – 2.00';
    }
    hi = @{
        title='CONTROL FOV'; subtitle='दृश्य क्षेत्र'; current='FOV गुणक'; step='बदलाव'; enabled='FOV समायोजन चालू'; disabled='FOV समायोजन बंद'; enable='FOV चालू करें'; disable='FOV बंद करें';
        shortcuts='शॉर्टकट'; key='कुंजी'; action='क्रिया'; increase='FOV बढ़ाएँ'; decrease='FOV घटाएँ'; enableAction='FOV चालू करें'; disableAction='FOV बंद करें';
        save='सेटिंग सहेजें'; restart='Control चलने पर बदलाव तुरंत लागू होते हैं।'; saved='अगली बार के लिए FOV सेटिंग सहेजी गई।'; gameRunning='Control मिल गया। कैमरा शुरू होने की प्रतीक्षा है।'; live='FOV Control पर तुरंत लागू हुआ।'; notRunning='FOV लागू करने के लिए Control शुरू करें।'; memoryError='इस Control संस्करण से कनेक्ट नहीं हो सका।';
        missing='चुने गए गेम फ़ोल्डर में renderer.ini नहीं मिला।'; invalid='renderer.ini में FOV सेटिंग अपडेट नहीं हो सकी।'; conflict='कुंजी पहले से उपयोग में है या दोहराई गई है। दूसरी कुंजी चुनें।';
        language='भाषा'; theme='लाइट मोड'; about='जानकारी'; close='बंद करें'; minimize='छोटा करें'; aboutCreator='निर्माता: Khalid Alsahari'; aboutWebsite='वेबसाइट'; aboutInstagram='Instagram';
        hint='शॉर्टकट केवल Control विंडो सक्रिय होने पर काम करते हैं।'; range='अनुमत सीमा: 0.50 – 2.00';
    }
}
$script:vk = @{
    PageUp=0x21; PageDown=0x22; Home=0x24; End=0x23; Insert=0x2D; Delete=0x2E;
    F1=0x70; F2=0x71; F3=0x72; F4=0x73; F5=0x74; F6=0x75; F7=0x76; F8=0x77; F9=0x78; F10=0x79; F11=0x7A; F12=0x7B;
    NumPadAdd=0x6B; NumPadSubtract=0x6D
}
foreach ($keyName in [Enum]::GetNames([Windows.Input.Key])) {
    if ($script:vk.ContainsKey($keyName)) { continue }
    try {
        $keyValue = [Windows.Input.Key][Enum]::Parse([Windows.Input.Key],$keyName)
        $virtualKey = [Windows.Input.KeyInterop]::VirtualKeyFromKey($keyValue)
        if ($virtualKey -gt 0 -and $virtualKey -le 255) { $script:vk[$keyName] = [uint32]$virtualKey }
    } catch {}
}
for ($digit = 0; $digit -le 9; $digit++) { $script:vk[[string]$digit] = [uint32](0x30 + $digit) }
$script:hotkeyUi = @{
    en=@{ press='Press any key…'; reset='Restore default hotkeys'; resetFov='Reset FOV multiplier' }
    ar=@{ press='اضغط أي مفتاح…'; reset='إعادة الاختصارات الافتراضية'; resetFov='إعادة ضبط مجال الرؤية' }
    es=@{ press='Pulsa cualquier tecla…'; reset='Restaurar atajos predeterminados'; resetFov='Restablecer el multiplicador FOV' }
    tr=@{ press='Bir tuşa basın…'; reset='Varsayılan kısayolları geri yükle'; resetFov='FOV çarpanını sıfırla' }
    'zh-CN'=@{ press='请按任意键…'; reset='恢复默认快捷键'; resetFov='重置视野倍率' }
    fr=@{ press='Appuyez sur une touche…'; reset='Rétablir les raccourcis par défaut'; resetFov='Réinitialiser le multiplicateur FOV' }
    de=@{ press='Beliebige Taste drücken…'; reset='Standard-Tastenkürzel wiederherstellen'; resetFov='FOV-Multiplikator zurücksetzen' }
    pt=@{ press='Pressione qualquer tecla…'; reset='Restaurar atalhos padrão'; resetFov='Redefinir multiplicador de FOV' }
    ja=@{ press='任意のキーを押してください…'; reset='ショートカットを初期設定に戻す'; resetFov='FOV倍率をリセット' }
    ko=@{ press='아무 키나 누르세요…'; reset='기본 단축키로 재설정'; resetFov='FOV 배율 초기화' }
    ru=@{ press='Нажмите любую клавишу…'; reset='Сбросить горячие клавиши'; resetFov='Сбросить множитель FOV' }
    hi=@{ press='कोई भी कुंजी दबाएँ…'; reset='डिफ़ॉल्ट शॉर्टकट बहाल करें'; resetFov='FOV गुणक रीसेट करें' }
}

$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Control FOV" Width="500" Height="530" ResizeMode="NoResize"
        WindowStyle="None" AllowsTransparency="True" Background="Transparent"
        WindowStartupLocation="CenterScreen" ShowInTaskbar="True" FontFamily="Segoe UI">
  <Window.Resources>
    <SolidColorBrush x:Key="AppBg" Color="#111318"/><SolidColorBrush x:Key="PanelBg" Color="#1B1E26"/>
    <SolidColorBrush x:Key="ControlBg" Color="#292D38"/><SolidColorBrush x:Key="TextFg" Color="#F5F5F7"/>
    <SolidColorBrush x:Key="MutedFg" Color="#A2A6B1"/><SolidColorBrush x:Key="Accent" Color="#9B7AFF"/>
    <SolidColorBrush x:Key="AccentHover" Color="#AD94FF"/><SolidColorBrush x:Key="Outline" Color="#303440"/>
    <Style TargetType="Button" x:Key="ActionButton">
      <Setter Property="Foreground" Value="{DynamicResource TextFg}"/><Setter Property="Background" Value="{DynamicResource ControlBg}"/>
      <Setter Property="BorderThickness" Value="0"/><Setter Property="Padding" Value="12,7"/><Setter Property="Cursor" Value="Hand"/>
      <Setter Property="FontSize" Value="13"/><Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
        <Border x:Name="b" Background="{TemplateBinding Background}" CornerRadius="8" Padding="{TemplateBinding Padding}">
          <ContentPresenter Content="{TemplateBinding Content}" ContentTemplate="{TemplateBinding ContentTemplate}" ContentTemplateSelector="{TemplateBinding ContentTemplateSelector}" RecognizesAccessKey="True" HorizontalAlignment="Center" VerticalAlignment="Center" TextElement.Foreground="{TemplateBinding Foreground}"/>
        </Border><ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Opacity" Value="0.84"/></Trigger>
        <Trigger Property="IsEnabled" Value="False"><Setter TargetName="b" Property="Opacity" Value="0.45"/></Trigger></ControlTemplate.Triggers>
      </ControlTemplate></Setter.Value></Setter>
    </Style>
    <Style TargetType="Button" x:Key="PrimaryButton" BasedOn="{StaticResource ActionButton}"><Setter Property="Background" Value="{DynamicResource Accent}"/><Setter Property="Foreground" Value="#FFFFFF"/><Setter Property="FontWeight" Value="SemiBold"/></Style>
    <Style TargetType="ComboBox"><Setter Property="Foreground" Value="{DynamicResource TextFg}"/><Setter Property="Background" Value="{DynamicResource ControlBg}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource Outline}"/><Setter Property="BorderThickness" Value="1"/><Setter Property="Padding" Value="8,5"/><Setter Property="FontSize" Value="12"/>
      <Setter Property="ItemContainerStyle"><Setter.Value><Style TargetType="ComboBoxItem"><Setter Property="Foreground" Value="{DynamicResource TextFg}"/><Setter Property="Background" Value="{DynamicResource PanelBg}"/><Setter Property="Padding" Value="8,6"/><Setter Property="HorizontalContentAlignment" Value="Stretch"/><Style.Triggers><Trigger Property="IsHighlighted" Value="True"><Setter Property="Background" Value="{DynamicResource Accent}"/><Setter Property="Foreground" Value="White"/></Trigger><Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="{DynamicResource ControlBg}"/><Setter Property="Foreground" Value="{DynamicResource TextFg}"/></Trigger></Style.Triggers></Style></Setter.Value></Setter>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="ComboBox"><Grid>
        <Border x:Name="ComboBorder" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="7"/>
        <ContentPresenter x:Name="ContentSite" IsHitTestVisible="False" Content="{TemplateBinding SelectionBoxItem}" ContentTemplate="{TemplateBinding SelectionBoxItemTemplate}" ContentTemplateSelector="{TemplateBinding ItemTemplateSelector}" Margin="8,2,27,2" VerticalAlignment="Center" HorizontalAlignment="Left" TextElement.Foreground="{TemplateBinding Foreground}"/>
        <ToggleButton x:Name="DropButton" Focusable="False" Width="25" HorizontalAlignment="Right" Background="Transparent" BorderThickness="0" IsChecked="{Binding IsDropDownOpen, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}" ClickMode="Press"><TextBlock Text="⌄" Foreground="{TemplateBinding Foreground}" FontSize="13" VerticalAlignment="Center" HorizontalAlignment="Center"/></ToggleButton>
        <Popup x:Name="Popup" Placement="Bottom" IsOpen="{TemplateBinding IsDropDownOpen}" AllowsTransparency="True" Focusable="False" PopupAnimation="Fade" StaysOpen="False"><Border Background="{DynamicResource PanelBg}" BorderBrush="{DynamicResource Outline}" BorderThickness="1" CornerRadius="7" MinWidth="{Binding ActualWidth, RelativeSource={RelativeSource TemplatedParent}}" MaxHeight="{TemplateBinding MaxDropDownHeight}"><ScrollViewer Margin="3" SnapsToDevicePixels="True"><ItemsPresenter KeyboardNavigation.DirectionalNavigation="Contained"/></ScrollViewer></Border></Popup>
      </Grid><ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="ComboBorder" Property="BorderBrush" Value="{DynamicResource Accent}"/></Trigger><Trigger Property="IsEnabled" Value="False"><Setter TargetName="ComboBorder" Property="Opacity" Value="0.55"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter>
    </Style>
  </Window.Resources>
  <Border x:Name="Root" Background="{DynamicResource AppBg}" BorderBrush="{DynamicResource Outline}" BorderThickness="1" CornerRadius="16" Padding="16">
    <Grid>
      <Grid.RowDefinitions><RowDefinition Height="45"/><RowDefinition Height="146"/><RowDefinition Height="48"/><RowDefinition Height="*"/><RowDefinition Height="36"/></Grid.RowDefinitions>
      <Grid x:Name="DragBar" Grid.Row="0" Margin="0,0,0,10">
        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
        <StackPanel VerticalAlignment="Center"><TextBlock x:Name="AppTitle" Text="CONTROL FOV" FontSize="16" FontWeight="Bold" Foreground="{DynamicResource TextFg}"/><TextBlock x:Name="SubTitle" Text="FIELD OF VIEW" FontSize="9" Foreground="{DynamicResource Accent}" Margin="1,2,0,0"/></StackPanel>
        <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
          <ComboBox x:Name="LanguagePicker" Width="92" Height="32" SelectedValuePath="Tag" Margin="0,0,7,0"/>
          <Button x:Name="ThemeButton" Style="{StaticResource ActionButton}" Width="38" Height="32" Padding="0" Margin="0,0,7,0" Content="☼" ToolTip="Toggle light and dark theme"/>
          <Button x:Name="AboutButton" Style="{StaticResource ActionButton}" Height="32" Padding="10,4" Content="About"/>
          <Button x:Name="MinimizeButton" Style="{StaticResource ActionButton}" Width="32" Height="32" Padding="0" Margin="7,0,0,0" Content="−" FontSize="18"/>
          <Button x:Name="CloseButton" Style="{StaticResource ActionButton}" Width="32" Height="32" Padding="0" Margin="7,0,0,0" Content="×" FontSize="18"/>
        </StackPanel>
      </Grid>
      <Border x:Name="FovCard" Grid.Row="1" Background="{DynamicResource PanelBg}" CornerRadius="12" Padding="18,12" Margin="0,0,0,10">
        <Grid><Grid.RowDefinitions><RowDefinition Height="22"/><RowDefinition Height="*"/><RowDefinition Height="28"/></Grid.RowDefinitions>
          <Grid Grid.Row="0">
            <TextBlock x:Name="FovCaption" Text="FOV MULTIPLIER" FontSize="10" FontWeight="SemiBold" Foreground="{DynamicResource MutedFg}" VerticalAlignment="Center"/>
            <Button x:Name="ResetFovButton" Style="{StaticResource ActionButton}" Width="28" Height="23" Padding="0" Content="↻" FontSize="14" HorizontalAlignment="Right" VerticalAlignment="Center" ToolTip="Reset FOV multiplier"/>
          </Grid>
          <Grid Grid.Row="1" Margin="0,4,0,0"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
            <TextBlock x:Name="FovValue" Text="1.00" MinWidth="160" FontSize="38" FontWeight="SemiBold" Foreground="{DynamicResource Accent}" VerticalAlignment="Center" TextTrimming="None"/>
            <Button x:Name="DecreaseButton" Grid.Column="1" Style="{StaticResource ActionButton}" Width="46" Height="46" Margin="0,0,8,0" Padding="0"/>
            <Button x:Name="IncreaseButton" Grid.Column="2" Style="{StaticResource PrimaryButton}" Width="46" Height="46" Padding="0"/>
            <TextBlock Grid.Column="1" Text="−" IsHitTestVisible="False" Foreground="{DynamicResource TextFg}" FontSize="20" FontWeight="SemiBold" HorizontalAlignment="Center" VerticalAlignment="Center"/>
            <TextBlock Grid.Column="2" Text="+" IsHitTestVisible="False" Foreground="White" FontSize="18" FontWeight="SemiBold" HorizontalAlignment="Center" VerticalAlignment="Center"/>
          </Grid>
          <Grid Grid.Row="2"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
            <TextBlock x:Name="RangeText" Text="Allowed multiplier: 0.50 – 2.00" FontSize="10" Foreground="{DynamicResource MutedFg}" VerticalAlignment="Center"/>
            <TextBlock x:Name="StepCaption" Grid.Column="1" Text="Step" FontSize="11" Foreground="{DynamicResource MutedFg}" VerticalAlignment="Center" Margin="0,0,8,0"/>
            <ComboBox x:Name="StepPicker" Grid.Column="2" Width="78" Height="27" SelectedValue="0.05" SelectedValuePath="Content">
              <ComboBoxItem Content="0.01"/><ComboBoxItem Content="0.02"/><ComboBoxItem Content="0.05"/><ComboBoxItem Content="0.10"/><ComboBoxItem Content="0.20"/>
            </ComboBox>
          </Grid>
        </Grid>
      </Border>
      <Grid Grid.Row="2" Margin="0,0,0,9"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
        <StackPanel VerticalAlignment="Center"><TextBlock x:Name="StateText" Text="FOV adjustments enabled" FontSize="12" FontWeight="SemiBold" Foreground="#72D6A1"/><TextBlock x:Name="HotkeyHint" Text="Hotkeys work globally while this window is open." FontSize="9" Foreground="{DynamicResource MutedFg}" Margin="0,3,0,0"/></StackPanel>
        <Button x:Name="ToggleButton" Grid.Column="1" Style="{StaticResource ActionButton}" Height="34" MinWidth="112" Content="Disable FOV"/>
      </Grid>
      <Border x:Name="HotkeyCard" Grid.Row="3" Background="{DynamicResource PanelBg}" CornerRadius="12" Padding="16,12" Margin="0,0,0,10">
        <Grid><Grid.RowDefinitions><RowDefinition Height="27"/><RowDefinition Height="28"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Grid Grid.Row="0">
            <TextBlock x:Name="HotkeyTitle" Text="HOTKEYS" FontSize="12" FontWeight="Bold" Foreground="{DynamicResource TextFg}" VerticalAlignment="Center"/>
            <Button x:Name="ResetHotkeysButton" Style="{StaticResource ActionButton}" Width="30" Height="25" Padding="0" Content="↻" FontSize="15" HorizontalAlignment="Right" VerticalAlignment="Center" ToolTip="Restore default hotkeys"/>
          </Grid>
          <Grid Grid.Row="1"><Grid.ColumnDefinitions><ColumnDefinition Width="154"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
            <TextBlock x:Name="KeyHeader" Text="HOTKEY" FontSize="9" FontWeight="SemiBold" Foreground="{DynamicResource MutedFg}" VerticalAlignment="Center"/>
            <TextBlock x:Name="ActionHeader" Grid.Column="1" Text="ACTION" FontSize="9" FontWeight="SemiBold" Foreground="{DynamicResource MutedFg}" VerticalAlignment="Center"/>
          </Grid>
          <Grid Grid.Row="2"><Grid.RowDefinitions><RowDefinition Height="*"/><RowDefinition Height="*"/><RowDefinition Height="*"/><RowDefinition Height="*"/></Grid.RowDefinitions>
            <Grid.ColumnDefinitions><ColumnDefinition Width="154"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
            <Button x:Name="UpKey" Tag="Up" Grid.Row="0" Width="140" Height="28" Margin="0,3,8,3" Padding="8,2" Style="{StaticResource ActionButton}" HorizontalAlignment="Left" VerticalAlignment="Center" Content="PageUp"/>
            <Button x:Name="DownKey" Tag="Down" Grid.Row="1" Width="140" Height="28" Margin="0,3,8,3" Padding="8,2" Style="{StaticResource ActionButton}" HorizontalAlignment="Left" VerticalAlignment="Center" Content="PageDown"/>
            <Button x:Name="EnableKey" Tag="Enable" Grid.Row="2" Width="140" Height="28" Margin="0,3,8,3" Padding="8,2" Style="{StaticResource ActionButton}" HorizontalAlignment="Left" VerticalAlignment="Center" Content="F2"/>
            <Button x:Name="DisableKey" Tag="Disable" Grid.Row="3" Width="140" Height="28" Margin="0,3,8,3" Padding="8,2" Style="{StaticResource ActionButton}" HorizontalAlignment="Left" VerticalAlignment="Center" Content="F3"/>
            <TextBlock x:Name="UpAction" Grid.Column="1" Grid.Row="0" Text="Increase FOV" FontSize="12" Foreground="{DynamicResource TextFg}" VerticalAlignment="Center"/>
            <TextBlock x:Name="DownAction" Grid.Column="1" Grid.Row="1" Text="Decrease FOV" FontSize="12" Foreground="{DynamicResource TextFg}" VerticalAlignment="Center"/>
            <TextBlock x:Name="EnableAction" Grid.Column="1" Grid.Row="2" Text="Enable FOV" FontSize="12" Foreground="{DynamicResource TextFg}" VerticalAlignment="Center"/>
            <TextBlock x:Name="DisableAction" Grid.Column="1" Grid.Row="3" Text="Disable FOV" FontSize="12" Foreground="{DynamicResource TextFg}" VerticalAlignment="Center"/>
          </Grid>
        </Grid>
      </Border>
      <Grid Grid.Row="4" Margin="0,0,0,0">
        <TextBlock x:Name="StatusText" Text="Changes are saved to renderer.ini. Restart Control to apply." FontSize="10" Foreground="{DynamicResource MutedFg}" TextWrapping="Wrap" Margin="1,0,0,0" VerticalAlignment="Center"/>
      </Grid>
    </Grid>
  </Border>
</Window>
'@

[xml]$xamlXml = $xaml
$xamlReader = New-Object System.Xml.XmlNodeReader $xamlXml
$script:window = [Windows.Markup.XamlReader]::Load($xamlReader)
foreach ($name in @('Root','DragBar','AppTitle','SubTitle','LanguagePicker','ThemeButton','AboutButton','MinimizeButton','CloseButton','FovCard','FovCaption','ResetFovButton','FovValue','DecreaseButton','IncreaseButton','RangeText','StepCaption','StepPicker','StateText','HotkeyHint','ToggleButton','HotkeyCard','HotkeyTitle','ResetHotkeysButton','KeyHeader','ActionHeader','UpKey','DownKey','EnableKey','DisableKey','UpAction','DownAction','EnableAction','DisableAction','StatusText')) {
    Set-Variable -Scope Script -Name $name -Value $script:window.FindName($name)
}
foreach ($languageCode in $script:languageOptions.Keys) {
    $languageItem = New-Object Windows.Controls.ComboBoxItem
    $languageItem.Content = $script:languageOptions[$languageCode]
    $languageItem.Tag = $languageCode
    [void]$script:LanguagePicker.Items.Add($languageItem)
}
$script:LanguagePicker.ApplyTemplate() | Out-Null
$languageArrow = $script:LanguagePicker.Template.FindName('DropButton',$script:LanguagePicker)
if ($languageArrow) { $languageArrow.Visibility = [Windows.Visibility]::Collapsed }
$languageText = $script:LanguagePicker.Template.FindName('ContentSite',$script:LanguagePicker)
if ($languageText) { $languageText.Margin = [Windows.Thickness]::new(8,2,8,2) }
$script:StepPicker.ApplyTemplate() | Out-Null
$stepArrow = $script:StepPicker.Template.FindName('DropButton',$script:StepPicker)
if ($stepArrow) { $stepArrow.Visibility = [Windows.Visibility]::Collapsed }
$stepText = $script:StepPicker.Template.FindName('ContentSite',$script:StepPicker)
if ($stepText) { $stepText.Margin = [Windows.Thickness]::new(8,2,8,2) }
$script:StepPicker.SelectedValue = $script:step.ToString('0.00',[cultureinfo]::InvariantCulture)
function Format-HotkeyLabel([string]$keyName) {
    if ($keyName -match '^D([0-9])$') { return $Matches[1] }
    return $keyName
}
foreach ($name in @('Up','Down','Enable','Disable')) { $script:hotkeys[$name] = Format-HotkeyLabel $script:hotkeys[$name] }
$script:UpKey.Content = $script:hotkeys.Up
$script:DownKey.Content = $script:hotkeys.Down
$script:EnableKey.Content = $script:hotkeys.Enable
$script:DisableKey.Content = $script:hotkeys.Disable

function Get-Strings { return $script:text[$script:language] }
function Save-Preferences {
    $script:hotkeys.Up = [string]$script:UpKey.Content
    $script:hotkeys.Down = [string]$script:DownKey.Content
    $script:hotkeys.Enable = [string]$script:EnableKey.Content
    $script:hotkeys.Disable = [string]$script:DisableKey.Content
    $script:step = [double]::Parse([string]$script:StepPicker.SelectedValue,[cultureinfo]::InvariantCulture)
    $record = [ordered]@{ Language=$script:language; DarkMode=$script:darkMode; Enabled=$script:enabled; Fov=$script:fov; LastEnabledFov=$script:lastEnabledFov; Step=$script:step; Up=$script:hotkeys.Up; Down=$script:hotkeys.Down; Enable=$script:hotkeys.Enable; Disable=$script:hotkeys.Disable; GameDir=$script:gameDir }
    $record | ConvertTo-Json | Set-Content -LiteralPath $script:prefsPath -Encoding UTF8
}
function Set-Status([string]$kind) {
    $s = Get-Strings
    switch ($kind) {
        'saved' { $script:StatusText.Text = $s.saved }
        'running' { $script:StatusText.Text = $s.gameRunning }
        'live' { $script:StatusText.Text = $s.live }
        'notRunning' { $script:StatusText.Text = $s.notRunning }
        'memoryError' { $script:StatusText.Text = $s.memoryError }
        'missing' { $script:StatusText.Text = $s.missing }
        'invalid' { $script:StatusText.Text = $s.invalid }
        'conflict' { $script:StatusText.Text = $s.conflict }
        default { $script:StatusText.Text = $s.restart }
    }
}
function Is-ControlRunning {
    return [bool](Get-Process -Name @('Control_DX11','Control_DX12') -ErrorAction SilentlyContinue | Select-Object -First 1)
}
function Get-ControlProcess {
    return Get-Process -Name @('Control_DX11','Control_DX12') -ErrorAction SilentlyContinue | Sort-Object StartTime -Descending | Select-Object -First 1
}
function Set-GamePathFromProcess($process) {
    try {
        $exePath = [string]$process.MainModule.FileName
        if ([string]::IsNullOrWhiteSpace($exePath)) { return $false }
        $directory = [IO.Path]::GetDirectoryName($exePath)
        if ([string]::IsNullOrWhiteSpace($directory) -or !(Test-Path -LiteralPath $directory -PathType Container)) { return $false }
        $script:gameDir = $directory
        $script:iniPath = Join-Path $directory 'renderer.ini'
        $script:gamePathPid = $process.Id
        Save-Preferences
        return $true
    } catch {
        return $false
    }
}
function Close-LiveConnection {
    if ($script:liveHandle -ne [IntPtr]::Zero) {
        $alive = Get-Process -Id $script:livePid -ErrorAction SilentlyContinue
        if ($alive -and $script:liveHookAddress -ne 0 -and $script:liveBridgeAddress -ne 0) {
            [void][ControlFovMemory]::RestoreHook($script:liveHandle,$script:liveHookAddress,$script:liveBridgeAddress)
        }
        [ControlFovMemory]::Close($script:liveHandle)
    }
    $script:livePid = 0; $script:liveHandle = [IntPtr]::Zero; $script:liveHookAddress = 0L; $script:liveBridgeAddress = 0L
    $script:liveFieldAddress = 0L; $script:liveLastWrittenAddress = 0L
}
function Apply-LiveFov {
    if ($script:liveHandle -eq [IntPtr]::Zero -or $script:liveBridgeAddress -eq 0) { return $false }
    $ok = [ControlFovMemory]::WriteFloat($script:liveHandle,$script:liveBridgeAddress + 40,[single]$script:fov)
    if (!$ok) { Set-Status 'running'; return $false }
    if ($script:liveFieldAddress -ne 0) {
        [void][ControlFovMemory]::WriteFloat($script:liveHandle,$script:liveFieldAddress + 0x10,[single]$script:fov)
        $script:liveLastWrittenAddress = $script:liveFieldAddress
        Set-Status 'live'; return $true
    }
    Set-Status 'running'; return $false
}
function Update-LiveConnection {
    $process = Get-ControlProcess
    if (!$process) {
        $script:controlPid = 0
        $wasAttached = $script:livePid -ne 0
        if ($script:liveHandle -ne [IntPtr]::Zero) { Close-LiveConnection }
        $script:liveFailedPid = 0
        if ($wasAttached) { [void](Write-FovConfig -ForceFile) } else { Set-Status 'notRunning' }
        return
    }
    $script:controlPid = $process.Id
    if ($script:gamePathPid -ne $process.Id) { [void](Set-GamePathFromProcess $process) }
    if ($script:liveFailedPid -eq $process.Id) { Set-Status 'memoryError'; return }
    if ($script:livePid -ne $process.Id -or $script:liveHandle -eq [IntPtr]::Zero) {
        if ($script:liveHandle -ne [IntPtr]::Zero) { Close-LiveConnection }
        if ($script:liveFailedPid -ne 0 -and $script:liveFailedPid -ne $process.Id) { $script:liveFailedPid = 0 }
        if (((Get-Date) - $process.StartTime).TotalSeconds -lt 2) { Set-Status 'running'; return }
        $handle = [IntPtr]::Zero
        try {
            $module = $process.MainModule
            $handle = [ControlFovMemory]::Open($process.Id)
            if ($handle -eq [IntPtr]::Zero) { $script:liveFailedPid = $process.Id; Set-Status 'memoryError'; return }
            $target = [ControlFovMemory]::FindUniquePattern($handle,$module.BaseAddress.ToInt64(),$module.ModuleMemorySize,[byte[]](0xF3,0x0F,0x59,0x43,0x10))
            if ($target -eq 0) { [ControlFovMemory]::Close($handle); $script:liveFailedPid = $process.Id; Set-Status 'memoryError'; return }
            $bridge = [ControlFovMemory]::InstallHook($handle,$target,[single]$script:fov)
            $script:livePid = $process.Id; $script:liveHandle = $handle; $script:liveHookAddress = $target; $script:liveBridgeAddress = $bridge
            $script:liveFailedPid = 0
        } catch {
            if ($handle -ne [IntPtr]::Zero) { [ControlFovMemory]::Close($handle) }
            $script:liveFailedPid = $process.Id
            Set-Status 'memoryError'; return
        }
    }
    $field = [ControlFovMemory]::ReadPointer($script:liveHandle,$script:liveBridgeAddress + 32)
    if ($field -ne 0) {
        $changed = ($field -ne $script:liveFieldAddress)
        $script:liveFieldAddress = $field
        if ($changed -or $script:liveLastWrittenAddress -ne $field) { [void](Apply-LiveFov) }
    } else { Set-Status 'running' }
}
function Write-FovConfig([switch]$ForceFile) {
    Save-Preferences
    $script:FovValue.Text = $script:fov.ToString('0.00',[cultureinfo]::InvariantCulture)
    if ((Is-ControlRunning) -and !$ForceFile) {
        Apply-LiveFov
        if ($script:liveFieldAddress -eq 0) { Set-Status 'running' }
        return $true
    }
    if ([string]::IsNullOrWhiteSpace($script:iniPath)) { Set-Status 'notRunning'; return $false }
    if (!(Test-Path -LiteralPath $script:iniPath)) { Set-Status 'missing'; return $false }
    $content = [IO.File]::ReadAllText($script:iniPath)
    $pattern = '("m_fFOVMultiplier"\s*:\s*)([0-9]+(?:\.[0-9]+)?)'
    if (![regex]::IsMatch($content,$pattern)) { Set-Status 'invalid'; return $false }
    $number = $script:fov.ToString('0.00',[cultureinfo]::InvariantCulture)
    $match = [regex]::Match($content,$pattern)
    $replacement = $match.Groups[1].Value + $number
    $updated = $content.Substring(0,$match.Index) + $replacement + $content.Substring($match.Index + $match.Length)
    $backup = $script:iniPath + '.control-fov.bak'
    if (!(Test-Path -LiteralPath $backup)) { Copy-Item -LiteralPath $script:iniPath -Destination $backup }
    $tempPath = $script:iniPath + '.control-fov.tmp'
    [IO.File]::WriteAllText($tempPath,$updated,[Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $tempPath -Destination $script:iniPath -Force
    Set-Status 'saved'
    return $true
}
function Refresh-State {
    $s = Get-Strings
    $script:FovValue.Text = $script:fov.ToString('0.00',[cultureinfo]::InvariantCulture)
    $script:StateText.Text = if ($script:enabled) { $s.enabled } else { $s.disabled }
    $stateColor = if ($script:enabled) { '#3CB371' } else { '#EF5350' }
    $script:StateText.Foreground = [Windows.Media.BrushConverter]::new().ConvertFromString($stateColor)
    $script:ToggleButton.Content = if ($script:enabled) { $s.disable } else { $s.enable }
    $toggleColor = if ($script:enabled) { '#16803C' } else { '#C62828' }
    $script:ToggleButton.Background = [Windows.Media.BrushConverter]::new().ConvertFromString($toggleColor)
    $script:ToggleButton.Foreground = [Windows.Media.Brushes]::White
}
function Reset-Fov {
    $script:fov = 1.00
    $script:lastEnabledFov = 1.00
    Refresh-State
    [void](Write-FovConfig)
}
function Update-Language {
    $s = Get-Strings
    $script:window.FlowDirection = if ($script:language -eq 'ar') { [Windows.FlowDirection]::RightToLeft } else { [Windows.FlowDirection]::LeftToRight }
    $script:AppTitle.Text = $s.title; $script:SubTitle.Text = $s.subtitle; $script:FovCaption.Text = $s.current
    $script:StepCaption.Text = $s.step; $script:RangeText.Text = $s.range; $script:HotkeyTitle.Text = $s.shortcuts
    $script:KeyHeader.Text = $s.key; $script:ActionHeader.Text = $s.action
    $script:UpAction.Text = $s.increase; $script:DownAction.Text = $s.decrease; $script:EnableAction.Text = $s.enableAction; $script:DisableAction.Text = $s.disableAction
    $script:HotkeyHint.Text = $s.hint; $script:AboutButton.Content = $s.about
    $script:ResetHotkeysButton.ToolTip = $script:hotkeyUi[$script:language].reset
    $script:ResetFovButton.ToolTip = $script:hotkeyUi[$script:language].resetFov
    if ($script:captureTarget) { $script:captureTarget.Content = $script:hotkeyUi[$script:language].press }
    $script:MinimizeButton.ToolTip = $s.minimize
    $script:ThemeButton.Content = if ($script:darkMode) { '☼' } else { '☾' }
    $script:ThemeButton.ToolTip = $s.theme
    Refresh-State
    Set-Status 'restart'
}
function Set-Theme {
    $palette = if ($script:darkMode) {
        @{ AppBg='#111318'; PanelBg='#1B1E26'; ControlBg='#292D38'; TextFg='#F5F5F7'; MutedFg='#A2A6B1'; Accent='#9B7AFF'; Outline='#303440' }
    } else {
        @{ AppBg='#F2F3F7'; PanelBg='#FFFFFF'; ControlBg='#E8EAF0'; TextFg='#252733'; MutedFg='#656A78'; Accent='#6948C7'; Outline='#D7D9E1' }
    }
    foreach ($key in $palette.Keys) {
        $brush = [Windows.Media.BrushConverter]::new().ConvertFromString($palette[$key])
        $brush.Freeze(); $script:window.Resources[$key] = $brush
    }
    $script:ThemeButton.Content = if ($script:darkMode) { '☼' } else { '☾' }
}
function Apply-FovDelta([double]$delta) {
    if (!$script:enabled) { return }
    $script:fov = [math]::Round([math]::Max(0.50,[math]::Min(2.00,$script:fov + $delta)),2)
    $script:lastEnabledFov = $script:fov
    [void](Write-FovConfig)
}
function Set-FovEnabled([bool]$on) {
    if ($on -eq $script:enabled) { return }
    if ($on) { $script:enabled = $true; $script:fov = [math]::Max(0.50,[math]::Min(2.00,$script:lastEnabledFov)) }
    else { $script:lastEnabledFov = $script:fov; $script:enabled = $false; $script:fov = 1.00 }
    Refresh-State
    [void](Write-FovConfig)
}
function Get-HotkeyRows {
    return @(
        @{ Id=1; Name='Up'; Box=$script:UpKey; Action={ Apply-FovDelta $script:step } },
        @{ Id=2; Name='Down'; Box=$script:DownKey; Action={ Apply-FovDelta (-$script:step) } },
        @{ Id=3; Name='Enable'; Box=$script:EnableKey; Action={ Set-FovEnabled $true } },
        @{ Id=4; Name='Disable'; Box=$script:DisableKey; Action={ Set-FovEnabled $false } }
    )
}
function Unregister-Hotkeys {
    foreach ($id in $script:registeredIds) { [void][ControlFovHotkeys]::UnregisterHotKey($script:hotkeyHandle,$id) }
    $script:registeredIds = @()
}
function Register-Hotkeys {
    Save-Preferences
    Unregister-Hotkeys
    if ($script:hotkeyHandle -eq [IntPtr]::Zero) { return }
    $script:hotkeysActive = ($script:controlPid -gt 0 -and [ControlFovHotkeys]::GetForegroundProcessId() -eq $script:controlPid)
    $rows = @(Get-HotkeyRows)
    $chosen = @($rows | ForEach-Object { [string]$_.Box.Content })
    $codes = @($chosen | Where-Object { $script:vk.ContainsKey($_) } | ForEach-Object { [int]$script:vk[$_] })
    if ($chosen.Count -ne 4 -or $codes.Count -ne 4 -or @($codes | Select-Object -Unique).Count -ne 4) { Set-Status 'conflict'; return }
    if (!$script:hotkeysActive) { return }
    $registrationFailed = $false
    foreach ($row in $rows) {
        $keyName = [string]$row.Box.Content
        if (![ControlFovHotkeys]::RegisterHotKey($script:hotkeyHandle,$row.Id,0,[uint32]$script:vk[$keyName])) {
            $registrationFailed = $true
            continue
        }
        $script:registeredIds += $row.Id
    }
    if ($registrationFailed) { Set-Status 'conflict'; return }
    if ([string]::IsNullOrWhiteSpace($script:iniPath) -or !(Test-Path -LiteralPath $script:iniPath)) { Set-Status 'notRunning' } else { Set-Status 'restart' }
}
function Update-HotkeyFocus {
    $shouldBeActive = ($script:controlPid -gt 0 -and [ControlFovHotkeys]::GetForegroundProcessId() -eq $script:controlPid)
    if (!$shouldBeActive) {
        if ($script:hotkeysActive -or $script:registeredIds.Count -gt 0) { Unregister-Hotkeys }
        $script:hotkeysActive = $false
        return
    }
    if (!$script:hotkeysActive) { Register-Hotkeys }
}
function Cancel-HotkeyCapture([switch]$Closing) {
    if (!$script:captureTarget) { return }
    $target = $script:captureTarget
    $name = $script:captureName
    if ($script:captureTimer) { $script:captureTimer.Stop() }
    $target.Content = [string]$script:hotkeys[$name]
    $target.ClearValue([Windows.Controls.Control]::BackgroundProperty)
    $target.ClearValue([Windows.Controls.Control]::ForegroundProperty)
    $script:captureTarget = $null
    $script:captureName = ''
    if (!$Closing) { Register-Hotkeys }
}
function Begin-HotkeyCapture([Windows.Controls.Button]$button) {
    if ($script:captureTarget -eq $button) { Cancel-HotkeyCapture; return }
    if ($script:captureTarget) { Cancel-HotkeyCapture }
    Unregister-Hotkeys
    $script:captureTarget = $button
    $script:captureName = [string]$button.Tag
    $button.Content = $script:hotkeyUi[$script:language].press
    $button.Background = $script:window.Resources['Accent']
    $button.Foreground = [Windows.Media.Brushes]::White
    $script:StatusText.Text = $script:hotkeyUi[$script:language].press
    [void]$button.Focus()
    $script:pressedVirtualKeys = @{}
    foreach ($entry in $script:vk.GetEnumerator()) {
        $keyName = [string]$entry.Key
        $virtualKey = [int]$entry.Value
        if ($virtualKey -lt 0x08 -or $keyName -in @('LeftCtrl','RightCtrl','LeftAlt','RightAlt','LeftShift','RightShift','LWin','RWin','System')) { continue }
        if (!$script:pressedVirtualKeys.ContainsKey($virtualKey)) {
            $script:pressedVirtualKeys[$virtualKey] = ([ControlFovHotkeys]::GetAsyncKeyState($virtualKey) -lt 0)
        }
    }
    if ($script:captureTimer) { $script:captureTimer.Start() }
}
function Reset-Hotkeys {
    if ($script:captureTarget) { Cancel-HotkeyCapture }
    $script:hotkeys.Up = 'PageUp'; $script:hotkeys.Down = 'PageDown'; $script:hotkeys.Enable = 'F2'; $script:hotkeys.Disable = 'F3'
    $script:UpKey.Content = $script:hotkeys.Up; $script:DownKey.Content = $script:hotkeys.Down
    $script:EnableKey.Content = $script:hotkeys.Enable; $script:DisableKey.Content = $script:hotkeys.Disable
    Register-Hotkeys
}
function Set-CapturedHotkey([string]$keyName) {
    if (!$script:captureTarget) { return }
    $keyName = Format-HotkeyLabel $keyName
    if ($keyName -in @('LeftCtrl','RightCtrl','LeftAlt','RightAlt','LeftShift','RightShift','LWin','RWin','System')) { return }
    if (!$script:vk.ContainsKey($keyName)) { return }
    $virtualKey = [int]$script:vk[$keyName]
    $otherCodes = @(Get-HotkeyRows | Where-Object { $_.Name -ne $script:captureName } | ForEach-Object { $otherName = [string]$_.Box.Content; if ($script:vk.ContainsKey($otherName)) { [int]$script:vk[$otherName] } })
    if ($otherCodes -contains $virtualKey) {
        Cancel-HotkeyCapture
        Set-Status 'conflict'
        return
    }
    $target = $script:captureTarget
    $name = $script:captureName
    $target.Content = $keyName
    $target.ClearValue([Windows.Controls.Control]::BackgroundProperty)
    $target.ClearValue([Windows.Controls.Control]::ForegroundProperty)
    $script:hotkeys[$name] = $keyName
    $script:captureTarget = $null
    $script:captureName = ''
    if ($script:captureTimer) { $script:captureTimer.Stop() }
    Register-Hotkeys
}
function Capture-Hotkey([Windows.Input.KeyEventArgs]$eventArgs) {
    if (!$script:captureTarget) { return }
    $key = if ($eventArgs.Key -eq [Windows.Input.Key]::System) { $eventArgs.SystemKey } else { $eventArgs.Key }
    $keyName = $key.ToString()
    if ($keyName -in @('LeftCtrl','RightCtrl','LeftAlt','RightAlt','LeftShift','RightShift','LWin','RWin','System')) { return }
    if (!$script:vk.ContainsKey($keyName)) { $eventArgs.Handled = $true; return }
    Set-CapturedHotkey $keyName
    $eventArgs.Handled = $true
}
$script:captureTimer = New-Object Windows.Threading.DispatcherTimer
$script:captureTimer.Interval = [TimeSpan]::FromMilliseconds(25)
$script:captureTimer.Add_Tick({
    if (!$script:captureTarget) { $script:captureTimer.Stop(); return }
    foreach ($entry in $script:vk.GetEnumerator()) {
        $keyName = [string]$entry.Key
        $virtualKey = [int]$entry.Value
        if ($virtualKey -lt 0x08 -or $keyName -in @('LeftCtrl','RightCtrl','LeftAlt','RightAlt','LeftShift','RightShift','LWin','RWin','System')) { continue }
        $isDown = ([ControlFovHotkeys]::GetAsyncKeyState($virtualKey) -lt 0)
        $wasDown = [bool]$script:pressedVirtualKeys[$virtualKey]
        $script:pressedVirtualKeys[$virtualKey] = $isDown
        if ($isDown -and !$wasDown) { Set-CapturedHotkey $keyName; break }
    }
})
function Show-About {
    $s = Get-Strings
    $palette = if ($script:darkMode) {
        @{ PanelBg='#1B1E26'; ControlBg='#292D38'; TextFg='#F5F5F7'; MutedFg='#A2A6B1'; Accent='#9B7AFF'; Outline='#303440' }
    } else {
        @{ PanelBg='#FFFFFF'; ControlBg='#E8EAF0'; TextFg='#252733'; MutedFg='#656A78'; Accent='#6948C7'; Outline='#D7D9E1' }
    }
    $aboutXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Width="390" Height="245" MinWidth="390" MaxWidth="390" MinHeight="245" MaxHeight="245"
        WindowStyle="None" ResizeMode="NoResize" AllowsTransparency="True" Background="Transparent"
        ShowInTaskbar="False" WindowStartupLocation="CenterOwner" UseLayoutRounding="True">
    <Window.Resources>
        <Style x:Key="LinkButton" TargetType="{x:Type Button}">
            <Setter Property="Background" Value="Transparent" />
            <Setter Property="BorderThickness" Value="0" />
            <Setter Property="Padding" Value="0" />
            <Setter Property="Cursor" Value="Hand" />
            <Setter Property="FontFamily" Value="Segoe UI" />
            <Setter Property="FontSize" Value="13" />
            <Setter Property="FontWeight" Value="SemiBold" />
            <Setter Property="FocusVisualStyle" Value="{x:Null}" />
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="{x:Type Button}">
                        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" />
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>
    <Border x:Name="AboutBorder" CornerRadius="16" BorderThickness="1" Padding="21">
        <Grid>
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto" />
                <RowDefinition Height="16" />
                <RowDefinition Height="*" />
            </Grid.RowDefinitions>
            <DockPanel Grid.Row="0" LastChildFill="True">
                <Button x:Name="AboutClose" DockPanel.Dock="Right" Width="34" Height="34" Margin="12,0,0,0"
                    Content="×" FontFamily="Segoe UI" FontSize="23" FontWeight="Light"
                    BorderThickness="0" Focusable="False" Cursor="Hand" />
                <StackPanel VerticalAlignment="Center">
                    <TextBlock x:Name="AboutTitle" FontFamily="Segoe UI" FontSize="18" FontWeight="SemiBold" />
                    <TextBlock x:Name="AboutSubtitle" Text="CONTROL FIELD OF VIEW" Margin="0,3,0,0"
                        FontFamily="Segoe UI" FontSize="10" FontWeight="SemiBold" />
                </StackPanel>
            </DockPanel>
            <Border x:Name="AboutContent" Grid.Row="2" CornerRadius="11" Padding="15">
                <StackPanel VerticalAlignment="Center">
                    <TextBlock x:Name="AboutCreator" FontFamily="Segoe UI" FontSize="13" Margin="0,0,0,10" />
                    <StackPanel Orientation="Horizontal" Margin="0,0,0,8">
                        <TextBlock x:Name="AboutWebsiteLabel" VerticalAlignment="Center" FontFamily="Segoe UI" FontSize="12" />
                        <Button x:Name="AboutWebsiteLink" Content="ippyz.com" Style="{StaticResource LinkButton}" Margin="8,0,0,0" />
                    </StackPanel>
                    <StackPanel Orientation="Horizontal">
                        <TextBlock x:Name="AboutInstagramLabel" VerticalAlignment="Center" FontFamily="Segoe UI" FontSize="12" />
                        <Button x:Name="AboutInstagramLink" Content="@ippyz" Style="{StaticResource LinkButton}" Margin="8,0,0,0" />
                    </StackPanel>
                </StackPanel>
            </Border>
        </Grid>
    </Border>
</Window>
'@
    $reader = [System.Xml.XmlNodeReader]::new([xml]$aboutXaml)
    $dialog = [Windows.Markup.XamlReader]::Load($reader)
    $dialog.Owner = $script:window
    $dialog.FlowDirection = if ($script:language -eq 'ar') { [Windows.FlowDirection]::RightToLeft } else { [Windows.FlowDirection]::LeftToRight }
    $dialog.Title = $s.about
    $dialog.FontFamily = $script:window.FontFamily
    $dialog.FindName('AboutBorder').Background = [Windows.Media.BrushConverter]::new().ConvertFromString($palette.PanelBg)
    $dialog.FindName('AboutBorder').BorderBrush = [Windows.Media.BrushConverter]::new().ConvertFromString($palette.Outline)
    $dialog.FindName('AboutTitle').Text = $s.about
    $dialog.FindName('AboutTitle').Foreground = [Windows.Media.BrushConverter]::new().ConvertFromString($palette.TextFg)
    $dialog.FindName('AboutSubtitle').Foreground = [Windows.Media.BrushConverter]::new().ConvertFromString($palette.Accent)
    $dialog.FindName('AboutContent').Background = [Windows.Media.BrushConverter]::new().ConvertFromString($palette.ControlBg)
    $dialog.FindName('AboutCreator').Text = $s.aboutCreator
    $dialog.FindName('AboutCreator').Foreground = [Windows.Media.BrushConverter]::new().ConvertFromString($palette.TextFg)
    $dialog.FindName('AboutWebsiteLabel').Text = $s.aboutWebsite + ':'
    $dialog.FindName('AboutWebsiteLabel').Foreground = [Windows.Media.BrushConverter]::new().ConvertFromString($palette.MutedFg)
    $dialog.FindName('AboutInstagramLabel').Text = $s.aboutInstagram + ':'
    $dialog.FindName('AboutInstagramLabel').Foreground = [Windows.Media.BrushConverter]::new().ConvertFromString($palette.MutedFg)
    $aboutClose = $dialog.FindName('AboutClose')
    $aboutClose.Background = [Windows.Media.BrushConverter]::new().ConvertFromString($palette.ControlBg)
    $aboutClose.Foreground = [Windows.Media.BrushConverter]::new().ConvertFromString($palette.TextFg)
    $websiteLink = $dialog.FindName('AboutWebsiteLink')
    $instagramLink = $dialog.FindName('AboutInstagramLink')
    $linkBrush = [Windows.Media.BrushConverter]::new().ConvertFromString($palette.Accent)
    $websiteLink.Foreground = $linkBrush
    $instagramLink.Foreground = $linkBrush
    $websiteLink.Add_Click({ Start-Process -FilePath 'https://ippyz.com/' })
    $instagramLink.Add_Click({ Start-Process -FilePath 'https://www.instagram.com/ippyz' })
    $closeHandler = { $dialog.Close() }.GetNewClosure()
    $aboutClose.Add_Click($closeHandler)
    $dragHandler = { if ($_.ButtonState -eq [Windows.Input.MouseButtonState]::Pressed) { $dialog.DragMove() } }.GetNewClosure()
    $dialog.Add_MouseLeftButtonDown($dragHandler)
    $dialog.ShowDialog() | Out-Null
}

$script:DragBar.Add_MouseLeftButtonDown({ if ($_.ButtonState -eq [Windows.Input.MouseButtonState]::Pressed) { $script:window.DragMove() } })
$script:MinimizeButton.Add_Click({ $script:window.WindowState = [Windows.WindowState]::Minimized })
$script:CloseButton.Add_Click({ $script:window.Close() })
$script:AboutButton.Add_Click({ Show-About })
$script:ResetFovButton.Add_Click({ Reset-Fov })
$script:ThemeButton.Add_Click({ $script:darkMode = !$script:darkMode; Set-Theme; Save-Preferences })
$script:LanguagePicker.Add_SelectionChanged({
    $selectedLanguage = [string]$script:LanguagePicker.SelectedValue
    if ($script:text.ContainsKey($selectedLanguage)) {
        $script:language = $selectedLanguage
        Update-Language; Save-Preferences
    }
})
$script:LanguagePicker.Add_PreviewMouseLeftButtonDown({
    if ($_.OriginalSource -is [Windows.Controls.ComboBoxItem]) { return }
    $item = [Windows.Controls.ItemsControl]::ContainerFromElement($script:LanguagePicker,$_.OriginalSource)
    if ($item) { return }
    $script:LanguagePicker.IsDropDownOpen = !$script:LanguagePicker.IsDropDownOpen
    $_.Handled = $true
})
$script:StepPicker.Add_PreviewMouseLeftButtonDown({
    param($sender, $eventArgs)
    if ($eventArgs.OriginalSource -is [Windows.Controls.ComboBoxItem]) { return }
    $item = [Windows.Controls.ItemsControl]::ContainerFromElement($script:StepPicker,$eventArgs.OriginalSource)
    if ($item) { return }
    $script:StepPicker.IsDropDownOpen = !$script:StepPicker.IsDropDownOpen
    $eventArgs.Handled = $true
})
$script:StepPicker.Add_SelectionChanged({ if ($script:StepPicker.SelectedValue) { Save-Preferences } })
$script:UpKey.Add_Click({ Begin-HotkeyCapture $script:UpKey })
$script:DownKey.Add_Click({ Begin-HotkeyCapture $script:DownKey })
$script:EnableKey.Add_Click({ Begin-HotkeyCapture $script:EnableKey })
$script:DisableKey.Add_Click({ Begin-HotkeyCapture $script:DisableKey })
$script:ResetHotkeysButton.Add_Click({ Reset-Hotkeys })
$script:window.Add_PreviewKeyDown({
    param($sender, $eventArgs)
    if ($script:captureTarget) { Capture-Hotkey $eventArgs }
})
foreach ($hotkeyButton in @($script:UpKey,$script:DownKey,$script:EnableKey,$script:DisableKey)) {
    $lostFocusHandler = { if ($script:captureTarget -eq $hotkeyButton) { Cancel-HotkeyCapture } }.GetNewClosure()
    $hotkeyButton.Add_LostKeyboardFocus($lostFocusHandler)
}
$script:DecreaseButton.Add_Click({ Apply-FovDelta (-$script:step) })
$script:IncreaseButton.Add_Click({ Apply-FovDelta $script:step })
$script:ToggleButton.Add_Click({ Set-FovEnabled (!$script:enabled) })
$script:window.Add_SourceInitialized({
    $helper = New-Object Windows.Interop.WindowInteropHelper($script:window)
    $script:hotkeyHandle = $helper.Handle
    $script:hotkeySource = [Windows.Interop.HwndSource]::FromHwnd($script:hotkeyHandle)
    $script:hotkeyHook = [Windows.Interop.HwndSourceHook]{
        param($hwnd,$msg,$wParam,$lParam,[ref]$handled)
        if ($msg -eq 0x0312) {
            $id = $wParam.ToInt32()
            $row = @(Get-HotkeyRows | Where-Object { $_.Id -eq $id } | Select-Object -First 1)
            if ($row.Count -gt 0) { & $row[0].Action; $handled.Value = $true }
        }
        return [IntPtr]::Zero
    }
    $script:hotkeySource.AddHook($script:hotkeyHook)
    Register-Hotkeys
})
$script:window.Add_Closed({
    if ($script:captureTarget) { Cancel-HotkeyCapture -Closing }
    if ($script:liveTimer) { $script:liveTimer.Stop() }
    if ($script:hotkeyFocusTimer) { $script:hotkeyFocusTimer.Stop() }
    foreach ($id in $script:registeredIds) { [void][ControlFovHotkeys]::UnregisterHotKey($script:hotkeyHandle,$id) }
    $script:registeredIds = @()
    $script:hotkeysActive = $false
    Close-LiveConnection
    [void](Write-FovConfig -ForceFile)
    Save-Preferences
})

$script:StepPicker.SelectedValue = $script:step.ToString('0.00',[cultureinfo]::InvariantCulture)
$script:LanguagePicker.SelectedValue = $script:language
Update-Language
Set-Theme
$script:liveTimer = New-Object Windows.Threading.DispatcherTimer
$script:liveTimer.Interval = [TimeSpan]::FromMilliseconds(500)
$script:liveTimer.Add_Tick({ try { Update-LiveConnection } catch { Set-Status 'memoryError' } })
try { Update-LiveConnection } catch { Set-Status 'memoryError' }
$script:liveTimer.Start()
$script:hotkeyFocusTimer = New-Object Windows.Threading.DispatcherTimer
$script:hotkeyFocusTimer.Interval = [TimeSpan]::FromMilliseconds(75)
$script:hotkeyFocusTimer.Add_Tick({ try { Update-HotkeyFocus } catch {} })
$script:hotkeyFocusTimer.Start()
[void]$script:window.ShowDialog()
