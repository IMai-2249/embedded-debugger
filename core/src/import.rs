//! 芯片描述导入：自定义 probe-rs YAML 与厂商 CMSIS-Pack（.pack）
//!
//! 从桌面版 commands.rs 抽出的纯逻辑（无 GUI 依赖）：
//! 解析 PDSC 设备表 + FLM Flash 算法，生成芯片描述 YAML 存入自定义目录。

use serde::Serialize;

// ---------- 自定义芯片描述（YAML） ----------

/// 自定义芯片描述目录（%APPDATA%/com.embedded.debugger/custom-targets）
/// 桌面版与 VS Code 桥接版共用同一目录（tauri app_data_dir = %APPDATA%/<identifier>）
fn custom_dir() -> Result<std::path::PathBuf, String> {
    let base = std::env::var("APPDATA").map_err(|_| "获取数据目录失败".to_string())?;
    Ok(std::path::Path::new(&base)
        .join("com.embedded.debugger")
        .join("custom-targets"))
}

/// 读取全部自定义芯片描述并加入 registry
pub fn registry_with_custom() -> probe_rs::config::Registry {
    let mut reg = probe_rs::config::Registry::from_builtin_families();
    if let Ok(dir) = custom_dir() {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                let p = e.path();
                let is_yaml = p
                    .extension()
                    .map(|x| x == "yaml" || x == "yml")
                    .unwrap_or(false);
                if is_yaml {
                    if let Ok(yaml) = std::fs::read_to_string(&p) {
                        let _ = reg.add_target_family_from_yaml(&yaml);
                    }
                }
            }
        }
    }
    reg
}

#[derive(Serialize, Clone)]
pub struct ImportResult {
    pub family: String,
    pub variants: Vec<String>,
}

/// 导入自定义芯片描述 YAML（可来自 target-gen 从 CMSIS-Pack 生成）
pub fn import_target(path: &str) -> Result<ImportResult, String> {
    let yaml = std::fs::read_to_string(path).map_err(|e| format!("读取文件失败: {e}"))?;
    let mut reg = probe_rs::config::Registry::from_builtin_families();
    let family = reg
        .add_target_family_from_yaml(&yaml)
        .map_err(|e| format!("YAML 解析失败: {e}"))?;
    let variants = reg
        .families()
        .iter()
        .find(|f| f.name == family)
        .map(|f| f.variants.iter().map(|c| c.name.clone()).collect())
        .unwrap_or_default();

    let dir = custom_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建目录失败: {e}"))?;
    let safe: String = family
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    std::fs::write(dir.join(format!("{safe}.yaml")), yaml)
        .map_err(|e| format!("保存失败: {e}"))?;

    Ok(ImportResult { family, variants })
}

#[derive(Serialize, Clone)]
pub struct PackImportProgress {
    pub stage: String, // parse | family | done
    pub family: Option<String>,
    pub done: usize,
    pub total: usize,
    pub message: String,
}

#[derive(Serialize, Clone)]
pub struct PackImportResult {
    pub pack: String,
    pub families: Vec<ImportResult>,
}

/// 导入厂商 CMSIS-Pack（.pack）：解析 PDSC 设备表 + FLM Flash 算法，
/// 生成芯片描述 YAML 存入自定义目录，同名系列自动替换（重复导入即更新）。
pub fn import_pack_sync(
    path: &str,
    progress: &dyn Fn(PackImportProgress),
) -> Result<PackImportResult, String> {
    let emit = |stage: &str, family: Option<String>, done: usize, total: usize, message: String| {
        progress(PackImportProgress { stage: stage.into(), family, done, total, message });
    };

    emit("parse", None, 0, 0, format!("正在解析芯片包 {} …", path));
    let mut families: Vec<probe_rs_target::ChipFamily> = Vec::new();
    target_gen::generate::visit_file(std::path::Path::new(path), &mut families)
        .map_err(|e| format!("芯片包解析失败: {e}"))?;
    if families.is_empty() {
        return Err("芯片包中没有可识别的设备（未找到有效的设备描述）".into());
    }

    let dir = custom_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建目录失败: {e}"))?;
    let mut reg = probe_rs::config::Registry::from_builtin_families();
    // 内置库已有的系列不再写自定义 YAML：两份定义会各带一个 Flash 算法，
    // probe-rs 会报 "more than one suitable flash loader algorithm"，烧录直接失败
    let builtin_names: std::collections::HashSet<String> =
        reg.families().iter().map(|f| f.name.clone()).collect();
    let total = families.len();
    let mut out = Vec::new();
    for (i, family) in families.iter().enumerate() {
        if builtin_names.contains(&family.name) {
            emit(
                "family",
                Some(family.name.clone()),
                i + 1,
                total,
                format!("跳过 {}（内置库已有该系列）", family.name),
            );
            continue;
        }
        let yaml = target_gen::commands::elf::serialize_to_yaml_string(family)
            .map_err(|e| format!("生成描述失败（{}）: {e}", family.name))?;
        let name = reg
            .add_target_family_from_yaml(&yaml)
            .map_err(|e| format!("校验失败（{}）: {e}", family.name))?;
        let safe: String = name
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect();
        std::fs::write(dir.join(format!("{safe}.yaml")), &yaml)
            .map_err(|e| format!("保存失败（{name}）: {e}"))?;
        let variants: Vec<String> = reg
            .families()
            .iter()
            .find(|f| f.name == name)
            .map(|f| f.variants.iter().map(|c| c.name.clone()).collect())
            .unwrap_or_default();
        emit(
            "family",
            Some(name.clone()),
            i + 1,
            total,
            format!("已导入系列 {name}（{} 型号）", variants.len()),
        );
        out.push(ImportResult { family: name, variants });
    }
    emit("done", None, out.len(), out.len(), format!("导入完成：{} 个系列", out.len()));
    Ok(PackImportResult { pack: path.into(), families: out })
}
