//! addr_resolver
//!
//! Resolve a u32 kernel address (decimal) to source:line using DWARF info from vmlinux.
//!
//! Address rule:
//!   addr64 = (addr_u32 as u64) | 0xFFFF_FFFF_0000_0000
//!
//! Note: to keep addr2line::Context inside the struct we leak the binary bytes once
//! (Box::leak) to obtain a 'static borrow. This is a single intentional leak.
use addr2line::Context;
use anyhow::{Context as AnyhowContext, Result};
use object::File;
use std::any;
use std::rc::Rc;
use std::sync::Once;
use std::{
    fs,
    path::{Component, Path, PathBuf},
    cell::RefCell,
    sync::OnceLock,
};

// use addr2line's re-exported gimli types to match versions exactly
type RunTimeEndian = addr2line::gimli::RunTimeEndian;
type Addr2lineReader = addr2line::gimli::EndianReader<RunTimeEndian, Rc<[u8]>>;
type Addr2lineContext = addr2line::Context<Addr2lineReader>;

thread_local! {
    static THREAD_LOCAL_RESOLVER: RefCell<Option<AddrResolver>> = RefCell::new(None);
}

static GLOBAL_INIT: OnceLock<(String, String)> = OnceLock::new();

pub struct AddrResolver {
    ctx: Addr2lineContext,
    // keep a reference to leaked bytes (data itself is 'static)
    _leaked: &'static [u8],
    // linux source tree root (normalized)
    linux_root: PathBuf,
}

impl AddrResolver {
    // 初始化全局的路径，只在主线程调用一次
    pub fn init_global(vmlinux_path: &str, linux_src: &str) {
        GLOBAL_INIT.get_or_init(|| (vmlinux_path.to_string(), linux_src.to_string()));
    }

    // 在当前的线程中获取resolver的引用，从而执行操作
    pub fn with<F, R>(f: F) -> Result<R, anyhow::Error>
    where F: FnOnce(&Self) -> Result<R>, {
        THREAD_LOCAL_RESOLVER.with(|cell| {
            let mut opt = cell.borrow_mut();
            let resolver = opt.get_or_insert_with(|| {
                let (vmlinux, src_root) = GLOBAL_INIT.get()
                    .expect("AddrResolver::init_global must be called first");
                AddrResolver::new(Some(vmlinux), Some(src_root))
                    .expect("Failed to create thread-local AddrResolver")
            });
            f(resolver)
        })
    }

    /// Create an AddrResolver from a vmlinux path (must contain DWARF/debug info).
    /// This reads the file and builds the addr2line context once.
    /// Note: this leaks the file bytes to 'static (Box::leak).
    /// New: accepts linux_src_root, the absolute path to the linux source used to build vmlinux.
    pub fn new(vmlinux_path: Option<&str>, linux_src_root: Option<&str>) -> Result<Self> {
        let data = fs::read(vmlinux_path.as_ref().unwrap())
            .with_context(|| format!("failed to read file {:?}", vmlinux_path))?;
        // Leak bytes to 'static to avoid self-referential lifetime issues.
        let leaked: &'static [u8] = Box::leak(data.into_boxed_slice());
        // Parse object file borrowing leaked bytes
        let file = File::parse(leaked)
            .with_context(|| format!("failed to parse object file {:?}", vmlinux_path))?;
        // addr2line will pick its preferred reader type (which uses Rc<[u8]> internally).
        let ctx = Context::new(&file).with_context(|| "failed to create addr2line context")?;
        // normalize provided linux source root (remove "./" components, etc)
        let linux_root_norm =
            normalize_path(linux_src_root.map(Path::new).unwrap_or(Path::new("")));
        Ok(Self {
            ctx,
            _leaked: leaked,
            linux_root: linux_root_norm,
        })
    }
    /// Resolve a u32 address (decimal) to source path and line.
    /// Address expansion rule: addr64 = (addr as u64) | 0xFFFF_FFFF_0000_0000
    /// Returns Ok(Some((source_path, line))) if found, Ok(None) if not found.
    /// The returned source_path is simplified relative to the linux_src_root provided at construction:
    /// if the DWARF file path is under linux_src_root, the linux_root prefix is removed.
    pub fn resolve(&self, addr: u32) -> Result<Option<(String, u32)>> {
        let addr64 = (addr as u64) | 0xFFFF_FFFF_0000_0000u64;
        if let Some(location) = self.ctx.find_location(addr64)? {
            if let (Some(file), Some(line)) = (location.file, location.line) {
                // simplify file path relative to linux_root
                let simplified = self.simplify_source(file);
                // println!("Addr: {:x} Src: {:?} Line: {:?}", addr, &simplified, line);
                return Ok(Some((simplified, line)));
            }
            else {
                // No file or line info found, return None
                // println!("Addr: {:x} has no source location", addr);
            }
        }
        Ok(None)
    }

    /// Simplify an addr2line-provided source path using linux_root:
    /// - normalize the incoming path (remove "/./" like components),
    /// - if it's under linux_root, strip the linux_root prefix and return the remainder,
    /// - otherwise return the normalized path.
    fn simplify_source(&self, source: &str) -> String {
        let p = Path::new(source);
        let p_norm = normalize_path(p);
        // Try strip_prefix using normalized linux_root
        if let Ok(rel) = p_norm.strip_prefix(&self.linux_root) {
            // return "lib/idr.c" style (no leading '/')
            return rel.to_string_lossy().into_owned();
        }
        // If not under linux_root, return the normalized original path (losing any "./" pieces)
        p_norm.to_string_lossy().into_owned()
    }
}

/// normalization: just remove "./" components
fn normalize_path(p: &Path) -> PathBuf {
    p.components()
        .filter(|&comp| comp != Component::CurDir)
        .collect()
}
