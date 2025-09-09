use crate::util::stop_soon;
use anyhow::{Context, Result};
use healer_core::corpus::CorpusWrapper;
use healer_core::syscall::Syscall;
use healer_core::target::Target;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::thread::sleep;
use std::{
    sync::atomic::{AtomicU64, Ordering},
    sync::Mutex,
    time::Duration,
};
use std::io::Write;
use crate::Arc;

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct Stats {
    fuzzing: AtomicU64,
    repro: AtomicU64,
    relations: AtomicU64,
    crashes: AtomicU64,
    unique_crash: AtomicU64,
    // crash_suppressed: AtomicU64,
    vm_restarts: AtomicU64,
    corpus_size: AtomicU64,
    exec_total: AtomicU64,
    cal_cov: AtomicU64,
    max_cov: AtomicU64,
}

impl Stats {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn inc_fuzzing(&self) {
        self.fuzzing.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn dec_fuzzing(&self) {
        self.fuzzing.fetch_sub(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_repro(&self) {
        self.repro.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn dec_repro(&self) {
        self.repro.fetch_sub(1, Ordering::Relaxed);
    }

    pub(crate) fn set_re(&self, n: u64) {
        self.relations.store(n, Ordering::Relaxed);
    }

    pub(crate) fn set_unique_crash(&self, n: u64) {
        self.unique_crash.store(n, Ordering::Relaxed);
    }

    pub(crate) fn inc_crashes(&self) {
        self.crashes.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_vm_restarts(&self) {
        self.vm_restarts.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_corpus_size(&self) {
        self.corpus_size.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_exec_total(&self) {
        self.exec_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn set_cal_cov(&self, n: u64) {
        self.cal_cov.store(n, Ordering::Relaxed);
    }

    pub(crate) fn set_max_cov(&self, n: u64) {
        self.max_cov.store(n, Ordering::Relaxed);
    }

    pub(crate) fn report<P: AsRef<Path>>(
        &self,
        duration: Duration,
        out_dir: Option<P>,
    ) -> Result<()> {
        let mut f: Option<File> = if let Some(d) = out_dir {
            let p = d.as_ref();
            let f = OpenOptions::new()
                .create(true)
                .append(true)
                .write(true)
                .open(p)
                .context("report")?;
            Some(f)
        } else {
            None
        };

        while !stop_soon() {
            sleep(duration);

            let fuzzing = self.fuzzing.load(Ordering::Relaxed);
            let repro = self.repro.load(Ordering::Relaxed);
            let crashes = self.crashes.load(Ordering::Relaxed);
            let unique_crash = self.unique_crash.load(Ordering::Relaxed);
            let corpus_size = self.corpus_size.load(Ordering::Relaxed);
            let exec_total = self.exec_total.load(Ordering::Relaxed);
            let corpus_cov = self.cal_cov.load(Ordering::Relaxed);
            let max_cov = self.max_cov.load(Ordering::Relaxed);
            log::info!(
                "exec: {}, fuzz/repro {}/{}, uniq/total crashes {}/{}, cal/max cover {}/{}, corpus: {}",
                exec_total,
                fuzzing,
                repro,
                unique_crash,
                crashes,
                corpus_cov,
                max_cov,
                corpus_size
            );

            if let Some(f) = f.as_mut() {
                serde_json::to_writer_pretty(f, self).context("dump stats")?;
            }
        }

        Ok(())
    }

    pub(crate) fn report_corpus<P: AsRef<Path>>(
        &self,
        duration: Duration,
        corpus_out_dir: Option<P>,
        corpus: Arc<CorpusWrapper>,
        target: Arc<Target>,
    ) -> Result<()> {
        let mut f: Option<File> = if let Some(d) = corpus_out_dir {
            let p = d.as_ref();
            let f = OpenOptions::new()
                .create(true)
                .append(true)
                .write(true)
                .open(p)
                .context("report")?;
            Some(f)
        } else {
            None
        };

        while !stop_soon() {
            sleep(duration);

            // 统计corpus里的所有种子里各种显式依赖和隐式依赖有多少对
            let (explicitPair, implicitPair) = corpus.expImpDepCount();

            if let Some(f) = f.as_mut() {
                // 先输出"Explicit: xx"代表下面的内容是显式依赖
                writeln!(f, "Explicit: {}", explicitPair.len()).context("dump corpus stats")?;
                // 然后把每一对显式依赖及数量以"sysA sysB count"的格式写入文件
                for ((a, b), count) in &explicitPair {
                    let syscall_a_name = target
                        .syscall_of(a.clone())
                        .name();
                    let syscall_b_name = target
                        .syscall_of(b.clone())
                        .name();
                    writeln!(f, "({} -> {}) : {}", syscall_a_name, syscall_b_name, count).context("dump corpus stats")?;
                }
                // 隐式依赖同理
                // 先输出"Implicit: xx"代表下面的内容是隐式依赖
                writeln!(f, "Implicit: {}", implicitPair.len()).context("dump corpus stats")?;
                // 然后把每一对隐式依赖及数量以"sysA sysB count"的格式写入文件
                for ((a, b), count) in &implicitPair {
                    let syscall_a_name = target
                        .syscall_of(a.clone())
                        .name();
                    let syscall_b_name = target
                        .syscall_of(b.clone())
                        .name();
                    writeln!(f, "({} -> {}) : {}", syscall_a_name, syscall_b_name, count).context("dump corpus stats")?;
                }
                println!("total dependency has written into the file.");
            }
        }

        Ok(())
    }
}
