use crate::util::stop_soon;
use anyhow::{Context, Result};
use healer_core::corpus::CorpusWrapper;
use healer_core::prog::Prog;
use healer_core::syscall::SyscallId;
use healer_core::HashSet;
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
        totalcorpus_out_dir: Option<P>,
        newcorpus_out_dir: Option<P>,
        totalcorpus: Arc<CorpusWrapper>,
        newcorpus: Arc<Mutex<Vec<Prog>>>,
    ) -> Result<()> {
        let mut f1: Option<File> = if let Some(d) = totalcorpus_out_dir {
            let p = d.as_ref();
            let f1 = OpenOptions::new()
                .create(true)
                .append(true)
                .write(true)
                .open(p)
                .context("report")?;
            Some(f1)
        } else {
            None
        };

        let mut f2: Option<File> = if let Some(d) = newcorpus_out_dir {
            let p = d.as_ref();
            let f2 = OpenOptions::new()
                .create(true)
                .append(true)
                .write(true)
                .open(p)
                .context("report")?;
            Some(f2)
        } else {
            None
        };

        while !stop_soon() {
            sleep(duration);

            // 统计totalcorpus的长度和里面的显式隐式依赖数量
            let totalcorpus_size = self.corpus_size.load(Ordering::Relaxed);
            let (expNumTotal, impNumTotal) = totalcorpus.expImpDepCount();

            // 先把newcorpus复制一份给记录函数用
            let newcorpus_clone = newcorpus.lock().unwrap().clone();
            let newcorpus_size = newcorpus_clone.len() as i32;
            // 然后再清掉
            newcorpus.lock().unwrap().clear();
            let mut expPairs: HashSet<(SyscallId, SyscallId)> = HashSet::new();
            let mut impPairs: HashSet<(SyscallId, SyscallId)> = HashSet::new();
            for p in newcorpus_clone.iter() {
                expPairs.extend(p.explicitPairs.clone());
                impPairs.extend(p.implicitPairs.clone());
            }

            let expNum = if expPairs.len() > 0 {
                expPairs.len() as i32
            } else {
                -1
            };
            let impNum = if impPairs.len() > 0 {
                impPairs.len() as i32
            } else {
                -1
            };

            if let Some(f1) = f1.as_mut() {
                writeln!(f1, "{} {} {}", totalcorpus_size, expNumTotal, impNumTotal).context("dump corpus stats")?;
                println!("total dependency has written into the file.");
            }
            
            if let Some(f2) = f2.as_mut() {
                writeln!(f2, "{} {} {}", newcorpus_size, expNum, impNum).context("dump corpus stats")?;
                println!("dependency has written into the file.");
            }
        }

        Ok(())
    }
}
