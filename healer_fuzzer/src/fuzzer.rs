use crate::{
    config::Config, crash::CrashManager, feedback::Feedback, fuzzer_log::set_fuzzer_id, kill_syz,
    prepare_exec_env, retry_exec, stats::Stats, util::stop_soon,
};
use anyhow::Context;
use healer_core::{
    corpus::CorpusWrapper, gen::{gen_prog, minimize}, mutation::mutate, prog::Prog, relation::RelationWrapper, target::Target, HashMap, HashSet, RngType, 
    config2code::Config2Code,
};
use healer_vm::{qemu::QemuHandle};
use sha1::Digest;
use std::{
    cell::Cell,
    collections::VecDeque,
    fs::{create_dir_all, write, File},
    io::{BufWriter, Write, ErrorKind},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use syz_wrapper::{
    exec::{
        features::FEATURE_FAULT, ExecError, ExecOpt, ExecutorHandle, CALL_FAULT_INJECTED,
        FLAG_COLLIDE, FLAG_INJECT_FAULT,
    },
    report::extract_report,
    repro::repro,
};
use addr_resolver::AddrResolver;

pub struct SharedState {
    pub(crate) target: Arc<Target>,
    pub(crate) relation: Arc<RelationWrapper>,
    pub(crate) corpus: Arc<CorpusWrapper>,
    pub(crate) stats: Arc<Stats>,
    pub(crate) feedback: Arc<Feedback>,
    pub(crate) crash: Arc<CrashManager>,
    // 新增项，配置项与代码块的映射信息
    pub(crate) config2code: Arc<Config2Code>,
    // 新增项，统计产生新覆盖的种子数量
    pub(crate) newCoverageSeedNum: Arc<Mutex<u64>>,
    // 新增项，每隔固定时间加入到种子库的新种子
    pub(crate) newcorpus: Arc<Mutex<Vec<Prog>>>,
}

impl Clone for SharedState {
    fn clone(&self) -> Self {
        Self {
            target: Arc::clone(&self.target),
            relation: Arc::clone(&self.relation),
            corpus: Arc::clone(&self.corpus),
            stats: Arc::clone(&self.stats),
            feedback: Arc::clone(&self.feedback),
            crash: Arc::clone(&self.crash),
            config2code: Arc::clone(&self.config2code),
            newCoverageSeedNum: Arc::clone(&self.newCoverageSeedNum),
            newcorpus: Arc::clone(&self.newcorpus),
        }
    }
}

pub struct Fuzzer {
    pub shared_state: SharedState,

    // local
    pub id: u64,
    pub rng: RngType,
    pub executor: ExecutorHandle,
    pub qemu: QemuHandle,
    pub last_reboot: Instant,
    pub run_history: VecDeque<(ExecOpt, Prog)>,
    pub config: Config,
}

pub const HISTORY_CAPACITY: usize = 1024;

impl Fuzzer {
    pub fn fuzz_loop(&mut self, progs: Vec<Prog>) -> anyhow::Result<()> {
        // set fuzzer id to thread_local
        set_fuzzer_id(self.id);
        self.shared_state.stats.inc_fuzzing();
        fuzzer_info!("online",);

        if self.config.vmlinux_path.is_none() || self.config.kernel_src_path.is_none() {
            println!("Due to vmlinux is not provided, disable dynamic validation.")
        }
        else {
            // 由于KConfigFuzz需要用vmlinux从地址解析到源码行，这里需要新建一个AddrResolver对象传给shared_state
            AddrResolver::init_global(&(self.config.vmlinux_path.as_ref().unwrap()), &(self.config.kernel_src_path.as_ref().unwrap()));
        }

        // execute input progs
        if let Err(e) = self.exec_input_prog(progs) {
            self.shared_state.stats.dec_fuzzing();
            fuzzer_error!("{}", e);
            fuzzer_info!("offline",);
            return Err(e);
        } else if stop_soon() {
            self.shared_state.stats.dec_fuzzing();
            fuzzer_info!("offline",);
            return Ok(());
        }

        // real fuzz loop
        let mut ret = Ok(());
        if let Err(e) = self.fuzz_loop_inner() {
            fuzzer_error!("{}", e);
            ret = Err(e);
        }
        self.shared_state.stats.dec_fuzzing();
        fuzzer_info!("offline",);
        ret
    }

    fn exec_input_prog(&mut self, progs: Vec<Prog>) -> anyhow::Result<()> {
        if progs.is_empty() {
            return Ok(());
        }
        let prog_num = progs.len();
        fuzzer_info!("executing {} input progs", prog_num);
        for prog in progs {
            self.execute_one(prog)
                .context("failed to execute input prog")?;
            if stop_soon() {
                return Ok(());
            }
        }
        fuzzer_info!(
            "{} input progs execution finished, start to prog generation&mutation",
            prog_num
        );
        Ok(())
    }

    fn fuzz_loop_inner(&mut self) -> anyhow::Result<()> {
        // 注意这里有改动，原本是50
        const GENERATE_PERIOD: u64 = 50;

        // 新增：每隔一段时间将覆盖信息存储到文件里
        const OUTPUT_COVERAGE_PERIOD: u64 = 200;

        for i in 0_u64.. {

            // if i % OUTPUT_COVERAGE_PERIOD == 0 {
            //     let cov = self.shared_state.feedback.get_cal_cov();
            //     let file = File::create("healer_coverage")?;
            //     let mut writer = BufWriter::new(file);
            //     for value in &cov {
            //         writeln!(writer, "{:x}", value)?; // 以十六进制格式写入每个值
            //     }
            //     println!("Output coverage info to 'healer_coverage', total: {}", cov.len());
            // }

            // TODO update period based on gaining
            if self.shared_state.corpus.is_empty() || i % GENERATE_PERIOD == 0 {
                let p = gen_prog(
                    &self.shared_state.target,
                    &self.shared_state.relation,
                    &mut self.rng,
                );
                self.execute_one(p)
                    .context("failed to execute generated prog")?;
            } else {
                let mut p = self.shared_state.corpus.select_one(&mut self.rng).unwrap();
                mutate(
                    &self.shared_state.target,
                    &self.shared_state.relation,
                    &self.shared_state.corpus,
                    &mut self.rng,
                    &mut p,
                );
                self.execute_one(p)
                    .context("failed to execute mutated prog")?;
            }

            if stop_soon() {
                break;
            }
        }

        Ok(())
    }

    /// 执行一个种子。
    pub fn execute_one(&mut self, p: Prog) -> anyhow::Result<bool> {
        let opt = ExecOpt::new();
        self.record_execution(&p, &opt);
        let ret = self
            .executor
            .execute_one(&self.shared_state.target, &p, &opt);
        self.shared_state.stats.inc_exec_total();

        match ret {
            Ok(prog_info) => {
                // 是否有新的覆盖
                let mut new_cov = false;

                // 把种子里的每个系统调用对应的覆盖存在一个HashSet里
                let mut calls: Vec<(usize, HashSet<u32>)> = Vec::with_capacity(p.calls().len());
                let mut call_configs: Vec<HashMap<u32, HashSet<String>>> = Vec::new();

                for (idx, call_info) in prog_info.call_infos.into_iter().enumerate() {
                    let new = self
                        .shared_state
                        .feedback
                        .check_max_cov(call_info.branches.iter().copied());
                    calls.push((idx, call_info.branches.iter().copied().collect()));
                    if !new.is_empty() {
                        new_cov = true;
                    }
                }
                if let Some(extra) = prog_info.extra {
                    self.shared_state.feedback.check_max_cov(extra.branches);
                    // TODO handle extra
                }

                // 如果种子有新覆盖，给这个数加1
                if new_cov {
                    let mut num = self.shared_state.newCoverageSeedNum.lock().unwrap();
                    *num += 1;
                }

                // let mut idx_in_call_configs: usize = 0;
                for (idx, brs) in calls {
                    if self.config.vmlinux_path != None && self.config.kernel_src_path != None {
                        call_configs.push(self.AddrtoConfigs(&brs));
                    }
                    self.save_if_new(&p, idx, brs, &call_configs)?;
                    // println!("idx: {}, call_configs_length: {}", idx, call_configs.len());
                }

                self.clear_vm_log();
                self.maybe_reboot_vm()?;
                Ok(new_cov)
            }
            Err(e) => {
                if let Some(crash) = self.check_vm(&p, &e) {
                    self.handle_crash(&p, crash)
                        .context("failed to handle crash")?;
                    Ok(true)
                } else {
                    if let ExecError::UnexpectedExitStatus(_) | ExecError::OutputParse(_) = e {
                        fuzzer_warn!("executor: {}", e)
                    }
                    self.restart_exec()?;
                    Ok(false)
                }
            }
        }
    }

    // 将一个系统调用执行过的地址转换成源码，然后寻找对应的配置项
    fn AddrtoConfigs(&mut self, covs: &HashSet<u32>) -> HashMap<u32, HashSet<String>> {
        let mut configs = HashMap::<u32, HashSet<String>>::new();
        for addr in covs.iter() {
            // 先将地址转换成源码路径和行
            if let Ok(Some((src, line))) = AddrResolver::with(|r| r.resolve(*addr)) {
                // 然后根据源码路径和行号获取对应的配置项
                if let Some(target_configs) = self.shared_state.config2code.get_config(&src, &line) {
                    let mut configSet = HashSet::new();
                    for config in target_configs.iter() {
                        configSet.insert(config.clone());
                    }
                    configs.insert(*addr, configSet);
                }
            }
        }
        configs
    }

    fn save_if_new(&mut self, p: &Prog, mut idx: usize, brs: HashSet<u32>, call_configs: &Vec<HashMap<u32, HashSet<String>>>) -> anyhow::Result<()> {
        let mut new = self
            .shared_state
            .feedback
            .check_cal_cov(brs.iter().copied());
        if new.is_empty() {
            return Ok(());
        }
        fuzzer_debug!(
            "[{}] new cov: {}",
            self.shared_state.target.syscall_of(p.calls()[idx].sid()),
            new.len()
        );

        // calibrate new cov by executing it three times
        let mut failed = 0;
        for _ in 0..3 {
            let ret = self.reexec(p, idx)?;
            if ret.is_none() {
                failed += 1;
                if failed > 2 {
                    return Ok(());
                }
                continue;
            }
            let brs = ret.unwrap();
            new = new.intersection(&brs).copied().collect();
            if new.is_empty() {
                return Ok(());
            }
        }

        // minimize->学习新依赖->添加到依赖库

        // minimize
        let mut p = p.clone();
        let target = Arc::clone(&self.shared_state.target);
        idx = minimize(&target, &mut p, idx, |new_p, new_idx| {
            for _ in 0..3 {
                if let Ok(Some(brs)) = self.reexec(new_p, new_idx) {
                    return brs.intersection(&new).copied().count() == new.len();
                }
            }
            false
        });

        // detect relations
        let relation = Arc::clone(&self.shared_state.relation);

        let found_new = relation.try_update(&p, idx, |new_p, new_idx| {
            for _ in 0..3 {
                if let Ok(Some(brs)) = self.reexec(new_p, new_idx) {
                    return brs.intersection(&new).copied().count() != new.len();
                }
            }
            false
        });
        if found_new {
            let a = self
                .shared_state
                .target
                .syscall_of(p.calls()[idx - 1].sid());
            let b = self.shared_state.target.syscall_of(p.calls()[idx].sid());
            
            // println!("new relation: {:} -> {:}", a, b);
            // TODO dump relations

            self.shared_state
                .stats
                .set_re(self.shared_state.relation.num() as u64);
        }

        if self.config.vmlinux_path != None && self.config.kernel_src_path != None {
            // 新增的D部分
            // 对已有的依赖关系对(xxx, idx)进行验证
            for i in 0..idx {
                let call_a = p.calls()[i].sid();
                let call_b = p.calls()[idx].sid();
                if relation.influence(call_a, call_b) {
                    // 如果这个依赖关系对确实有需要验证的地址
                    if let Some(relate_paths) = relation.relate_path(call_a, call_b) {
                        // 遍历地址
                        for expected_addr in relate_paths.iter() {
                            // 这里需要一个验证的函数
                            if validate(expected_addr, &brs) {
                                relation.update_validation(call_a, call_b, expected_addr);
                            }
                        }
                    }
                }
            }
            // 同时这里进行基于配置项的新依赖捕获
            // 方式很简单，直接比较两个syscall调用的源码所属的配置项集有没有交集即可
            let mut found_new2 = false;
            let mut related_idx: usize = 0;
            let mut related_idx_cov: Vec<u32> = Vec::new();
            for i in 0..idx {
                related_idx_cov = has_intersection(&call_configs[i], &call_configs[idx]);
                if related_idx_cov.len() > 0 {
                    found_new2 = true;
                    related_idx = i;
                    break;
                }
            }
            if found_new2 {
                let a = p.calls()[related_idx].sid();
                let b = p.calls()[idx].sid();
                for path in related_idx_cov.iter() {
                    let addr = *path as u64;
                    relation.update_validation(a, b, &addr);
                }
                self.shared_state
                    .stats
                    .set_re(self.shared_state.relation.num() as u64);
                // TODO dump relations
                // let syscall_a = self.shared_state.target.syscall_of(a);
                // let syscall_b = self.shared_state.target.syscall_of(b);
                // println!("new relation: {:} -> {:}", syscall_a, syscall_b);
            }
        }
        
        // 记录种子里的显式与隐式依赖对
        p.foundSyscallPairInProg(&self.shared_state.target, &self.shared_state.relation);

        // save to local
        self.do_save_prog(p.clone(), &brs)?;

        // 将新种子存到newcorpus里去
        self.shared_state.newcorpus.lock().unwrap().push(p.clone());

        // fail call that found new cov
        if self.should_fail(&p) {
            self.fail_call(&p, idx)?;
        }
        Ok(())
    }

    fn should_fail(&self, p: &Prog) -> bool {
        let has_fault = self.config.features.unwrap() & FEATURE_FAULT != 0;
        if has_fault && !self.config.disable_fault_injection {
            if let Some(re) = self.config.fault_injection_regex.as_ref() {
                for c in p.calls() {
                    let s = self.shared_state.target.syscall_of(c.sid());
                    if re.is_match(s.name()) {
                        return false;
                    }
                }
            }
            return true;
        }
        false
    }

    fn fail_call(&mut self, p: &Prog, idx: usize) -> anyhow::Result<()> {
        let t = Arc::clone(&self.shared_state.target);
        let mut opt = ExecOpt::new();
        opt.enable(FLAG_INJECT_FAULT);
        opt.fault_call = idx as i32;

        for i in 1..=100 {
            opt.fault_nth = i;
            self.record_execution(p, &opt);
            self.shared_state.stats.inc_exec_total();
            let ret = self.executor.execute_one(&t, p, &opt);
            match ret {
                Ok(info) => {
                    if info.call_infos.len() > idx
                        && info.call_infos[idx].flags & CALL_FAULT_INJECTED == 0
                    {
                        break;
                    }
                    self.clear_vm_log();
                }
                Err(e) => {
                    if let Some(crash) = self.check_vm(p, &e) {
                        self.handle_crash(p, crash)
                            .context("failed to handle crash")?;
                    } else {
                        self.restart_exec()?;
                    }
                }
            }

            if stop_soon() {
                break;
            }
        }
        Ok(())
    }

    fn do_save_prog(&mut self, p: Prog, cov: &HashSet<u32>) -> anyhow::Result<()> {
        let mut hasher = sha1::Sha1::new();
        let p_str = p.display(&self.shared_state.target).to_string();
        hasher.update(p_str.as_bytes());
        let sha1 = hasher.finalize();
        let out = self.config.output.join("corpus");
        if let Err(e) = create_dir_all(&out) {
            if e.kind() != ErrorKind::AlreadyExists {
                return Err(e).context("failed to create corpus dir");
            }
        }
        write(out.join(&hex::encode(sha1)), p_str.as_bytes()).context("failed to write prog")?;

        self.shared_state.corpus.add_prog(p, cov.len() as u64);
        self.shared_state.stats.inc_corpus_size();
        self.shared_state.feedback.merge(cov);
        self.shared_state
            .stats
            .set_max_cov(self.shared_state.feedback.max_cov_len() as u64);
        self.shared_state
            .stats
            .set_cal_cov(self.shared_state.feedback.cal_cov_len() as u64);

        Ok(())
    }

    fn reexec(&mut self, p: &Prog, idx: usize) -> anyhow::Result<Option<HashSet<u32>>> {
        let mut opt = ExecOpt::new();
        opt.disable(FLAG_COLLIDE);
        let ret = self
            .executor
            .execute_one(&self.shared_state.target, p, &opt);
        self.shared_state.stats.inc_exec_total();

        match ret {
            Ok(info) => {
                let mut ret = Ok(None);
                if info.call_infos.len() > idx && !info.call_infos[idx].branches.is_empty() {
                    let brs = info.call_infos[idx].branches.iter().copied().collect();
                    ret = Ok(Some(brs));
                }
                self.clear_vm_log();
                ret
            }
            Err(e) => {
                if let Some(crash) = self.check_vm(p, &e) {
                    self.handle_crash(p, crash)?;
                } else {
                    self.restart_exec()?;
                }
                Ok(None)
            }
        }
    }

    fn check_vm(&mut self, p: &Prog, e: &ExecError) -> Option<Vec<u8>> {
        fuzzer_debug!("failed to exec prog: {}", e);

        let crash_error = !matches!(
            e,
            ExecError::ProgSerialization(_) | ExecError::OutputParse(_)
        );
        if crash_error && !self.qemu.is_alive() {
            fuzzer_warn!(
                "QEMU not alive, kernel maybe crashed, last executed prog:\n{}",
                p.display(&self.shared_state.target)
            );
            let log = self.qemu.collect_crash_log().unwrap();
            Some(log)
        } else {
            None
        }
    }

    fn handle_crash(&mut self, p: &Prog, crash_log: Vec<u8>) -> anyhow::Result<()> {
        self.shared_state.stats.inc_crashes();
        let ret = extract_report(&self.config.report_config, p, &crash_log);
        match ret.as_deref() {
            Ok([report, ..]) => {
                let title = report.title.clone();
                fuzzer_info!("crash: {}", title);
                let need_repro = self
                    .shared_state
                    .crash
                    .save_new_report(&self.shared_state.target, report.clone())?;
                self.shared_state
                    .stats
                    .set_unique_crash(self.shared_state.crash.unique_crashes());
                if need_repro {
                    self.try_repro(&title, &crash_log)
                        .context("failed to repro")?;
                }
            }
            _ => {
                if !crash_log.is_empty() {
                    fuzzer_info!("failed to extract report, saving to raw logs",);
                    self.shared_state.crash.save_raw_log(&crash_log)?;
                }
            }
        }

        self.reboot_vm()
    }

    fn try_repro(&mut self, title: &str, crash_log: &[u8]) -> anyhow::Result<()> {
        if self.config.disable_repro || stop_soon() {
            return Ok(());
        }
        fuzzer_info!("trying to repro...",);
        self.shared_state.stats.inc_repro();
        self.shared_state.stats.dec_fuzzing();
        let history = self.run_history.make_contiguous();
        let now = Instant::now();
        let repro = repro(
            &self.config.repro_config,
            &self.shared_state.target,
            crash_log,
            history,
        )
        .context("failed to repro")?;
        self.shared_state.stats.dec_repro();
        self.shared_state.stats.inc_fuzzing();
        let cost = now.elapsed();
        if let Some(r) = repro.as_ref() {
            fuzzer_info!(
                "'{}' repro success, cost: {}s, c_repro: {}",
                title,
                cost.as_secs(),
                r.c_prog.is_some()
            );
        } else {
            fuzzer_info!("failed to repro '{}'", title);
        }

        self.shared_state.crash.repro_done(title, repro)
    }

    #[inline]
    fn record_execution(&mut self, p: &Prog, opt: &ExecOpt) {
        if self.run_history.len() >= HISTORY_CAPACITY {
            self.run_history.pop_front();
        }
        self.run_history.push_back((opt.clone(), p.clone()))
    }

    #[inline]
    fn clear_vm_log(&mut self) {
        thread_local! {
            static LAST_CLEAR: Cell<u64> = Cell::new(0)
        }
        let n = LAST_CLEAR.with(|v| {
            let n = v.get();
            v.set(n + 1);
            n
        });
        if n >= 16 {
            LAST_CLEAR.with(|v| {
                v.set(0);
            });
            self.qemu.reset();
        }
    }

    #[inline]
    fn restart_exec(&mut self) -> anyhow::Result<()> {
        let ret = retry_exec(|| {
            kill_syz(&self.qemu);
            self.executor.respawn()
        });
        if let Err(e) = ret {
            fuzzer_warn!("failed to respawn executor: {}", e);
            fuzzer_warn!("rebooting vm",);
            self.reboot_vm()
                .context("rebooting due to executor spawn failure")?;
        }
        Ok(())
    }

    #[inline]
    fn reboot_vm(&mut self) -> anyhow::Result<()> {
        let ret = prepare_exec_env(&mut self.config, &mut self.qemu, &mut self.executor)
            .context("failed to reboot");
        self.last_reboot = Instant::now();
        ret
    }

    fn maybe_reboot_vm(&mut self) -> anyhow::Result<()> {
        if stop_soon() {
            return Ok(());
        }
        let du = self.last_reboot.elapsed();
        if du >= Duration::from_secs(60 * 60) {
            fuzzer_info!("running for 1 hour, rebooting vm...",);
            self.reboot_vm()?;
            self.shared_state.stats.inc_vm_restarts();
        }
        Ok(())
    }
}

// 验证已执行的路径brs里是否有待验证的路径expected_addr
#[inline]
pub fn validate(expected_addr: &u64, brs: &HashSet<u32>) -> bool {
    // 这里需要一个验证的函数，检查brs中是否包含expected_addr
    // 假设brs中的u32是地址的某种表示形式
    // 问题在于，测试器捕获的执行地址都是只有低32位的，而syscallPair中却是64位的。
    // 需要将expected_addr转换成u32类型进行比较，即去掉高32位的1。
    let expected_addr_for_comparison = *expected_addr & 0xFFFF_FFFF_0000_0000;
    brs.contains(&(expected_addr_for_comparison as u32))
}

#[inline]
// pub fn has_intersection(configs1: &HashSet<String>, configs2: &HashSet<String>) -> bool {
//     // 遍历前面的所有 HashSet
//     if configs1.iter().any(|item| configs2.contains(item)) {
//             return true; // 一旦发现交集就立刻返回
//     }
//     false
// }
pub fn has_intersection(configs1: &HashMap<u32, HashSet<String>>, configs2: &HashMap<u32, HashSet<String>>) -> Vec<u32> {
    let mut result = Vec::<u32>::new();
    // 先总看一遍
    let _has_overlapping = false;
    let all_configs2: HashSet<&String> = configs2.values()
        .flat_map(|set| set.iter())
        .collect();
    for (addr, set1) in configs1.iter() {
        for config in set1.iter() {
            if all_configs2.contains(config) {
                result.push(*addr);
                break;
            }
        }
    }
    result
}