//! Relation learning algorithm.

use std::{arch::x86_64::_MM_EXCEPT_INEXACT, sync::RwLock};
use std::collections::HashSet;
use rand::Rng;

use crate::{prog::Prog, syscall::SyscallId, target::Target, HashMap};

use pest::iterators::Pair;
use serde::Deserialize;

type SyscallPair = (SyscallId, SyscallId);

#[derive(Deserialize, Debug)]
pub struct JsonEntry {
    Target: Vec<String>,
    Relate: Vec<String>,
    Addr: u64
}

#[derive(Debug)]
pub struct RelationWrapper {
    pub inner: RwLock<Relation>,
}

impl RelationWrapper {
    pub fn new(r: Relation) -> Self {
        Self {
            inner: RwLock::new(r),
        }
    }

    pub fn try_update<T>(&self, p: &Prog, idx: usize, pred: T) -> bool
    where
        T: FnMut(&Prog, usize) -> bool, // fn(new_prog: &Prog, index: usize) -> bool
    {
        let mut inner = self.inner.write().unwrap();
        inner.try_update(p, idx, pred)
    } 

    /// Return if `a` can influence the execution of `b`.
    #[inline]
    pub fn influence(&self, a: SyscallId, b: SyscallId) -> bool {
        let inner = self.inner.read().unwrap();
        inner.influence(a, b)
    }

    /// Return if `a` can be influenced by the execution of `b`.
    #[inline]
    pub fn influence_by(&self, a: SyscallId, b: SyscallId) -> bool {
        let inner = self.inner.read().unwrap();
        inner.influence_by(a, b)
    }

    /// Return the number of known relations.
    #[inline(always)]
    pub fn num(&self) -> usize {
        let inner = self.inner.read().unwrap();
        inner.num()
    }

    /// Return the paths(usually addresses) that relate syscall `a` and `b`.
    #[inline]
    pub fn relate_path(&self, a: SyscallId, b: SyscallId) -> Option<Vec<u64>> {
        let inner = self.inner.read().unwrap();
        inner.relate_path(a, b)
    }

    /// Validate the given path of (Syscall_a, Syscall_b).
    #[inline]
    pub fn update_validation(&self, a: SyscallId, b: SyscallId, expected_path: &u64) {
        let mut inner = self.inner.write().unwrap();
        inner.relate_path.entry((a, b)).or_insert_with(|| HashMap::<u64, u32>::new())
            .entry(expected_path.clone()).and_modify(|e| *e += 1).or_insert(1);
        // inner.relate_path.entry((a, b)).or_insert_with(|| HashMap::<u64, u32>::new())
        //     .insert(expected_path.clone(), update_value);
        if *(inner.relate_path.get(&(a, b)).unwrap().get(expected_path).unwrap()) > 1 {
            println!("Successfully validated ( {:}, {:} ) at addr: {:}", a, b, expected_path);
        }
        // 别忘了验证后，把这个新关系加进去（如果没有的话）
        inner.push_ordered(a, b);
    }

    /// 检查当前的系统调用对是显式依赖还是隐式依赖。
    /// 注：这个系统调用对必须是依赖对。
    #[inline]
    pub fn is_explicit_dependency(&self, target: &Target, a: SyscallId, b: SyscallId) -> bool {
        Relation::calculate_influence(target, a, b)
    }

    /// 返回显式/隐式的权重
    #[inline]
    pub fn dependency_ratio(&self) -> f32 {
        let inner = self.inner.read().unwrap();
        inner.dependency_ratio
    }
}

/// Influence relations between syscalls.
#[derive(Debug, Clone)]
pub struct Relation {
    influence: HashMap<SyscallId, Vec<SyscallId>>,
    influence_by: HashMap<SyscallId, Vec<SyscallId>>,
    relate_path: HashMap::<SyscallPair, HashMap<u64, u32>>,
    n: usize,
    explicit_num: u32,
    implicit_num: u32,
    dependency_ratio: f32,
}

impl Relation {
    /// Create initial relations based on syscall type information.
    pub fn new(target: &Target, json_path: Option<&str>, open_explicit: bool, explicit_ratio: f32, implicit_ratio: f32) -> Self {
        // 基于系统调用描述符建立起来的显式依赖关系
        let influence: HashMap<SyscallId, Vec<SyscallId>> = target
            .enabled_syscalls()
            .iter()
            .map(|syscall| (syscall.id(), Vec::new()))
            .collect();
        let influence_by = influence.clone();
        let mut relate_path = HashMap::<SyscallPair, HashMap<u64, u32>>::new();
        let mut r = Relation {
            influence,
            influence_by,
            relate_path,
            n: 0,
            explicit_num: 0,
            implicit_num: 0,
            dependency_ratio: 1.0,
        };
        let mut explicit_pairs = HashSet::new();
        let mut generate_dependency: f32 = 0.0;
        let mut rng = rand::thread_rng();
        // 如果想测试只有config-based静态分析的依赖的效果，就把open_explicit设成false
        if open_explicit {
            for i in target.enabled_syscalls().iter().map(|s| s.id()) {
                for j in target.enabled_syscalls().iter().map(|s| s.id()) {
                    if i != j && Self::calculate_influence(target, i, j) {
                        // 随机生成一个0-1间的f32类型随机数，决定是否添加该依赖
                        generate_dependency = rng.gen_range(0.0..1.0);
                        if generate_dependency < explicit_ratio {
                            r.push_ordered(i, j);
                            explicit_pairs.insert((i, j));
                        }
                    }
                }
            }
            println!("Length of explicit depndencies: {:}", explicit_pairs.len());
            r.explicit_num = explicit_pairs.len() as u32;
            drop(explicit_pairs);
        }

        // 查询两个系统调用是否有依赖关系
        // let syscall_a = "getpid";
        // let syscall_b = "read";
        // let a_id = target.syscall_of_name(syscall_a);
        // let b_id = target.syscall_of_name(syscall_b);
        // println!("{:} and {:} is related? {:}", syscall_a, syscall_b, r.influence(a_id.unwrap().id(), b_id.unwrap().id()));

        // 加载syscallPair.json，注入额外的关系
        if let Some(path) = json_path {
            if let Err(e) = r.load_json_relations(path, target, implicit_ratio) {
                eprintln!("Failed to load JSON relations from {}: {}", path, e);
            }
        } else {
            log::info!("No syscallPair specified. Using syscall type information only.");
        }

        r
    }

    /// 私有方法：从JSON里加载关系
    fn load_json_relations(&mut self, path: &str, target: &Target, implicit_ratio: f32) -> Result<(), Box<dyn std::error::Error>> {
        use std::fs::File;
        use std::io::Read;

        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let entries: Vec<JsonEntry> = serde_json::from_str(&contents)?;

        let mut implicit_pairs = HashSet::new();
        for entry in entries {
            // 解析地址
            let addr = entry.Addr;
            // 先解析Target，从syscall名到SyscallId
            let target_syscalls: Vec<SyscallId> = entry.Target.iter()
                .filter_map(|s| target.syscall_of_name(s).map(|syscall| syscall.id()))
                .collect();
            // 再解析Relate，同样从syscall名到SyscallId
            let relate_syscalls: Vec<SyscallId> = entry.Relate.iter()
                .filter_map(|s| target.syscall_of_name(s).map(|syscall| syscall.id()))
                .collect();
            // 建立关系并存储
            let mut rng = rand::thread_rng();
            if !target_syscalls.is_empty() && !relate_syscalls.is_empty() {
                for a in &target_syscalls {
                    for b in &relate_syscalls {
                        if a != b {
                            if !self.influence(*a, *b) {
                                implicit_pairs.insert((*a, *b));
                            }
                            // 随机生成一个0-1间的f32类型随机数，决定是否添加该依赖
                            let mut generate_dependency = rng.gen_range(0.0..1.0);
                            if generate_dependency < implicit_ratio {
                                self.push_ordered(*a, *b);

                                let key = (*a, *b);
                                let paths = self.relate_path.entry(key).or_insert_with(|| HashMap::<u64, u32>::new());
                                paths.insert(addr, 0);
                            }
                        }
                    }
                }
            }
        }
        println!("Length of implicit dependencies: {:}", implicit_pairs.len());
        self.implicit_num = implicit_pairs.len() as u32;
        if self.implicit_num != 0 {
            let ratio = self.explicit_num as f32 / self.implicit_num as f32;
            if ratio != 0.0 {
                self.dependency_ratio = ratio;
            }
        }
        drop(implicit_pairs);
        Ok(())
    }

    /// Calculate if syscall `a` can influence the execution of syscall `b` based on
    /// input/output resources.
    ///
    /// Syscall `a` can influcen syscall `b` when any resource output by `a` is subtype
    /// of resources input by `b`. For example, syscall `a` outputs resource `sock`, syscall
    /// `b` takes resource `fd` as input, then `a` can influence `b`, because `sock` is
    /// subtype of `fd`. In contrast, if `b` takes `sock_ax25` as input, then the above
    /// conlusion maybe wrong (return false), because `sock` is not subtype of `sock_ax25` and
    /// the output resource of `a` maybe useless for `b`. For the latter case, the relation
    /// should be judged with dynamic method.
    pub fn calculate_influence(target: &Target, a: SyscallId, b: SyscallId) -> bool {
        let output_res_a = target.syscall_output_res(a);
        let input_res_b = target.syscall_input_res(b);

        !output_res_a.is_empty()
            && !input_res_b.is_empty()
            && input_res_b.iter().any(|input_res| {
                output_res_a
                    .iter()
                    .any(|output_res| target.res_sub_tys(input_res).contains(output_res))
            })
    }

    /// Detect relations by removing calls dynamically.
    ///
    /// The algorithm removes call before call `idx `of `p` and calls the callback
    /// `changed` to verify if the removal changed the feedback of adjacent call.
    /// For example, for prog [open, read], the algorithm removes `open` first and calls `changed`
    /// with the index of `open` (0 in this case) and the `new_prog`. The index of `open` equals to
    /// the index of `read` in the new `prog` and the callback `changed` should judge the feedback
    /// changes of the `index` call after the execution of `new_prog`. Finally, `try_update` returns
    /// the number of detected new relations.
    /// 人话：分析p[idx]系统调用的依赖时，尝试删除p[idx-1]，如果删除后p[idx]的覆盖变了（变大还是变小？如果变大怎么办，岂不说明是反向关系？这个论文没有考虑），就说明p[idx]依赖p[idx-1]，否则就不依赖。
    /// 补充：这里存在一个问题：如果种子最小化后只剩下ABC，他只会认为依赖关系是A->B->C，而不会认为A->C且B->C，这可能会导致分析的配置项关系是错误的。而有了配置项后，这个问题会被解决。
    /// 怎么解决？参见我们的函数try_update_by_config。
    pub fn try_update<T>(&mut self, p: &Prog, idx: usize, mut pred: T) -> bool
    where
        T: FnMut(&Prog, usize) -> bool, // fn(new_prog: &Prog, index: usize) -> bool
    {
        let mut found_new = false;
        if idx == 0 {
            return found_new;
        }
        let a = &p.calls[idx - 1];
        let b = &p.calls[idx];

        // 想用这个方法来推测1-假阳性的值
        // 在update前，看minimize后的种子（此时它一定包含依赖对）的依赖对是否本就存在，如果本就存在且有relate_path，那就是隐式依赖
        // let mut is_implicit_dependency = false;
        // if let Some(_relate_path) = self.relate_path(a.sid(), b.sid()) {
        //     is_implicit_dependency = true;
        // }
        // println!("Found relation in seeds: {:} -> {:} {:} {:}", a.sid(), b.sid(), self.influence(a.sid(), b.sid()), is_implicit_dependency);

        if !self.influence(a.sid(), b.sid()) {
            let new_p = p.remove_call(idx - 1);
            if pred(&new_p, idx - 1) {
                self.push_ordered(a.sid(), b.sid());
                found_new = true;
            }
        }

        found_new
    }

    /// Return if `a` can influence the execution of `b`.
    #[inline]
    pub fn influence(&self, a: SyscallId, b: SyscallId) -> bool {
        self.influence[&a].binary_search(&b).is_ok()
    }

    /// Return if `a` can be influenced by the execution of `b`.
    #[inline]
    pub fn influence_by(&self, a: SyscallId, b: SyscallId) -> bool {
        self.influence_by[&a].binary_search(&b).is_ok()
    }

    /// Return the known syscalls that `a` can influence.
    #[inline]
    pub fn influence_of(&self, a: SyscallId) -> &[SyscallId] {
        &self.influence[&a]
    }

    /// Return the known syscalls that can influence `a`.
    #[inline]
    pub fn influence_by_of(&self, a: SyscallId) -> &[SyscallId] {
        &self.influence_by[&a]
    }

    /// Return the paths(usually addresses) that relate syscall `a` and `b`.
    #[inline]
    pub fn relate_path(&self, a: SyscallId, b: SyscallId) -> Option<Vec<u64>> {
        let res = self.relate_path.get(&(a, b)).map(|map| map.keys().copied().collect());
        res
    }

    /// Return the paths(usually addresses) and verification number that relate syscall `a` and `b`.
    #[inline]
    pub fn relate_path_with_verification_num(&self, a: SyscallId, b: SyscallId) -> Option<&HashMap<u64, u32>> {
        let res = self.relate_path.get(&(a, b));
        res
    }

    #[inline(always)]
    pub fn influences(&self) -> &HashMap<SyscallId, Vec<SyscallId>> {
        &self.influence
    }

    #[inline(always)]
    pub fn influences_by(&self) -> &HashMap<SyscallId, Vec<SyscallId>> {
        &self.influence_by
    }

    /// Return the number of known relations.
    #[inline(always)]
    pub fn num(&self) -> usize {
        self.n
    }

    pub fn insert(&mut self, a: SyscallId, b: SyscallId) -> bool {
        let old = self.num();
        self.push_ordered(a, b);
        old != self.num()
    }

    fn push_ordered(&mut self, a: SyscallId, b: SyscallId) {
        let rs_a = self.influence.get_mut(&a).unwrap();
        if let Err(idx) = rs_a.binary_search(&b) {
            self.n += 1;
            rs_a.insert(idx, b);
        }
        let rs_b = self.influence_by.get_mut(&b).unwrap();
        if let Err(idx) = rs_b.binary_search(&a) {
            rs_b.insert(idx, a);
        }
    }
}
