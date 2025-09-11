//! Sequence level mutation.
use super::{foreach_call_arg_mut, restore_partial_ctx, restore_res_ctx};
use crate::{
    context::Context,
    corpus::CorpusWrapper,
    gen::{gen_one_call, prog_len_range},
    prog::{Call, Prog},
    select::select_with_calls,
    syscall::SyscallId,
    value::ResValueKind,
    HashMap, RngType,
};
use rand::prelude::*;
use std::sync::atomic::{Ordering, AtomicBool};

/// Select a prog from `corpus` and splice it with calls in the `ctx` randomly.
pub fn splice(ctx: &mut Context, corpus: &CorpusWrapper, rng: &mut RngType, current_period: bool, dependency_choice: bool) -> bool {
    if ctx.calls.is_empty() || ctx.calls.len() > prog_len_range().end || corpus.is_empty() {
        return false;
    }

    let p = corpus.select_one(rng).unwrap();
    let mut calls = p.calls;
    // mapping resource id of `calls`, continue with current `ctx.next_res_id`
    mapping_res_id(ctx, &mut calls);
    restore_partial_ctx(ctx, &calls);
    let idx = rng.gen_range(0..=ctx.calls.len());
    debug_info!(
        "splice: splicing {} call(s) to location {}",
        calls.len(),
        idx
    );
    ctx.calls.splice(idx..idx, calls);
    true
}

/// Insert calls to random location of ctx's calls.
pub fn insert_calls(ctx: &mut Context, _corpus: &CorpusWrapper, rng: &mut RngType, current_period: bool, dependency_choice: bool) -> bool {
    if ctx.calls.len() > prog_len_range().end {
        return false;
    }

    let idx = rng.gen_range(0..=ctx.calls.len());
    restore_res_ctx(ctx, idx); // restore the resource information before call `idx`
    let sid = select_call_to(ctx, rng, idx, current_period, dependency_choice);
    debug_info!(
        "insert_calls: inserting {} to location {}",
        ctx.target.syscall_of(sid).name(),
        idx
    );
    let mut calls_backup = std::mem::take(&mut ctx.calls);
    gen_one_call(ctx, rng, sid);
    let new_calls = std::mem::take(&mut ctx.calls);
    debug_info!("insert_calls: {} call(s) inserted", new_calls.len());
    calls_backup.splice(idx..idx, new_calls);
    ctx.calls = calls_backup;
    true
}

pub fn remove_call(ctx: &mut Context, _corpus: &CorpusWrapper, rng: &mut RngType, current_period: bool, dependency_choice: bool) -> bool {
    if ctx.calls.is_empty() {
        return false;
    }

    let idx = rng.gen_range(0..ctx.calls.len());
    let calls = std::mem::take(&mut ctx.calls);
    let mut p = Prog::new(calls);
    debug_info!("remove_call: removing call-{}", idx);
    p.remove_call_inplace(idx);
    ctx.calls = p.calls;
    true
}

/// 依据选择表，选择一个新的系统调用插入到位置 `idx`
/// Select new call to location `idx`.
fn select_call_to(ctx: &mut Context, rng: &mut RngType, idx: usize, current_period: bool, dependency_choice: bool) -> SyscallId {
    let mut candidates: HashMap<SyscallId, u64> = HashMap::new();
    let r = ctx.relation().inner.read().unwrap();
    let calls = ctx.calls();

    // first, consider calls that can be influenced by calls before `idx`.
    // If a call has verified path, improve its weight.
    for sid in calls[..idx].iter().map(|c| c.sid()) {
        for candidate in r.influence_of(sid).iter().copied() {
            let entry = candidates.entry(candidate).or_default();
            // 利用阶段
            if current_period == false {
                // 如果显式依赖的收益高
                if dependency_choice == true {
                    *entry += 1;
                    if let Some(path_and_verification_number) = r.relate_path_with_verification_num(candidate, sid) {
                        for number in path_and_verification_number.values() {
                            *entry += *number as u64;
                        }
                    }
                }
                // 如果是隐式依赖 
                else {
                    // 如果隐式依赖的收益高
                    if dependency_choice == false {
                        if !(ctx.relation().is_explicit_dependency(ctx.target(), sid, candidate)) {
                            *entry += 1;
                            if let Some(path_and_verification_number) = r.relate_path_with_verification_num(candidate, sid) {
                                for number in path_and_verification_number.values() {
                                    *entry += *number as u64;
                                }
                            }
                        }
                    }
                }
            }
            // 探索阶段，谁都用
            else {
                *entry += 1;
                if let Some(path_and_verification_number) = r.relate_path_with_verification_num(candidate, sid) {
                    for number in path_and_verification_number.values() {
                        *entry += *number as u64;
                    }
                }
            }
        }
    }

    // then, consider calls that can be influence calls after `idx`.
    // If a call has verified path, improve its weight.
    if idx != calls.len() {
        for sid in calls[idx..].iter().map(|c| c.sid()) {
            for candidate in r.influence_of(sid).iter().copied() {
                let entry = candidates.entry(candidate).or_default();
                // 利用阶段
                if current_period == false {
                    // 如果显式依赖的收益高
                    if dependency_choice == true {
                        // 这里加一个，让隐式依赖的相对权重大一点
                        if !(ctx.relation().is_explicit_dependency(ctx.target(), sid, candidate)) {
                            *entry += (1.0 * ctx.relation().dependency_ratio()) as u64;
                        }
                        if let Some(path_and_verification_number) = r.relate_path_with_verification_num(candidate, sid) {
                            for number in path_and_verification_number.values() {
                                *entry += *number as u64;
                            }
                        }
                    }
                    // 如果是隐式依赖 
                    else {
                        // 如果隐式依赖的收益高
                        if dependency_choice == false {
                            if !(ctx.relation().is_explicit_dependency(ctx.target(), sid, candidate)) {
                                *entry += 1;
                                if let Some(path_and_verification_number) = r.relate_path_with_verification_num(candidate, sid) {
                                    for number in path_and_verification_number.values() {
                                        *entry += *number as u64;
                                    }
                                }
                            }
                        }
                    }
                }
                // 探索阶段，谁都用
                else {
                    if !(ctx.relation().is_explicit_dependency(ctx.target(), sid, candidate)) {
                        *entry += (1.0 * ctx.relation().dependency_ratio()) as u64;
                    }
                    if let Some(path_and_verification_number) = r.relate_path_with_verification_num(candidate, sid) {
                        for number in path_and_verification_number.values() {
                            *entry += *number as u64;
                        }
                    }
                }
            }
        }
    }

    let candidates: Vec<(SyscallId, u64)> = candidates.into_iter().collect();
    // for syscallid, weight in candidates.iter()
    if let Ok(candidate) = candidates.choose_weighted(rng, |candidate| candidate.1) {
        candidate.0
    } else {
        // failed to select with relation, use normal strategy.
        // 如果这里把select_random_syscall的概率改为0，就意味着不会选除了依赖关系以外的任何系统调用.
        // println!("No relation.");
        select_with_calls(ctx, rng)
    }
}

/// Mapping resource id of `calls`, make sure all `res_id` in `calls` is bigger then current `next_res_id`
fn mapping_res_id(ctx: &mut Context, calls: &mut [Call]) {
    for call in calls {
        foreach_call_arg_mut(call, |val| {
            if let Some(val) = val.as_res_mut() {
                match &mut val.kind {
                    ResValueKind::Ref(id) | ResValueKind::Own(id) => *id += ctx.next_res_id,
                    ResValueKind::Null => (),
                }
            }
        });
        for ids in call.generated_res.values_mut() {
            for id in ids {
                *id += ctx.next_res_id;
            }
        }
        for ids in call.used_res.values_mut() {
            for id in ids {
                *id += ctx.next_res_id;
            }
        }
    }
}
