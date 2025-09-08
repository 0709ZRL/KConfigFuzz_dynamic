//! 配置项与源码间相互映射的相关代码
use std::fs::File;
use std::io::Read;
use serde::Deserialize;

use crate::HashMap;

#[derive(Debug, Clone)]
pub struct Config2Code {
    // 虽然该类名叫 Config2Code，但实际上它是从代码到配置的映射。
    // 这里的 key 是源码路径，value又是一个 HashMap，
    // key 是拼接成的代码行范围，value 是管辖这个代码块的所有配置项vector。
    pub code2config: HashMap<String, HashMap<String, Vec<String>>>,
    // 配置项间关系列表
    pub config_tree: HashMap<String, Vec<String>>,
}

impl Config2Code {
    // 加载位于 Code2ConfigSrc 的配置项与源码间映射关系的json文件。
    // 以及位于 ConfigTreeSrc 的配置项关系的json文件。
    pub fn new(Code2ConfigSrc: Option<&str>, ConfigTreeSrc: Option<&str>) -> Self {
        let mut code2config: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();
        let mut config_tree: HashMap<String, Vec<String>> = HashMap::new();
        // 这两个路径缺一个都不行，直接返回空关系，使HEALER走默认策略。
        if Code2ConfigSrc.is_none() || ConfigTreeSrc.is_none() {
            log::info!("Due to configuration files not provided, using default empty configuration.");
            return Self { code2config, config_tree };
        }
        
        let mut file_code2config = File::open(Code2ConfigSrc.unwrap()).expect("Failed to open code to config file");
        let mut file_config_tree = File::open(ConfigTreeSrc.unwrap()).expect("Failed to open config tree file");
        let mut contents1 = String::new();
        let mut contents2 = String::new();
        file_code2config.read_to_string(&mut contents1).expect("Failed to read code to config file");
        code2config = serde_json::from_str(&contents1)
            .expect("Failed to parse code to config JSON");
        file_config_tree.read_to_string(&mut contents2).expect("Failed to read config tree file");
        config_tree = serde_json::from_str(&contents2)
            .expect("Failed to parse config tree JSON");
        Self { 
            code2config, 
            config_tree
        }
    }

    // 给定一个源码路径和代码行，返回该代码行所属的配置项。
    #[inline]
    pub fn get_config(&self, src: &str, line: &u32) -> Option<Vec<String>> {
        // let res = Vec<String>::new();
        // 首先看数据库里有没有这个源码对应的数据
        let Some(code_map) = self.code2config.get(src) else {
            return None;
        };
        for (range, configs) in code_map.iter() {
            // 如果 range 是 “0”，证明这个文件都被配置项包裹。
            if range == "0" {
                return Some(configs.clone());
            }
            // 解析 range 字符串，格式为 "begin-end"。
            let (begin, end) : (u32, u32) = self.parseRange(range);
            if begin <= *line && *line <= end {
                return Some(configs.clone());
            }
        }
        None
    }

    // 给定一个配置项，返回它的子配置项。
    #[inline]
    pub fn get_child_config(&self, config: &str) -> Option<Vec<String>> {
        self.config_tree.get(config).cloned()
    }
    
    // 给定两个配置项，看他们是否相关。
    // 判断方法：先看是否相同，如果不是则看两个配置项是否互为父子关系。
    pub fn is_related(&self, config1: &str, config2: &str) -> bool {
        if config1 == config2 {
            return true;
        }
        // 检查 config1 是否是 config2 的子配置项，或反之。
        if let Some(children) = self.config_tree.get(config1) {
            if children.contains(&config2.to_string()) {
                return true;
            }
        }
        if let Some(children) = self.config_tree.get(config2) {
            if children.contains(&config1.to_string()) {
                return true;
            }
        }
        false
    }

    // 拆解字符串格式的行号范围到两个数值变量里
    fn parseRange(&self, range: &str) -> (u32, u32) {
        let parts: Vec<&str> = range.split('-').collect();
        if parts.len() == 2 {
            let begin = parts[0].parse::<u32>().unwrap_or(0);
            let end = parts[1].parse::<u32>().unwrap_or(0);
            (begin, end)
        } else {
            (0, 0) // 如果格式不正确，返回默认值
        }
    }
}