use healer_core::relation::{Relation, RelationWrapper};
use healer_core::config2code::Config2Code;
use healer_core::verbose::set_verbose;
use structopt::StructOpt;
use syz_wrapper::sys::load_target;
use std::process::exit;

#[derive(Debug, StructOpt)]
struct Settings {
    /// Target to inspect.
    #[structopt(long, default_value = "linux/amd64")]
    target: String,
    /// Number of progs to generate.
    #[structopt(long, short, default_value = "1")]
    n: usize,
    /// Verbose.
    #[structopt(long)]
    verbose: bool,
}

fn main() {
    let settings = Settings::from_args();
    env_logger::init();
    set_verbose(settings.verbose);
    let target = load_target(&settings.target).unwrap_or_else(|e| {
        eprintln!("failed to load target: {}", e);
        exit(1)
    });
    let relation = Relation::new(&target, Some("syscallPair.json"));
    let config2code = Config2Code::new(Some("codeblock_config.json"), Some("config_tree.json"));

    let configs = config2code.get_config("/home/jiakai/tmp/linux/drivers/ata/libata-core.c", &4550);
    match configs {
        Some(configs) => {
            // 按道理应该返回config_has_dma
            println!("Configs for the given source and line: {:?}", configs);
        }
        None => {
            println!("No configs found for the given source and line.");
        }
    }

    let config1 = "CONFIG_INITRAMFS_ROOT_UID";
    let config2 = "CONFIG_INITRAMFS_SOURCE";
    let config3 = "CONFIG_SANGUOSHA";
    // 按道理应当分别是true，false
    println!("Does {} influence {}? {}\n", config1, config2, config2code.is_related(config1, config2));
    println!("Does {} influence {}? {}\n", config2, config3, config2code.is_related(config2, config3));

    // for (src, data) in config2code.code2config.iter() {
    //     println!("Source: {}", src);
    //     for (range, configs) in data.iter() {
    //         println!("  Range: {}, Configs: {:?}", range, configs);
    //     }
    // }

    // for (parent, children) in config2code.config_tree.iter() {
    //     println!("Config: {}, Children: {:?}", parent, children);
    // }
}