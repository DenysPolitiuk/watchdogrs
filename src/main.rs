use clap::{App, Arg};
use ctrlc;
use futures::StreamExt;
use heim::{process, process::Process, units::information};
use tokio::time::delay_for;

use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::Duration;

enum MemoryUnit {
    B,
    KB,
    MB,
    GB,
}

impl MemoryUnit {
    fn get_type(&self) -> &str {
        match self {
            MemoryUnit::B => "B",
            MemoryUnit::KB => "KB",
            MemoryUnit::MB => "MB",
            MemoryUnit::GB => "GB",
        }
    }

    fn get_value_string(&self, value: u64) -> String {
        format!("{} {}", value, self.get_type())
    }
}

enum WatchAction {
    Kill,
    Print,
}

impl WatchAction {
    fn is_valid_action(action_text: &str) -> bool {
        if action_text == "kill" || action_text == "print" {
            true
        } else {
            false
        }
    }

    fn new(action_text: &str) -> Option<WatchAction> {
        if !WatchAction::is_valid_action(action_text) {
            None
        } else {
            if action_text == "kill" {
                Some(WatchAction::Kill)
            } else if action_text == "print" {
                Some(WatchAction::Print)
            } else {
                None
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .arg(
            Arg::with_name("pid")
                .index(1)
                .required(true)
                .help("pid or executable to check"),
        )
        .arg(
            Arg::with_name("children")
                .short("c")
                .long("children")
                .help("include processes children"),
        )
        .arg(
            Arg::with_name("details")
                .short("d")
                .long("details")
                .help("print more information about the process"),
        )
        .arg(
            Arg::with_name("byte")
                .conflicts_with_all(&["kilobyte", "gigabyte"])
                .short("b")
                .long("byte")
                .help("use bytes to display memory usage"),
        )
        .arg(
            Arg::with_name("kilobyte")
                .conflicts_with_all(&["byte", "gigabyte"])
                .short("k")
                .long("kilobyte")
                .help("use kilobytes to display memory usage"),
        )
        .arg(
            Arg::with_name("gigabyte")
                .conflicts_with_all(&["kilobyte", "byte"])
                .short("g")
                .long("gigabyte")
                .help("use gigabytes to display memory usage"),
        )
        .arg(
            Arg::with_name("watch")
                .conflicts_with("details")
                .requires("limit")
                .short("w")
                .long("watch")
                .help("watch for process memory usage"),
        )
        .arg(
            Arg::with_name("limit")
                .requires("watch")
                .short("l")
                .long("limit")
                .takes_value(true)
                .help("limit of memory process can have before process is actioned on")
        )
        .arg(
            Arg::with_name("interval")
            .requires("watch")
            .short("i")
            .long("interval")
            .takes_value(true)
            .help("interval to check memory on a process in seconds, default 1 sec")
        )
        .arg(
            Arg::with_name("action")
            .requires_all(&["watch", "limit"])
            .short("a")
            .long("action")
            .takes_value(true)
            .help("action to take when the limit is hit, default print\npossible values:\n\tprint - print process info\n\tkill - kill process")
            .validator(is_valid_action)
        )
        .get_matches();
    let target = matches.value_of("pid").unwrap();
    let target_pid = target.parse::<u32>();

    let unit_to_use = if matches.is_present("byte") {
        MemoryUnit::B
    } else if matches.is_present("kilobyte") {
        MemoryUnit::KB
    } else if matches.is_present("gigabyte") {
        MemoryUnit::GB
    } else {
        MemoryUnit::MB
    };

    let include_children = matches.is_present("children");
    let is_details = matches.is_present("details");
    let is_watch = matches.is_present("watch");
    let limit_value = matches.value_of("limit").map(|v| v.parse::<u64>().ok());
    let interval_value = matches
        .value_of("interval")
        .or(Some("1"))
        .unwrap()
        .parse::<u64>()
        .expect("invalid interval value");
    let action_type = match matches.value_of("action") {
        None => Some(WatchAction::Print),
        Some(action) => WatchAction::new(action),
    }
    .expect("invalid action");

    if is_watch {
        let limit_value = limit_value
            .expect("missing limit value")
            .expect("invalid limit value");
        // TODO: add optional children inclusion in processes ram usage
        match target_pid {
            Ok(target_pid) => {
                watch_process(
                    target_pid as i32,
                    interval_value,
                    action_type,
                    limit_value,
                    &unit_to_use,
                )
                .await?
            }
            Err(_) => {
                watch_process_named(
                    target,
                    interval_value,
                    action_type,
                    limit_value,
                    &unit_to_use,
                )
                .await?
            }
        };
    } else {
        println!(
            "{}",
            match target_pid {
                Ok(target_pid) => {
                    process_ram_usage(
                        target_pid as i32,
                        is_details,
                        include_children,
                        &unit_to_use,
                    )
                    .await?
                    .0
                }
                Err(_) => {
                    process_ram_usage_named(target, is_details, include_children, unit_to_use)
                        .await?
                }
            }
        );
    }

    Ok(())
}

fn is_valid_action(val: String) -> Result<(), String> {
    if !WatchAction::is_valid_action(&val) {
        Err(String::from("invalid action"))
    } else {
        Ok(())
    }
}

async fn watch_process(
    pid: i32,
    interval: u64,
    action: WatchAction,
    limit: u64,
    unit_type: &MemoryUnit,
) -> Result<(), Box<dyn Error>> {
    let exit = Arc::new(Mutex::new(false));
    let e = exit.clone();
    let _ = ctrlc::set_handler(move || {
        let mut exit = e.lock().unwrap();
        *exit = true;
    });

    while !*exit.lock().unwrap() {
        let rss = process_ram_usage(pid, false, false, unit_type).await?;
        if rss.1 >= limit {
            match action {
                WatchAction::Print => println!(
                    "process {} reached limit {}{}, currently at {}",
                    pid,
                    limit,
                    unit_type.get_type(),
                    rss.0
                ),
                WatchAction::Kill => {
                    terminate_process(pid).await?;
                    break;
                }
            };
        }
        delay_for(Duration::from_secs(interval)).await;
    }

    Ok(())
}

async fn watch_process_named(
    name: &str,
    interval: u64,
    action: WatchAction,
    limit: u64,
    unit_type: &MemoryUnit,
) -> Result<(), Box<dyn Error>> {
    let processes = get_all_processes().await?;
    let possible_processes = get_process_from_name(name, &processes).await?;

    if possible_processes.len() > 1 {
        println!("more than 1 possible process with given name");
        println!(
            "found {} processes matching name {}",
            possible_processes.len(),
            name
        );
        return Ok(());
    } else if possible_processes.is_empty() {
        println!("did not find process with name {}", name);
        return Ok(());
    }

    let mut pid = -1;
    for (a_pid, _) in possible_processes {
        pid = a_pid;
        // should only be one, should be handled with checks before
        break;
    }

    watch_process(pid, interval, action, limit, unit_type).await?;

    Ok(())
}

async fn terminate_process(pid: i32) -> Result<(), Box<dyn Error>> {
    process::get(pid).await?.terminate().await?;
    Ok(())
}

async fn process_ram_usage(
    pid: i32,
    print_details: bool,
    include_children: bool,
    unit: &MemoryUnit,
) -> Result<(String, u64), Box<dyn Error>> {
    let process = process::get(pid).await?;
    let mut rss = get_memory_value(&process, &unit).await?;

    if print_details {
        print_process_info(&process, &unit).await?;
    }

    if !include_children {
        return Ok((unit.get_value_string(rss), rss));
    }

    let processes = get_all_processes().await?;
    let all_children = get_all_children(&processes, pid);
    if let Some(children) = all_children {
        for child in &children {
            rss += get_memory_value(&child, &unit).await?;
            if print_details {
                print_process_info(&child, &unit).await?;
                println!("");
            }
        }
    }

    Ok((format!("{} {}", rss, unit.get_type()), rss))
}

async fn get_process_from_name<'a>(
    name: &str,
    processes: &'a Vec<(Process, i32)>,
) -> Result<HashMap<i32, &'a Process>, Box<dyn Error>> {
    let self_process = process::current().await?.pid();

    let mut results = HashMap::new();

    for (process, _) in processes {
        let process_name = process.name().await?;
        let process_command = process
            .command()
            .await?
            .to_os_string()
            .into_string()
            .expect("unable to convert OsStrin to String");

        if process_name.contains(name) || process_command.contains(name) {
            if process.pid() == self_process {
                continue;
            }
            results.insert(process.pid(), process);
        }
    }

    Ok(results)
}

async fn process_ram_usage_named(
    name: &str,
    print_details: bool,
    include_children: bool,
    unit: MemoryUnit,
) -> Result<String, Box<dyn Error>> {
    let processes = get_all_processes().await?;
    let results = get_process_from_name(name, &processes).await?;
    let mut final_results: HashMap<i32, &Process> = HashMap::new();

    if include_children {
        for (pid, process) in &results {
            final_results.insert(*pid, process);
            match get_all_children(&processes, process.pid()) {
                None => (),
                Some(children) => {
                    for child in children {
                        final_results.entry(child.pid()).or_insert(child);
                    }
                }
            }
        }
    } else {
        final_results = results;
    }

    let mut rss = 0;
    for process in final_results.values() {
        rss += get_memory_value(&process, &unit).await?;
        if print_details {
            print_process_info(&process, &unit).await?;
            println!("");
        }
    }

    Ok(format!("{} {}", rss, unit.get_type()))
}

fn get_all_children(processes: &Vec<(Process, i32)>, parent_pid: i32) -> Option<Vec<&Process>> {
    match get_children(processes, parent_pid) {
        None => None,
        Some(children) => {
            let mut all_children = vec![];
            all_children.extend(&children);
            for child in children {
                match get_all_children(processes, child.pid()) {
                    None => (),
                    Some(mut children) => all_children.append(&mut children),
                };
            }
            Some(all_children)
        }
    }
}

async fn get_all_processes() -> Result<Vec<(Process, i32)>, Box<dyn Error>> {
    let processes = process::processes().await?;
    futures::pin_mut!(processes);
    let mut all_processes = vec![];
    while let Some(p) = processes.next().await {
        if let Some(p) = p.ok() {
            let parent_pid = p.parent_pid().await?;
            all_processes.push((p, parent_pid));
        }
    }

    Ok(all_processes)
}

fn get_children(processes: &Vec<(Process, i32)>, parent_pid: i32) -> Option<Vec<&Process>> {
    let mut result = vec![];
    for (process, process_parent_pid) in processes {
        if *process_parent_pid == parent_pid {
            result.push(process);
        }
    }

    if result.len() == 0 {
        None
    } else {
        Some(result)
    }
}

async fn print_process_info(
    process: &Process,
    unit_type: &MemoryUnit,
) -> Result<(), Box<dyn Error>> {
    println!("{:>10} {:?}", "PID", process.pid());
    println!("{:>10} {:?}", "Parent pid", process.parent_pid().await?);
    println!("{:>10} {:?}", "Name", process.name().await?);
    println!("{:>10} {:?}", "Exe", process.exe().await?);
    println!("{:>10} {:?}", "Command", process.command().await?);
    println!(
        "{:>10} {}",
        "RSS",
        unit_type.get_value_string(get_memory_value(&process, &unit_type).await?),
    );
    println!("{:>10} {:?}", "Status", process.status().await?);

    Ok(())
}

async fn get_memory_value(
    process: &Process,
    unit_type: &MemoryUnit,
) -> Result<u64, Box<dyn Error>> {
    match unit_type {
        MemoryUnit::B => Ok(process.memory().await?.rss().get::<information::byte>()),
        MemoryUnit::KB => Ok(process.memory().await?.rss().get::<information::kilobyte>()),
        MemoryUnit::MB => Ok(process.memory().await?.rss().get::<information::megabyte>()),
        MemoryUnit::GB => Ok(process.memory().await?.rss().get::<information::gigabyte>()),
    }
}
