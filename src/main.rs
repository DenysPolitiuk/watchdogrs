use clap::{App, Arg};
use futures::StreamExt;
use heim::{process, process::Process, units::information};

use std::collections::HashMap;
use std::error::Error;

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

    println!(
        "{}",
        match target_pid {
            Ok(target_pid) => {
                process_ram_usage(target_pid as i32, is_details, include_children, unit_to_use)
                    .await?
            }
            Err(_) => {
                process_ram_usage_named(target, is_details, include_children, unit_to_use).await?
            }
        }
    );

    Ok(())
}

async fn process_ram_usage(
    pid: i32,
    print_details: bool,
    include_children: bool,
    unit: MemoryUnit,
) -> Result<String, Box<dyn Error>> {
    let process = process::get(pid).await?;
    let mut rss = get_memory_value(&process, &unit).await?;

    if print_details {
        print_process_info(&process, &unit).await?;
    }

    if !include_children {
        return Ok(unit.get_value_string(rss));
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

    Ok(format!("{} {}", rss, unit.get_type()))
}

async fn process_ram_usage_named(
    name: &str,
    print_details: bool,
    include_children: bool,
    unit: MemoryUnit,
) -> Result<String, Box<dyn Error>> {
    let processes = get_all_processes().await?;
    let self_process = process::current().await?.pid();

    // need to use hashmaps because named search can find both a process and its children
    // which creates "double" entries
    let mut results = HashMap::new();

    for (process, _) in &processes {
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
