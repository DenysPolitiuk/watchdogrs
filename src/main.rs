use clap::{App, Arg};
use futures::StreamExt;
use heim::{process, process::Process, units::information};

use std::collections::HashMap;
use std::error::Error;

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
        .get_matches();
    let target = matches.value_of("pid").unwrap();
    let target_pid = target.parse::<u32>();

    let include_children = matches.is_present("children");
    let is_details = matches.is_present("details");

    let rss = match target_pid {
        Ok(target_pid) => {
            if include_children {
                process_ram_usage_full(target_pid as i32, is_details).await?
            } else {
                process_ram_usage_single(target_pid as i32, is_details).await?
            }
        }
        Err(_) => process_ram_usage_named(target, is_details, include_children).await?,
    };

    println!("{} MB", rss);

    Ok(())
}

async fn process_ram_usage_single(pid: i32, print_details: bool) -> Result<u64, Box<dyn Error>> {
    let process = process::get(pid).await?;
    let rss = process.memory().await?.rss().get::<information::megabyte>();

    if print_details {
        print_process_info(&process).await?;
        println!("");
    }

    Ok(rss)
}

async fn process_ram_usage_full(pid: i32, print_details: bool) -> Result<u64, Box<dyn Error>> {
    let processes = get_all_processes().await?;
    let process = process::get(pid).await?;
    let mut rss = process.memory().await?.rss().get::<information::megabyte>();

    if print_details {
        print_process_info(&process).await?;
    }

    let all_children = get_all_children(&processes, pid);
    if let Some(children) = all_children {
        for child in &children {
            rss += child.memory().await?.rss().get::<information::megabyte>();
            if print_details {
                print_process_info(&child).await?;
                println!("");
            }
        }
    }

    Ok(rss)
}

async fn process_ram_usage_named(
    name: &str,
    print_details: bool,
    include_children: bool,
) -> Result<u64, Box<dyn Error>> {
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
        rss += process.memory().await?.rss().get::<information::megabyte>();
        if print_details {
            print_process_info(&process).await?;
            println!("");
        }
    }

    Ok(rss)
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

async fn print_process_info(process: &Process) -> Result<(), Box<dyn Error>> {
    println!("{:>10} {:?}", "PID", process.pid());
    println!("{:>10} {:?}", "Parent pid", process.parent_pid().await?);
    println!("{:>10} {:?}", "Name", process.name().await?);
    println!("{:>10} {:?}", "Exe", process.exe().await?);
    println!("{:>10} {:?}", "Command", process.command().await?);
    println!(
        "{:>10} {:?} MB",
        "RSS",
        process.memory().await?.rss().get::<information::megabyte>()
    );
    println!("{:>10} {:?}", "Status", process.status().await?);

    Ok(())
}
