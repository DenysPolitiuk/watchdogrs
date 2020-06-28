use clap::{App, Arg};
use futures::StreamExt;
use heim::{process, process::Process, units::information};

use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .arg(
            Arg::with_name("pid")
                .index(1)
                .required(true)
                .help("pid to check"),
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
    let target_pid = matches
        .value_of("pid")
        .unwrap()
        .parse::<u32>()
        .expect("unable to parse pid value");
    let include_children = matches.is_present("children");
    let is_details = matches.is_present("details");

    let rss = if include_children {
        process_ram_usage_full(target_pid as i32, is_details).await?
    } else {
        process_ram_usage_single(target_pid as i32, is_details).await?
    };

    println!("{} MB", rss);

    Ok(())
}

async fn process_ram_usage_single(pid: i32, print_details: bool) -> Result<u64, Box<dyn Error>> {
    let process = process::get(pid).await?;
    let rss = process.memory().await?.rss().get::<information::megabyte>();

    if print_details {
        print_process_info(&process).await?;
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
                println!("");
                print_process_info(&child).await?;
            }
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
    println!("{:?}", process);
    println!("Name {:?}", process.name().await?);
    println!("Exe {:?}", process.exe().await?);
    println!("Command {:?}", process.command().await?);
    println!(
        "RSS {:?} MB",
        process.memory().await?.rss().get::<information::megabyte>()
    );
    println!("{:?}", process.status().await?);

    Ok(())
}
