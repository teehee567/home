use std::{process, time::Duration};

use serde::{Deserialize, Serialize};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tokio::time;

use crate::modules::{Context, Module};

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProcStats {
    pub cpu: f32,
    pub memory: u64,
}

#[derive(Serialize, Deserialize)]
pub enum SysinfoRequest {
    GetStats,
}

pub struct SysinfoModule {
    sys: System,
    pid: Pid,
    current: ProcStats,
}

impl Module for SysinfoModule {
    const NAME: &str = "sysinfo";

    type Request = SysinfoRequest;
    type Response = ProcStats;
    type Event = ProcStats;

    fn new() -> Self {
        Self {
            sys: System::new(),
            pid: Pid::from_u32(process::id()),
            current: ProcStats { cpu: 0.0, memory: 0 },
        }
    }

    async fn run(mut self, mut ctx: Context<Self>) {
        let mut tick = time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                msg = ctx.recv() => match msg {
                    Some(req) => match req.payload {
                        SysinfoRequest::GetStats => req.reply(Ok(self.current)),
                    },
                    None => break, // every handle dropped → shut down
                },
                _ = tick.tick() => {
                    let next = self.sample();
                    if next != self.current {
                        self.current = next;
                        ctx.publish(self.current);
                    }
                }
            }
        }
    }
}

impl SysinfoModule {
    fn sample(&mut self) -> ProcStats {
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[self.pid]),
            true,
            ProcessRefreshKind::nothing().with_cpu().with_memory(),
        );
        match self.sys.process(self.pid) {
            Some(p) => ProcStats { cpu: p.cpu_usage(), memory: p.memory() },
            None => self.current,
        }
    }
}