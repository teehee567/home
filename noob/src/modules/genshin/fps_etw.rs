use std::{
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::Duration,
};

use ferrisetw::{provider::Provider, trace::{TraceTrait, UserTrace}};
use tokio::sync::oneshot;

const SESSION_NAME: &str = "noob-fps-dxgi";
const DXGI_PROVIDER_GUID: &str = "CA11C036-0102-4A2D-A6AD-F03CFED5D3C9";
const OPCODE_START: u8 = 1;
const EV_PRESENT: u16 = 42;
const EV_PRESENT1: u16 = 58;

const WINDOW: Duration = Duration::from_secs(1);
const REFRESH: Duration = Duration::from_millis(100);
const SLOTS: usize = (WINDOW.as_millis() / REFRESH.as_millis()) as usize;

pub struct EtwSession;

impl EtwSession {
    pub fn stop_session() {
        let _ = Command::new("logman")
            .args(["stop", SESSION_NAME, "-ets"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    pub async fn start(pid: u32) -> Result<(Arc<AtomicU32>, EtwSession), String> {
        let present_count = Arc::new(AtomicU64::new(0));
        let fps = Arc::new(AtomicU32::new(0));

        let provider = Self::build_provider(pid, present_count.clone());

        Self::stop_session();

        let (tx, rx) = oneshot::channel::<Result<(), String>>();
        Self::spawn_trace_task(provider, tx, fps.clone(), present_count);

        rx.await
            .map_err(|e| e.to_string())?
            .map(|_| (fps, EtwSession))
    }

    fn build_provider(pid: u32, present_count: Arc<AtomicU64>) -> Provider {
        Provider::by_guid(DXGI_PROVIDER_GUID)
            .add_callback(move |record, _locator| {
                if record.process_id() != pid {
                    return;
                }
                if record.opcode() == OPCODE_START
                    && (record.event_id() == EV_PRESENT || record.event_id() == EV_PRESENT1)
                {
                    present_count.fetch_add(1, Ordering::Relaxed);
                }
            })
            .build()
    }

    fn spawn_trace_task(
        provider: Provider,
        tx: oneshot::Sender<Result<(), String>>,
        fps: Arc<AtomicU32>,
        present_count: Arc<AtomicU64>,
    ) {
        tokio::task::spawn_blocking(move || {
            match UserTrace::new()
                .named(String::from(SESSION_NAME))
                .enable(provider)
                .start()
            {
                Err(e) => {
                    tx.send(Err(format!("{e:?}"))).ok();
                }
                Ok((mut trace, handle)) => {
                    tx.send(Ok(())).ok();
                    Self::spawn_fps_task(fps, present_count);
                    let _ = trace.process();
                    let _ = handle;
                }
            }
        });
    }

    fn spawn_fps_task(fps: Arc<AtomicU32>, present_count: Arc<AtomicU64>) {
        // ring buffer for performance, 
        // premature optimisation bad or wahtever but this is easy
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(REFRESH);
            let mut ring = [0u32; SLOTS];
            let mut cursor: usize = 0;
            let mut last_count: u64 = 0;
            let mut total: u32 = 0;

            loop {
                interval.tick().await;

                let current = present_count.load(Ordering::Relaxed);
                let delta = (current.wrapping_sub(last_count)) as u32;
                last_count = current;

                total -= ring[cursor];
                ring[cursor] = delta;
                total += delta;
                cursor = (cursor + 1) % SLOTS;

                let fps_val = (total as f32 / WINDOW.as_secs_f32()).round() as u32;
                fps.store(fps_val, Ordering::Relaxed);
            }
        });
    }
}

impl Drop for EtwSession {
    fn drop(&mut self) {
        Self::stop_session();
    }
}
