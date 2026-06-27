// register modues
crate::register_modules! {
    pub enum ModuleId;
    pub struct Modules;

    device {
        Metrics => super::metrics::MetricsModule,
    }

    // modules that only make sense on an interactive user machine
    desktop {
        #[cfg(windows)] Genshin => super::genshin::GenshinModule,
        AppWatcher => super::app_watcher::AppWatcherModule,
    }

    // modules that live on the always-on node because it owns the resource
    // (e.g. FileStore owns the disk)
    authority {}
}
