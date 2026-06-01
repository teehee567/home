// register modues
crate::register_modules! {
    pub enum ModuleId;
    pub struct Modules;

    Sysinfo => super::sys_info::SysinfoModule,
    #[cfg(windows)] Genshin => super::genshin::GenshinModule,
}
