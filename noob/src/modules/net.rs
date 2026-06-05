use crate::modules::sys_info::{self, SysinfoModule};



pub struct ModuleNet;

impl ModuleNet {
    pub fn request() {
        SysinfoModule::ID;
    }
}