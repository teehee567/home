// utility shared by other modules
pub mod module_client;
pub mod broadcast_rx;

use modules::Module;
use std::marker::PhantomData;

pub struct ModuleClient<M: Module> {
    // placeholder while stub
    _marker: PhantomData<M>,
}

impl<M: Module> ModuleClient<M> {
    pub async fn send(&self, _req: M::Request) -> Result<M::Response, modules::ModuleError> {
        todo!()
    }
}
