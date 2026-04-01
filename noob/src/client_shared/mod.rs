use crate::modules::Module;
use std::marker::PhantomData;

pub struct ModuleClient<M: Module> {
    _marker: PhantomData<M>,
}

impl<M: Module> ModuleClient<M> {
    pub async fn send(&self, _req: M::Request) -> Result<M::Response, crate::modules::ModuleError> {
        todo!()
    }
}
