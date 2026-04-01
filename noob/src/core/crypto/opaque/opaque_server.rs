use std::collections::HashMap;

use anyhow::{Context, Result};
use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration, ServerRegistrationLen, ServerSetup,
    generic_array::GenericArray, rand::rngs::OsRng,
};
use secrecy::SecretBox;
use zeroize::Zeroize;

use super::OpaqueCipherSuite;

pub struct ServerLoginState(ServerLogin<OpaqueCipherSuite>);

pub struct OpaqueServer {
    server_setup: ServerSetup<OpaqueCipherSuite>,
    registered_users: HashMap<String, GenericArray<u8, ServerRegistrationLen<OpaqueCipherSuite>>>,
}

impl OpaqueServer {
    pub fn new() -> Self {
        let mut rng = OsRng;
        Self {
            server_setup: ServerSetup::<OpaqueCipherSuite>::new(&mut rng),
            registered_users: HashMap::new(),
        }
    }

    pub fn registration_start(&self, username: &str, request_bytes: &[u8]) -> Result<Vec<u8>> {
        let request = RegistrationRequest::deserialize(request_bytes)?;
        let start = ServerRegistration::<OpaqueCipherSuite>::start(
            &self.server_setup,
            request,
            username.as_bytes(),
        )?;
        Ok(start.message.serialize().to_vec())
    }

    pub fn registration_finish(&mut self, username: &str, upload_bytes: &[u8]) -> Result<()> {
        let upload = RegistrationUpload::<OpaqueCipherSuite>::deserialize(upload_bytes)?;
        let password = ServerRegistration::finish(upload);
        self.registered_users
            .insert(username.to_owned(), password.serialize());
        Ok(())
    }

    pub fn login_start(
        &self,
        username: &str,
        ke1_bytes: &[u8],
    ) -> Result<(Vec<u8>, ServerLoginState)> {
        let pf_bytes = self
            .registered_users
            .get(username)
            .context("unknown user")?;
        let pf = ServerRegistration::<OpaqueCipherSuite>::deserialize(pf_bytes)?;
        let request = CredentialRequest::deserialize(ke1_bytes)?;

        let mut rng = OsRng;
        let start = ServerLogin::start(
            &mut rng,
            &self.server_setup,
            Some(pf),
            request,
            username.as_bytes(),
            ServerLoginParameters::default(),
        )?;

        let ke2 = start.message.serialize().to_vec();
        Ok((ke2, ServerLoginState(start.state)))
    }

    pub fn login_finish(state: ServerLoginState, ke3_bytes: &[u8]) -> Result<SecretBox<[u8; 64]>> {
        let fin = CredentialFinalization::deserialize(ke3_bytes)?;
        let result = state
            .0
            .finish(fin, ServerLoginParameters::default())?;

        let mut sk: [u8; 64] = result.session_key.as_slice().try_into()?;
        let secret = SecretBox::new(Box::new(sk));
        sk.zeroize();
        Ok(secret)
    }
}
