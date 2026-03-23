use std::collections::HashMap;

use anyhow::{Context, Result};
use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration, ServerRegistrationLen, ServerSetup,
    generic_array::GenericArray, rand::rngs::OsRng,
};
use secrecy::SecretBox;
use transport::framed::FramedStream;
use zeroize::Zeroize;

use super::OpaqueCipherSuite;

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

    pub async fn register(&mut self, username: &str, stream: &mut impl FramedStream) -> Result<()> {
        // receive registration request
        let request = RegistrationRequest::deserialize(&stream.receive().await?)?;

        let start = ServerRegistration::<OpaqueCipherSuite>::start(
            &self.server_setup,
            request,
            username.as_bytes(),
        )?;

        // send registration response
        stream.send(&start.message.serialize()).await?;

        // receive password file
        let upload =
            RegistrationUpload::<OpaqueCipherSuite>::deserialize(&stream.receive().await?)?;

        let password = ServerRegistration::finish(upload);
        self.registered_users
            .insert(username.to_owned(), password.serialize());
        Ok(())
    }

    pub async fn login(
        &self,
        username: &str,
        stream: &mut impl FramedStream,
    ) -> Result<SecretBox<[u8; 64]>> {
        let pf_bytes = self
            .registered_users
            .get(username)
            .context("unknown user")?;
        let pf = ServerRegistration::<OpaqueCipherSuite>::deserialize(pf_bytes)?;

        // receive credential request
        let request = CredentialRequest::deserialize(&stream.receive().await?)?;

        let mut rng = OsRng;
        let start = ServerLogin::start(
            &mut rng,
            &self.server_setup,
            Some(pf),
            request,
            username.as_bytes(),
            ServerLoginParameters::default(),
        )?;

        // send credential response
        stream.send(&start.message.serialize()).await?;

        // receive credential finalisation
        let fin = CredentialFinalization::deserialize(&stream.receive().await?)?;

        let result = start
            .state
            .finish(fin, ServerLoginParameters::default())?;

        let mut sk: [u8; 64] = result.session_key.as_slice().try_into()?;
        let secret = SecretBox::new(Box::new(sk));
        sk.zeroize();
        Ok(secret)
    }

    pub fn has_user(&self, username: &str) -> bool {
        self.registered_users.contains_key(username)
    }
}
