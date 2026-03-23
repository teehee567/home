use anyhow::Result;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
    rand::rngs::OsRng,
};
use secrecy::SecretBox;
use transport::framed::FramedStream;
use zeroize::Zeroize;

use super::OpaqueCipherSuite;

pub struct LoginResult {
    pub session_key: SecretBox<[u8; 64]>,
    pub export_key: SecretBox<[u8; 64]>,
}

pub struct OpaqueClient;

impl OpaqueClient {
    pub async fn register(
        password: &[u8],
        stream: &mut impl FramedStream,
    ) -> Result<SecretBox<[u8; 64]>> {
        // send request to server
        let mut rng = OsRng;
        let start = ClientRegistration::<OpaqueCipherSuite>::start(&mut rng, password)?;

        stream.send(&start.message.serialize()).await?;

        // receive registration response
        let response = RegistrationResponse::deserialize(&stream.receive().await?)?;

        let finish = start
            .state
            .finish(
                &mut rng,
                password,
                response,
                ClientRegistrationFinishParameters::default(),
            )?;

        // send registration finish
        stream.send(&finish.message.serialize()).await?;

        let mut ek: [u8; 64] = finish.export_key.as_slice().try_into()?;
        let secret = SecretBox::new(Box::new(ek));
        ek.zeroize();
        Ok(secret)
    }

    pub async fn login(
        password: &[u8],
        stream: &mut impl FramedStream,
    ) -> Result<LoginResult> {
        // send login request
        let mut rng = OsRng;
        let start = ClientLogin::<OpaqueCipherSuite>::start(&mut rng, password)?;

        stream.send(&start.message.serialize()).await?;

        // receive login response
        let response = CredentialResponse::deserialize(&stream.receive().await?)?;

        let finish = start
            .state
            .finish(&mut rng, password, response, ClientLoginFinishParameters::default())?;

        // send login finish
        stream.send(&finish.message.serialize()).await?;

        let mut sk: [u8; 64] = finish.session_key.as_slice().try_into()?;
        let mut ek: [u8; 64] = finish.export_key.as_slice().try_into()?;
        let result = LoginResult {
            session_key: SecretBox::new(Box::new(sk)),
            export_key: SecretBox::new(Box::new(ek)),
        };
        sk.zeroize();
        ek.zeroize();
        Ok(result)
    }
}
