use rand::RngCore;
use rocket::Request;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("rand: {0:?}")]
    Rand(#[from] rand::Error),
    #[error("Unknown: {0:?}")]
    Unknown(#[from] anyhow::Error),
}

type Result<T, E = Error> = anyhow::Result<T, E>;

pub(crate) fn set_proof_in_cache<P: Send + Sync + 'static>(request: &Request<'_>, proof: P) {
    request.local_cache(|| Some(proof));
}

pub(crate) fn secure_id(len: usize) -> Result<String> {
    let mut buf = vec![0; len];
    rand::thread_rng().try_fill_bytes(&mut buf)?;
    Ok(base64::encode_config(buf, base64::URL_SAFE))
}
