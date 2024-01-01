use rand::RngCore;
use rocket::Request;

/// Sets the proof in the request's local cache, so other guards can access it.
pub(crate) fn set_proof_in_cache<P: Send + Sync + 'static>(request: &Request<'_>, proof: P) {
    request.local_cache(|| Some(proof));
}

/// Generates a random ID of the given length.
pub(crate) fn random_id(len: usize) -> Result<String, rand::Error> {
    let mut buf = vec![0; len];
    rand::thread_rng().try_fill_bytes(&mut buf)?;
    Ok(base64::encode_config(buf, base64::URL_SAFE_NO_PAD))
}
