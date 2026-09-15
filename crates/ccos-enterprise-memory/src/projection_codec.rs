//! Canonical version-1 projection bytes shared by save and recovery binding.
use super::{
    projection_corrupt, GovernedMemoryProjection, GovernedMemoryProjectionError,
    MAX_GOVERNED_MEMORY_PROJECTION_BYTES,
};

/// Validate and encode exactly the bytes used by projection persistence.
///
/// This binds a recovery image to all lineage states, trust rows, loadout and
/// tenant metadata, without treating a digest as authentication. Public fields
/// are revalidated, and the existing 16 MiB wire limit is preserved. The byte
/// limit is not a bound on all temporary validation allocations.
///
/// ```no_run
/// # use ccos_enterprise_memory::{encode_governed_memory_projection, GovernedMemoryProjection};
/// # fn example(projection: &GovernedMemoryProjection) -> Result<(), Box<dyn std::error::Error>> {
/// let bytes = encode_governed_memory_projection(projection)?;
/// assert!(!bytes.is_empty());
/// # Ok(()) }
/// ```
pub fn encode_governed_memory_projection(
    projection: &GovernedMemoryProjection,
) -> Result<Vec<u8>, GovernedMemoryProjectionError> {
    let checked =
        GovernedMemoryProjection::from_wire(Some(&projection.tenant), projection.to_wire())?;
    let bytes = serde_json::to_vec_pretty(&checked.to_wire())
        .map_err(|error| projection_corrupt(&error.to_string()))?;
    if bytes.len() > MAX_GOVERNED_MEMORY_PROJECTION_BYTES {
        return Err(projection_corrupt(
            "projection exceeds the 16 MiB byte limit",
        ));
    }
    Ok(bytes)
}
