//! Profile-specific admission; context capacity is never an instruction to consume it all.
use super::ModelProfile;

pub(super) struct Limits {
    pub input: usize,
    pub instructions: usize,
    pub history: usize,
    pub tools: usize,
    pub text: usize,
    pub description: usize,
    pub context_tokens: usize,
    pub request_frame: usize,
}

pub(super) const fn for_profile(profile: ModelProfile) -> Limits {
    if profile.is_native_conversation() {
        Limits {
            input: 256 * 1024,
            instructions: 64 * 1024,
            history: 128,
            tools: 32,
            text: 64 * 1024,
            description: 8192,
            context_tokens: if matches!(profile, ModelProfile::Qwen4bInstruct2507) {
                262144
            } else {
                32768
            },
            request_frame: 512 * 1024,
        }
    } else {
        Limits {
            input: super::MAX_BYTES,
            instructions: 4096,
            history: 32,
            tools: 8,
            text: 8192,
            description: 2048,
            context_tokens: 8192,
            request_frame: 32 * 1024,
        }
    }
}
