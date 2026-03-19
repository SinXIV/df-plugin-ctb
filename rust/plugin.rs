use std::sync::Arc;

use crate::plugin_registry::{FormatProvider, PluginRegistration};

pub struct CtbFormatProvider;

impl FormatProvider for CtbFormatProvider {
    fn default_export_format(&self) -> &'static str {
        "ctb"
    }
}

pub fn get_plugin_registration() -> PluginRegistration {
    PluginRegistration {
        name: "ctb".to_string(),
        network_handler: None,
        format_provider: Some(Arc::new(CtbFormatProvider)),
    }
}
