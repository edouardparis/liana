pub mod key;
pub mod template;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use iced::{Subscription, Task};
use liana::miniscript::bitcoin::bip32::ChildNumber;
use liana::{
    descriptors::{LianaDescriptor, LianaPolicy, PathInfo},
    miniscript::{
        bitcoin::{bip32::Fingerprint, Network},
        descriptor::DescriptorPublicKey,
    },
};

use liana_ui::{
    component::form,
    widget::{modal::Modal, Element},
};

use crate::installer::KeySourceKind;
use crate::{
    app::settings::KeySetting,
    hw::HardwareWallets,
    installer::{
        context::DescriptorTemplate,
        descriptor::{Key, Path, PathKind, PathSequence, PathWarning},
        message::{self, Message},
        step::{Context, Step},
        view,
    },
    services::keys::api::KeyKind,
    signer::Signer,
};

use key::{new_multixkey_from_xpub, EditKeyAlias, PathData, SelectKeySource};

pub trait DescriptorEditModal {
    fn processing(&self) -> bool {
        false
    }
    fn update(&mut self, _hws: &mut HardwareWallets, _message: Message) -> Task<Message> {
        Task::none()
    }
    fn view<'a>(&'a self, _hws: &'a HardwareWallets) -> Element<'a, Message>;
    fn subscription(&self, _hws: &HardwareWallets) -> Subscription<Message> {
        Subscription::none()
    }
}

pub struct DefineDescriptor {
    network: Network,
    use_taproot: bool,

    modal: Option<Box<dyn DescriptorEditModal>>,
    signer: Arc<Mutex<Signer>>,

    keys: HashMap<Fingerprint, Key>,
    paths: Vec<Path>,
    accounts: HashMap<Fingerprint, ChildNumber>,
    descriptor_template: DescriptorTemplate,

    error: Option<String>,
}

impl DefineDescriptor {
    pub fn new(network: Network, signer: Arc<Mutex<Signer>>) -> Self {
        Self {
            network,
            use_taproot: false,
            modal: None,

            signer,
            error: None,
            keys: HashMap::new(),
            descriptor_template: DescriptorTemplate::default(),
            paths: Vec::new(),
            accounts: Default::default(),
        }
    }

    fn check_for_warning(&mut self) {
        let mut all_sequence = HashSet::new();
        let mut duplicate_sequences = HashSet::new();
        for path in &mut self.paths {
            if all_sequence.contains(&path.sequence.as_u16()) {
                duplicate_sequences.insert(path.sequence.as_u16());
            } else {
                all_sequence.insert(path.sequence.as_u16());
            }
        }
        for path in &mut self.paths {
            if duplicate_sequences.contains(&path.sequence.as_u16()) {
                path.warning = Some(PathWarning::DuplicateSequence);
            } else if path.keys.iter().all(|key| {
                // All keys must be Some for warning to apply.
                key.as_ref()
                    .is_some_and(|k| k.source.provider_key_kind() == Some(KeyKind::Cosigner))
            }) {
                path.warning = Some(PathWarning::OnlyCosignerKeys);
            } else if path
                .keys
                .iter()
                .flatten() // can ignore None
                .any(|key| !path.kind().can_choose_key_source_kind(&key.source.kind()))
            {
                path.warning = Some(PathWarning::KeySourceKindDisallowed);
            } else {
                path.warning = None;
            }
        }
    }

    fn valid(&self) -> bool {
        !self.paths.iter().any(|path| {
            !path.valid()
                || (self.use_taproot
                    && path
                        .keys
                        .iter()
                        .any(|k| !k.as_ref().is_some_and(|k| k.source.is_compatible_taproot())))
        }) && self.paths.len() >= 2
    }

    fn check_setup(&mut self) {
        self.check_for_warning();
    }

    fn load_template(&mut self, template: DescriptorTemplate) {
        if self.descriptor_template != template || self.paths.is_empty() {
            match template {
                DescriptorTemplate::SimpleInheritance => {
                    self.paths = vec![Path::new_primary_path(), Path::new_recovery_path()];
                }
                DescriptorTemplate::MultisigSecurity => {
                    self.paths = vec![
                        Path::new_primary_path().with_n_keys(2).with_threshold(2),
                        Path::new_recovery_path().with_n_keys(3).with_threshold(2),
                    ];
                }
                DescriptorTemplate::Custom => {
                    self.paths = vec![Path::new_primary_path(), Path::new_recovery_path()];
                }
            }
        }
        self.descriptor_template = template;
    }

    fn keys(&self) -> HashMap<Fingerprint, (Vec<(usize, usize)>, Key)> {
        let mut keys: HashMap<Fingerprint, (Vec<(usize, usize)>, Key)> = self
            .keys
            .clone()
            .into_iter()
            .map(|(fg, key)| (fg, (vec![], key)))
            .collect();
        for (i, path) in self.paths.iter().enumerate() {
            for (j, key) in path.keys.iter().enumerate() {
                if let Some(k) = key {
                    let fg = k.fingerprint;
                    if !keys.contains_key(&fg) {
                        tracing::error!("DefineDesctriptor::keys() key {} missing", fg);
                    } else {
                        let entry = keys.get_mut(&fg).expect("checked");
                        entry.0.push((i, j));
                    }
                }
            }
        }
        keys
    }

    fn path_keys(&self, paths: Vec<usize>) -> Vec<Fingerprint> {
        let mut out = vec![];
        for path in paths {
            let mut fgs: Vec<_> = self.paths[path]
                .keys
                .iter()
                .filter_map(|k| k.as_ref().map(|k| k.fingerprint))
                .collect();
            out.append(&mut fgs);
        }
        out
    }

    fn edit_key_modal(
        &self,
        path_kind: PathKind,
        coordinates: Vec<(usize, usize)>,
    ) -> SelectKeySource {
        let mut token_kind = vec![];
        if let PathKind::SafetyNet = path_kind {
            token_kind.push(KeyKind::SafetyNet);
        }
        if path_kind.can_choose_key_source_kind(&KeySourceKind::Token(KeyKind::Cosigner))
            && path_kind != PathKind::SafetyNet
        {
            token_kind.push(KeyKind::Cosigner);
        }
        let keys = self.path_keys(coordinates.iter().map(|c| c.0).collect());
        let actual_path = PathData {
            coordinates,
            keys,
            token_kind,
        };
        let keys = self.keys();
        SelectKeySource::new(
            self.network,
            self.use_taproot,
            actual_path,
            keys,
            self.accounts.clone(),
            self.signer.clone(),
        )
    }
}

impl Step for DefineDescriptor {
    fn load_context(&mut self, ctx: &Context) {
        self.load_template(ctx.descriptor_template)
    }
    // form value is set as valid each time it is edited.
    // Verification of the values is happening when the user click on Next button.
    fn update(&mut self, hws: &mut HardwareWallets, message: Message) -> Task<Message> {
        self.error = None;
        match message {
            Message::Close => {
                self.modal = None;
            }
            Message::CreateTaprootDescriptor(use_taproot) => {
                self.use_taproot = use_taproot;
                self.check_setup();
            }
            Message::DefineDescriptor(message::DefineDescriptor::ChangeTemplate(template)) => {
                self.descriptor_template = template;
            }
            Message::DefineDescriptor(message::DefineDescriptor::AddRecoveryPath) => {
                self.paths.push(Path::new_recovery_path());
            }
            Message::DefineDescriptor(message::DefineDescriptor::AddSafetyNetPath) => {
                if !self.paths.iter().any(|p| p.kind() == PathKind::SafetyNet) {
                    self.paths.push(Path::new_safety_net_path());
                }
            }
            Message::DefineDescriptor(message::DefineDescriptor::KeysEdited(coordinates, key)) => {
                match key {
                    key::SelectedKey::Existing(fingerprint) => {
                        if let Some(existing_key) = self.keys.get(&fingerprint) {
                            if !self.keys.contains_key(&fingerprint) {
                                tracing::error!("Key {fingerprint} does not exists");
                                return Task::none();
                            }
                            for coordinate in coordinates {
                                if !self.paths[coordinate.0]
                                    .keys
                                    .contains(&Some(existing_key.clone()))
                                {
                                    self.paths[coordinate.0].keys[coordinate.1] =
                                        Some(existing_key.clone());
                                } else {
                                    tracing::error!(
                                        "Key {fingerprint} already in path {}",
                                        coordinate.0
                                    );
                                }
                            }
                            self.check_setup();
                        } else {
                            tracing::error!("Key with fingerprint {fingerprint} does not exists");
                        }
                        self.modal = None;
                    }
                    key::SelectedKey::New(key) => {
                        if let Some(acc) = key.account {
                            self.accounts.insert(key.fingerprint, acc);
                        }
                        if self.keys.contains_key(&key.fingerprint) {
                            tracing::error!("Key {} already exists", key.fingerprint);
                        }
                        self.keys.insert(key.fingerprint, *key.clone());
                        hws.aliases.insert(key.fingerprint, key.name.clone());
                        for coordinate in coordinates {
                            if !self.paths[coordinate.0].keys.contains(&Some(*key.clone())) {
                                self.paths[coordinate.0].keys[coordinate.1] = Some(*key.clone());
                            } else {
                                tracing::error!(
                                    "Key {} already in path {}",
                                    key.fingerprint,
                                    coordinate.0
                                );
                            }
                        }
                        self.check_setup();
                        self.modal = None;
                    }
                    key::SelectedKey::None => {
                        self.modal = None;
                    }
                }
            }
            Message::DefineDescriptor(message::DefineDescriptor::KeysEdit(
                path_kind,
                coordinates,
            )) => {
                let modal = self.edit_key_modal(path_kind, coordinates);
                self.modal = Some(Box::new(modal));
            }
            Message::DefineDescriptor(message::DefineDescriptor::AliasEdited(fg, alias)) => {
                if let Some(key) = self.keys.get_mut(&fg) {
                    key.name = alias.clone();
                }
                hws.aliases.insert(fg, alias.clone());
                // FIXME: this is a bad hack, we should not store duplicates of keys in paths,
                // source of truth should be self.keys
                for p in &mut self.paths {
                    #[allow(clippy::manual_flatten)]
                    for k in &mut p.keys {
                        if let Some(key) = k {
                            if key.fingerprint == fg {
                                key.name = alias.clone();
                            }
                        }
                    }
                }
                self.modal = None;
            }
            Message::DefineDescriptor(message::DefineDescriptor::Reset) => {
                hws.aliases.clear();
                self.keys.clear();
                self.paths.clear();
                self.load_template(self.descriptor_template);
                self.modal = None;
            }
            Message::DefineDescriptor(message::DefineDescriptor::Path(i, msg)) => {
                match msg {
                    message::DefinePath::SequenceEdited(seq) => {
                        self.modal = None;
                        if let Some(Path {
                            sequence: PathSequence::Recovery(s),
                            ..
                        }) = self.paths.get_mut(i)
                        {
                            *s = seq;
                        }
                        self.check_for_warning();
                    }
                    message::DefinePath::ThresholdEdited(t) => {
                        self.modal = None;
                        if let Some(path) = self.paths.get_mut(i) {
                            path.threshold = t;
                        }
                    }
                    message::DefinePath::EditSequence => {
                        if let Some(path) = self.paths.get(i) {
                            self.modal = Some(Box::new(EditSequenceModal::new(i, path.sequence)));
                        }
                    }
                    message::DefinePath::EditThreshold => {
                        if let Some(path) = self.paths.get(i) {
                            self.modal = Some(Box::new(EditThresholdModal::new(
                                i,
                                (path.threshold, path.keys.len()),
                            )));
                        }
                    }

                    message::DefinePath::AddKey => {
                        if let Some(path) = self.paths.get_mut(i) {
                            path.keys.push(None);
                            path.threshold += 1;
                            self.check_for_warning();
                        }
                    }
                    message::DefinePath::Key(j, msg) => {
                        match msg {
                            message::DefineKey::Clipboard(key) => {
                                return Task::perform(async move { key }, Message::Clipboard);
                            }

                            message::DefineKey::EditAlias => {
                                let coordinates = vec![(i, j)];
                                let path_kind = self.paths[i].sequence.into();
                                if let Some(path) = self.paths.get(i) {
                                    if let Some(Some(key)) = path.keys.get(j) {
                                        let fg = key.fingerprint;
                                        let alias = key.name.clone();
                                        let modal = EditKeyAlias::new(
                                            self.keys(),
                                            fg,
                                            alias,
                                            path_kind,
                                            coordinates,
                                        );
                                        self.modal = Some(Box::new(modal));
                                        return Task::none();
                                    }
                                }
                                log::error!("DefineDescriptor.update(): DefineKey::EditAlias => key is None.");
                                return Task::none();
                            }
                            message::DefineKey::Edit => {
                                let coordinates = vec![(i, j)];
                                let path_kind = self.paths[i].sequence.into();
                                let modal = self.edit_key_modal(path_kind, coordinates);
                                self.modal = Some(Box::new(modal));
                            }
                            message::DefineKey::Delete => {
                                if let Some(path) = self.paths.get_mut(i) {
                                    path.keys.remove(j);
                                    if path.threshold > path.keys.len() {
                                        path.threshold -= 1;
                                    }
                                }
                                // Only delete non-primary paths.
                                if i > 0 // we could alternatively check `path_kind != PathKind::Primary`
                                && self
                                    .paths
                                    .get(i)
                                    .map(|path| path.keys.is_empty())
                                    .unwrap_or(false)
                                {
                                    self.paths.remove(i);
                                }
                                self.check_setup();
                            }
                        }
                    }
                }
            }
            Message::EditKeyAlias(msg) => match msg.clone() {
                key::EditKeyAliasMessage::Alias(_)
                | key::EditKeyAliasMessage::Save
                | key::EditKeyAliasMessage::Replace => {
                    if let Some(modal) = &mut self.modal {
                        return modal.update(hws, Message::EditKeyAlias(msg));
                    }
                }
                key::EditKeyAliasMessage::DoReplace {
                    path_kind,
                    coordinates,
                } => {
                    let modal = self.edit_key_modal(path_kind, coordinates);
                    self.modal = Some(Box::new(modal));
                }
                key::EditKeyAliasMessage::Close => self.modal = None,
            },
            _ => {
                if let Some(modal) = &mut self.modal {
                    return modal.update(hws, message);
                }
            }
        };
        Task::none()
    }

    fn subscription(&self, hws: &HardwareWallets) -> Subscription<Message> {
        if let Some(modal) = &self.modal {
            modal.subscription(hws)
        } else {
            Subscription::none()
        }
    }

    fn apply(&mut self, ctx: &mut Context) -> bool {
        if self.paths.len() < 2 {
            return false;
        }

        ctx.bitcoin_config.network = self.network;
        ctx.keys = HashMap::new();
        let mut hw_is_used = false;
        let mut spending_keys: Vec<DescriptorPublicKey> = Vec::new();
        let mut key_derivation_index = HashMap::<Fingerprint, usize>::new();
        for spending_key in self.paths[0].keys.iter().clone() {
            let fingerprint = spending_key
                .as_ref()
                .expect("Must be present at this step")
                .fingerprint;
            let key = self
                .keys
                .get(&fingerprint)
                .expect("Must be present at this step");
            if let DescriptorPublicKey::XPub(xpub) = &key.key {
                if let Some((master_fingerprint, _)) = xpub.origin {
                    ctx.keys.insert(
                        master_fingerprint,
                        KeySetting {
                            master_fingerprint,
                            name: key.name.clone(),
                            provider_key: key.source.provider_key(),
                        },
                    );
                    if key.source.device_kind().is_some() {
                        hw_is_used = true;
                    }
                }
                let derivation_index = key_derivation_index.get(&fingerprint).unwrap_or(&0);
                spending_keys.push(DescriptorPublicKey::MultiXPub(new_multixkey_from_xpub(
                    xpub.clone(),
                    *derivation_index,
                )));
                key_derivation_index.insert(fingerprint, derivation_index + 1);
            }
        }

        let mut recovery_paths = BTreeMap::new();

        for path in &self.paths[1..] {
            let mut recovery_keys: Vec<DescriptorPublicKey> = Vec::new();
            for recovery_key in path.keys.iter().clone() {
                let fingerprint = recovery_key
                    .as_ref()
                    .expect("Must be present at this step")
                    .fingerprint;
                let key = self
                    .keys
                    .get(&fingerprint)
                    .expect("Must be present at this step");
                if let DescriptorPublicKey::XPub(xpub) = &key.key {
                    if let Some((master_fingerprint, _)) = xpub.origin {
                        ctx.keys.insert(
                            master_fingerprint,
                            KeySetting {
                                master_fingerprint,
                                name: key.name.clone(),
                                provider_key: key.source.provider_key(),
                            },
                        );
                        if key.source.device_kind().is_some() {
                            hw_is_used = true;
                        }
                    }

                    let derivation_index = key_derivation_index.get(&fingerprint).unwrap_or(&0);
                    recovery_keys.push(DescriptorPublicKey::MultiXPub(new_multixkey_from_xpub(
                        xpub.clone(),
                        *derivation_index,
                    )));
                    key_derivation_index.insert(fingerprint, derivation_index + 1);
                }
            }

            let recovery_keys = if recovery_keys.len() == 1 {
                PathInfo::Single(recovery_keys[0].clone())
            } else {
                PathInfo::Multi(path.threshold, recovery_keys)
            };

            recovery_paths.insert(path.sequence.as_u16(), recovery_keys);
        }

        if spending_keys.is_empty() {
            return false;
        }

        let spending_keys = if spending_keys.len() == 1 {
            PathInfo::Single(spending_keys[0].clone())
        } else {
            PathInfo::Multi(self.paths[0].threshold, spending_keys)
        };

        let policy = match if self.use_taproot {
            LianaPolicy::new(spending_keys, recovery_paths)
        } else {
            LianaPolicy::new_legacy(spending_keys, recovery_paths)
        } {
            Ok(policy) => policy,
            Err(e) => {
                self.error = Some(e.to_string());
                return false;
            }
        };

        ctx.descriptor = Some(LianaDescriptor::new(policy));
        ctx.hw_is_used = hw_is_used;
        true
    }

    fn view<'a>(
        &'a self,
        hws: &'a HardwareWallets,
        progress: (usize, usize),
        _email: Option<&'a str>,
    ) -> Element<'a, Message> {
        let content = match self.descriptor_template {
            DescriptorTemplate::SimpleInheritance => {
                view::editor::template::inheritance::inheritance_template(
                    progress,
                    self.use_taproot,
                    &self.paths[0],
                    &self.paths[1],
                    self.valid(),
                )
            }
            DescriptorTemplate::MultisigSecurity => {
                view::editor::template::multisig_security_wallet::multisig_security_template(
                    progress,
                    self.use_taproot,
                    &self.paths[0],
                    &self.paths[1],
                    self.valid(),
                )
            }
            DescriptorTemplate::Custom => view::editor::template::custom::custom_template(
                progress,
                self.use_taproot,
                &self.paths[0],
                &mut self.paths[1..]
                    .iter()
                    .enumerate()
                    .filter(|(_, p)| p.kind() == PathKind::Recovery),
                self.paths[1..]
                    .iter()
                    .enumerate()
                    .find(|(_, p)| p.kind() == PathKind::SafetyNet),
                self.paths[1..].len(),
                self.valid(),
            ),
        };
        if let Some(modal) = &self.modal {
            Modal::new(content, modal.view(hws))
                .on_blur(if modal.processing() {
                    None
                } else {
                    Some(Message::Close)
                })
                .into()
        } else {
            content
        }
    }
}

impl From<DefineDescriptor> for Box<dyn Step> {
    fn from(s: DefineDescriptor) -> Box<dyn Step> {
        Box::new(s)
    }
}

pub struct EditSequenceModal {
    path_index: usize,
    sequence: form::Value<String>,
}

impl EditSequenceModal {
    pub fn new(path_index: usize, path_sequence: PathSequence) -> Self {
        Self {
            path_index,
            sequence: form::Value {
                value: path_sequence.as_u16().to_string(),
                warning: None,
                valid: true,
            },
        }
    }
}

impl DescriptorEditModal for EditSequenceModal {
    fn processing(&self) -> bool {
        false
    }

    fn update(&mut self, _hws: &mut HardwareWallets, message: Message) -> Task<Message> {
        if let Message::DefineDescriptor(message::DefineDescriptor::ThresholdSequenceModal(msg)) =
            message
        {
            match msg {
                message::ThresholdSequenceModal::SequenceEdited(seq) => {
                    if let Ok(s) = u16::from_str(&seq) {
                        self.sequence.valid = s != 0
                    } else {
                        self.sequence.valid = false;
                    }
                    self.sequence.value = seq;
                }
                message::ThresholdSequenceModal::Confirm => {
                    if self.sequence.valid {
                        if let Ok(sequence) = u16::from_str(&self.sequence.value) {
                            let path_index = self.path_index;
                            return Task::perform(
                                async move { (path_index, sequence) },
                                |(path_index, sequence)| {
                                    message::DefineDescriptor::Path(
                                        path_index,
                                        message::DefinePath::SequenceEdited(sequence),
                                    )
                                },
                            )
                            .map(Message::DefineDescriptor);
                        }
                    }
                }
                _ => {}
            }
        }
        Task::none()
    }

    fn view(&self, _hws: &HardwareWallets) -> Element<Message> {
        view::editor::edit_sequence_modal(&self.sequence)
    }
}

pub struct EditThresholdModal {
    threshold: (usize, usize),
    path_index: usize,
}

impl EditThresholdModal {
    pub fn new(path_index: usize, threshold: (usize, usize)) -> Self {
        Self {
            threshold,
            path_index,
        }
    }
}

impl DescriptorEditModal for EditThresholdModal {
    fn processing(&self) -> bool {
        false
    }

    fn update(&mut self, _hws: &mut HardwareWallets, message: Message) -> Task<Message> {
        if let Message::DefineDescriptor(message::DefineDescriptor::ThresholdSequenceModal(msg)) =
            message
        {
            match msg {
                message::ThresholdSequenceModal::ThresholdEdited(threshold) => {
                    if threshold <= self.threshold.1 {
                        self.threshold.0 = threshold;
                    }
                }
                message::ThresholdSequenceModal::Confirm => {
                    let path_index = self.path_index;
                    let threshold = self.threshold.0;
                    return Task::perform(
                        async move { (path_index, threshold) },
                        |(path_index, threshold)| {
                            message::DefineDescriptor::Path(
                                path_index,
                                message::DefinePath::ThresholdEdited(threshold),
                            )
                        },
                    )
                    .map(Message::DefineDescriptor);
                }
                _ => {}
            }
        }
        Task::none()
    }

    fn view(&self, _hws: &HardwareWallets) -> Element<Message> {
        view::editor::edit_threshold_modal(self.threshold)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced::futures::StreamExt;
    use iced_runtime::{task::into_stream, Action};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use crate::installer::step::descriptor::editor::key::{SelectKeySource, SelectedKey};
    use crate::{dir::LianaDirectory, installer::descriptor::KeySource};

    pub struct Sandbox<S: Step> {
        step: Arc<Mutex<S>>,
    }

    impl<S: Step + 'static> Sandbox<S> {
        pub fn new(step: S) -> Self {
            Self {
                step: Arc::new(Mutex::new(step)),
            }
        }

        pub fn check<F: FnOnce(&mut S)>(&self, check: F) {
            let mut step = self.step.lock().unwrap();
            check(&mut step)
        }

        pub async fn update(&self, message: Message) {
            let mut hws = HardwareWallets::new(
                LianaDirectory::new(PathBuf::from_str("/").unwrap()),
                Network::Bitcoin,
            );
            let cmd = self.step.lock().unwrap().update(&mut hws, message);
            if let Some(mut stream) = into_stream(cmd) {
                while let Some(action) = stream.next().await {
                    if let Action::Output(msg) = action {
                        let _cmd = self.step.lock().unwrap().update(&mut hws, msg);
                    }
                }
            }
        }
        pub async fn load(&self, ctx: &Context) {
            self.step.lock().unwrap().load_context(ctx);
        }
    }

    #[tokio::test]
    async fn test_define_descriptor_use_hotkey() {
        let mut ctx = Context::new(
            Network::Signet,
            LianaDirectory::new(PathBuf::from_str("/").unwrap()),
            crate::installer::context::RemoteBackend::None,
        );
        let sandbox: Sandbox<DefineDescriptor> = Sandbox::new(DefineDescriptor::new(
            Network::Signet,
            Arc::new(Mutex::new(Signer::generate(Network::Bitcoin).unwrap())),
        ));
        sandbox.load(&ctx).await;

        // Edit primary key
        sandbox
            .update(Message::DefineDescriptor(message::DefineDescriptor::Path(
                0,
                message::DefinePath::Key(0, message::DefineKey::Edit),
            )))
            .await;
        sandbox.check(|step| assert!(step.modal.is_some()));
        sandbox
            .update(SelectKeySource::route(
                key::SelectKeySourceMessage::SelectGenerateHotKey,
            ))
            .await;
        sandbox
            .update(SelectKeySource::route(key::SelectKeySourceMessage::Alias(
                "hot_signer_key".to_string(),
            )))
            .await;
        sandbox
            .update(SelectKeySource::route(key::SelectKeySourceMessage::Next))
            .await;
        sandbox.check(|step| assert!(step.modal.is_none()));

        // Edit sequence
        sandbox
            .update(Message::DefineDescriptor(message::DefineDescriptor::Path(
                1,
                message::DefinePath::SequenceEdited(1000),
            )))
            .await;

        // Edit recovery key
        sandbox
            .update(Message::DefineDescriptor(message::DefineDescriptor::Path(
                1,
                message::DefinePath::Key(0, message::DefineKey::Edit),
            )))
            .await;
        sandbox.check(|step| assert!(step.modal.is_some()));
        sandbox
            .update(SelectKeySource::route(
                key::SelectKeySourceMessage::SelectEnterXpub,
            ))
            .await;
        sandbox
            .update(SelectKeySource::route(
                key::SelectKeySourceMessage::Xpub("[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK".to_string())
            ))
            .await;
        sandbox
            .update(SelectKeySource::route(key::SelectKeySourceMessage::Alias(
                "External recovery key".to_string(),
            )))
            .await;
        sandbox
            .update(SelectKeySource::route(key::SelectKeySourceMessage::Next))
            .await;
        sandbox.check(|step| {
            assert!(step.modal.is_none());
            assert!((step).apply(&mut ctx));
            assert!(ctx
                .descriptor
                .as_ref()
                .unwrap()
                .to_string()
                .contains(&step.signer.lock().unwrap().fingerprint().to_string()));
        });
    }

    #[tokio::test]
    async fn test_define_descriptor_stores_if_hw_is_used() {
        let mut ctx = Context::new(
            Network::Testnet,
            LianaDirectory::new(PathBuf::from_str("/").unwrap()),
            crate::installer::context::RemoteBackend::None,
        );
        let sandbox: Sandbox<DefineDescriptor> = Sandbox::new(DefineDescriptor::new(
            Network::Testnet,
            Arc::new(Mutex::new(Signer::generate(Network::Testnet).unwrap())),
        ));
        sandbox.load(&ctx).await;

        let key = DescriptorPublicKey::from_str("[4df3f0e3/84'/0'/0']tpubDDRs9DnRUiJc4hq92PSJKhfzQBgHJUrDo7T2i48smsDfLsQcm3Vh7JhuGqJv8zozVkNFin8YPgpmn2NWNmpRaE3GW2pSxbmAzYf2juy7LeW").unwrap();
        let specter_key = Key {
            name: "My Specter key".to_string(),
            fingerprint: key.master_fingerprint(),
            key,
            source: KeySource::Device(async_hwi::DeviceKind::Specter, None),
            account: None,
        };

        // Use Specter device for primary key
        sandbox
            .update(Message::DefineDescriptor(
                message::DefineDescriptor::KeysEdited(
                    vec![(0, 0)],
                    SelectedKey::New(Box::new(specter_key.clone())),
                ),
            ))
            .await;

        // Edit recovery key
        sandbox
            .update(Message::DefineDescriptor(message::DefineDescriptor::Path(
                1,
                message::DefinePath::Key(0, message::DefineKey::Edit),
            )))
            .await;
        sandbox.check(|step| assert!(step.modal.is_some()));
        sandbox
            .update(SelectKeySource::route(
                key::SelectKeySourceMessage::SelectEnterXpub,
            ))
            .await;
        sandbox
            .update(SelectKeySource::route(
                key::SelectKeySourceMessage::Xpub("[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK".to_string())
            ))
            .await;
        sandbox
            .update(SelectKeySource::route(key::SelectKeySourceMessage::Alias(
                "External recovery key".to_string(),
            )))
            .await;
        sandbox
            .update(SelectKeySource::route(key::SelectKeySourceMessage::Next))
            .await;
        sandbox.check(|step| {
            assert!(step.modal.is_none());
            assert!((step).apply(&mut ctx));
            assert!(ctx.hw_is_used);
        });

        // Now edit primary key to use hot signer instead of Specter device
        sandbox
            .update(Message::DefineDescriptor(message::DefineDescriptor::Path(
                0,
                message::DefinePath::Key(0, message::DefineKey::Edit),
            )))
            .await;
        sandbox.check(|step| assert!(step.modal.is_some()));
        sandbox
            .update(SelectKeySource::route(
                key::SelectKeySourceMessage::SelectGenerateHotKey,
            ))
            .await;
        sandbox
            .update(SelectKeySource::route(key::SelectKeySourceMessage::Alias(
                "hot signer key".to_string(),
            )))
            .await;
        sandbox
            .update(SelectKeySource::route(key::SelectKeySourceMessage::Next))
            .await;
        sandbox.check(|step| {
            assert!(step.modal.is_none());
            assert!((step).apply(&mut ctx));
            assert!(!ctx.hw_is_used);
        });

        // Now edit the recovery key to use Specter device
        sandbox
            .update(Message::DefineDescriptor(
                message::DefineDescriptor::KeysEdited(
                    vec![(1, 0)],
                    SelectedKey::New(Box::new(specter_key.clone())),
                ),
            ))
            .await;
        sandbox.check(|step| {
            assert!((step).apply(&mut ctx));
            assert!(ctx.hw_is_used);
        });
    }
}
