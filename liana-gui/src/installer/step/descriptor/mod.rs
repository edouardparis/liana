pub mod editor;

use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};

use iced::{Command, Subscription};
use liana::{
    descriptors::LianaDescriptor,
    miniscript::bitcoin::{bip32::Fingerprint, Network},
};

use liana_ui::{component::form, widget::Element};

use async_hwi::DeviceKind;

use crate::{
    app::wallet::wallet_name,
    hw::{HardwareWallet, HardwareWallets},
    installer::{
        message::{self, Message},
        step::{Context, Step},
        view, Error,
    },
};

pub struct ImportDescriptor {
    network: Network,
    imported_descriptor: form::Value<String>,
    wrong_network: bool,
    error: Option<String>,
}

impl ImportDescriptor {
    pub fn new(network: Network) -> Self {
        Self {
            network,
            imported_descriptor: form::Value::default(),
            wrong_network: false,
            error: None,
        }
    }

    fn check_descriptor(&mut self, network: Network) -> Option<LianaDescriptor> {
        if !self.imported_descriptor.value.is_empty() {
            if let Ok(desc) = LianaDescriptor::from_str(&self.imported_descriptor.value) {
                if network == Network::Bitcoin {
                    self.imported_descriptor.valid = desc.all_xpubs_net_is(network);
                } else {
                    self.imported_descriptor.valid = desc.all_xpubs_net_is(Network::Testnet);
                }
                if self.imported_descriptor.valid {
                    self.wrong_network = false;
                    Some(desc)
                } else {
                    self.wrong_network = true;
                    None
                }
            } else {
                self.imported_descriptor.valid = false;
                self.wrong_network = false;
                None
            }
        } else {
            self.wrong_network = false;
            self.imported_descriptor.valid = true;
            None
        }
    }
}

impl Step for ImportDescriptor {
    // ImportRemoteWallet is used instead
    fn skip(&self, ctx: &Context) -> bool {
        ctx.remote_backend.is_some()
    }
    // form value is set as valid each time it is edited.
    // Verification of the values is happening when the user click on Next button.
    fn update(&mut self, _hws: &mut HardwareWallets, message: Message) -> Command<Message> {
        if let Message::DefineDescriptor(message::DefineDescriptor::ImportDescriptor(desc)) =
            message
        {
            self.imported_descriptor.value = desc;
            self.check_descriptor(self.network);
        }
        Command::none()
    }

    fn apply(&mut self, ctx: &mut Context) -> bool {
        ctx.bitcoin_config.network = self.network;
        // Set to true in order to force the registration process to be shown to user.
        ctx.hw_is_used = true;
        // descriptor forms for import or creation cannot be both empty or filled.
        if let Some(desc) = self.check_descriptor(self.network) {
            ctx.descriptor = Some(desc);
            true
        } else {
            false
        }
    }

    fn view<'a>(
        &'a self,
        _hws: &'a HardwareWallets,
        progress: (usize, usize),
        email: Option<&'a str>,
    ) -> Element<Message> {
        view::import_descriptor(
            progress,
            email,
            &self.imported_descriptor,
            self.wrong_network,
            self.error.as_ref(),
        )
    }
}

impl From<ImportDescriptor> for Box<dyn Step> {
    fn from(s: ImportDescriptor) -> Box<dyn Step> {
        Box::new(s)
    }
}

pub struct RegisterDescriptor {
    descriptor: Option<LianaDescriptor>,
    processing: bool,
    chosen_hw: Option<usize>,
    hmacs: Vec<(Fingerprint, DeviceKind, Option<[u8; 32]>)>,
    registered: HashSet<Fingerprint>,
    error: Option<Error>,
    done: bool,
    /// Whether this step is part of the descriptor creation process. This is used to detect when
    /// it's instead shown as part of the descriptor *import* process, where we can't detect
    /// whether a signing device is used, to explicit this step is not required if the user isn't
    /// using a signing device.
    created_desc: bool,
}

impl RegisterDescriptor {
    fn new(created_desc: bool) -> Self {
        Self {
            created_desc,
            descriptor: Default::default(),
            processing: Default::default(),
            chosen_hw: Default::default(),
            hmacs: Default::default(),
            registered: Default::default(),
            error: Default::default(),
            done: Default::default(),
        }
    }

    pub fn new_create_wallet() -> Self {
        Self::new(true)
    }

    pub fn new_import_wallet() -> Self {
        Self::new(false)
    }
}

impl Step for RegisterDescriptor {
    fn load_context(&mut self, ctx: &Context) {
        // we reset device registered set if the descriptor have changed.
        if self.descriptor != ctx.descriptor {
            self.registered = Default::default();
            self.done = false;
        }
        self.descriptor.clone_from(&ctx.descriptor);
        let mut map = HashMap::new();
        for key in ctx.keys.iter().filter(|k| !k.name.is_empty()) {
            map.insert(key.master_fingerprint, key.name.clone());
        }
    }
    fn update(&mut self, hws: &mut HardwareWallets, message: Message) -> Command<Message> {
        match message {
            Message::Select(i) => {
                if let Some(HardwareWallet::Supported {
                    device,
                    fingerprint,
                    ..
                }) = hws.list.get(i)
                {
                    if !self.registered.contains(fingerprint) {
                        let descriptor = self.descriptor.as_ref().unwrap();
                        let name = wallet_name(descriptor);
                        self.chosen_hw = Some(i);
                        self.processing = true;
                        self.error = None;
                        return Command::perform(
                            register_wallet(
                                device.clone(),
                                *fingerprint,
                                name,
                                descriptor.to_string(),
                            ),
                            Message::WalletRegistered,
                        );
                    }
                }
            }
            Message::WalletRegistered(res) => {
                self.processing = false;
                self.chosen_hw = None;
                match res {
                    Ok((fingerprint, hmac)) => {
                        if let Some(hw_h) = hws
                            .list
                            .iter()
                            .find(|hw_h| hw_h.fingerprint() == Some(fingerprint))
                        {
                            self.registered.insert(fingerprint);
                            self.hmacs.push((fingerprint, *hw_h.kind(), hmac));
                        }
                    }
                    Err(e) => {
                        if !matches!(e, Error::HardwareWallet(async_hwi::Error::UserRefused)) {
                            self.error = Some(e)
                        }
                    }
                }
            }
            Message::Reload => {
                return self.load();
            }
            Message::UserActionDone(done) => {
                self.done = done;
            }
            _ => {}
        };
        Command::none()
    }
    fn skip(&self, ctx: &Context) -> bool {
        !ctx.hw_is_used
    }
    fn apply(&mut self, ctx: &mut Context) -> bool {
        for (fingerprint, kind, token) in &self.hmacs {
            ctx.hws.push((*kind, *fingerprint, *token));
        }
        true
    }
    fn subscription(&self, hws: &HardwareWallets) -> Subscription<Message> {
        hws.refresh().map(Message::HardwareWallets)
    }
    fn load(&self) -> Command<Message> {
        Command::none()
    }
    fn view<'a>(
        &'a self,
        hws: &'a HardwareWallets,
        progress: (usize, usize),
        email: Option<&'a str>,
    ) -> Element<'a, Message> {
        let desc = self.descriptor.as_ref().unwrap();
        view::register_descriptor(
            progress,
            email,
            desc.to_string(),
            &hws.list,
            &self.registered,
            self.error.as_ref(),
            self.processing,
            self.chosen_hw,
            self.done,
            self.created_desc,
        )
    }
}

async fn register_wallet(
    hw: std::sync::Arc<dyn async_hwi::HWI + Send + Sync>,
    fingerprint: Fingerprint,
    name: String,
    descriptor: String,
) -> Result<(Fingerprint, Option<[u8; 32]>), Error> {
    let hmac = hw
        .register_wallet(&name, &descriptor)
        .await
        .map_err(Error::from)?;
    Ok((fingerprint, hmac))
}

impl From<RegisterDescriptor> for Box<dyn Step> {
    fn from(s: RegisterDescriptor) -> Box<dyn Step> {
        Box::new(s)
    }
}

#[derive(Default)]
pub struct BackupDescriptor {
    done: bool,
    descriptor: Option<LianaDescriptor>,
    key_aliases: HashMap<Fingerprint, String>,
}

impl Step for BackupDescriptor {
    fn update(&mut self, _hws: &mut HardwareWallets, message: Message) -> Command<Message> {
        if let Message::UserActionDone(done) = message {
            self.done = done;
        }
        Command::none()
    }
    fn load_context(&mut self, ctx: &Context) {
        if self.descriptor != ctx.descriptor {
            self.descriptor.clone_from(&ctx.descriptor);
            self.done = false;
        }
        self.key_aliases = ctx
            .keys
            .iter()
            .cloned()
            .map(|k| (k.master_fingerprint, k.name))
            .collect()
    }
    fn view<'a>(
        &'a self,
        _hws: &'a HardwareWallets,
        progress: (usize, usize),
        email: Option<&'a str>,
    ) -> Element<Message> {
        view::backup_descriptor(
            progress,
            email,
            self.descriptor.as_ref().expect("Must be a descriptor"),
            &self.key_aliases,
            self.done,
        )
    }
}

impl From<BackupDescriptor> for Box<dyn Step> {
    fn from(s: BackupDescriptor) -> Box<dyn Step> {
        Box::new(s)
    }
}