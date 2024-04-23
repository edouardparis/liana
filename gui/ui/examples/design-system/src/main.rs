mod section;

use iced::widget::{button, column, container, row, scrollable, text, Space};
use iced::{executor, Application, Command, Length, Settings, Subscription};
use liana_ui::{component::text::*, font, image, theme, widget::*};

pub fn main() -> iced::Result {
    let mut settings = Settings::with_flags(Config {});
    settings.default_text_size = P1_SIZE.into();
    settings.default_font = font::REGULAR;
    DesignSystem::run(settings)
}

struct Config {}

#[derive(Default)]
struct DesignSystem {
    theme: theme::Theme,
    sections: Vec<Box<dyn Section>>,
    current: usize,
}

#[derive(Debug, Clone)]
pub enum Message {
    FontLoaded(Result<(), iced::font::Error>),
    Event(iced::Event),
    Section(usize),
    Ignore,
}

impl From<Result<(), iced::font::Error>> for Message {
    fn from(res: Result<(), iced::font::Error>) -> Message {
        Message::FontLoaded(res)
    }
}

impl Application for DesignSystem {
    type Message = Message;
    type Theme = theme::Theme;
    type Flags = Config;
    type Executor = executor::Default;

    fn title(&self) -> String {
        String::from("Liana - Design System")
    }

    fn new(_config: Config) -> (Self, Command<Self::Message>) {
        let app = Self {
            theme: theme::Theme::Dark,
            sections: vec![
                Box::new(section::Overview {}),
                Box::new(section::Colors {}),
                Box::new(section::Typography {}),
                Box::new(section::Buttons {}),
                Box::new(section::HardwareWallets {}),
                Box::new(section::Events {}),
            ],
            current: 0,
        };
        #[allow(unused_mut)]
        let mut cmds: Vec<Command<Self::Message>> = font::loads();

        #[cfg(target_arch = "wasm32")]
        {
            use iced_native::{command, window};
            let window = web_sys::window().unwrap();
            let (width, height) = (
                (window.inner_width().unwrap().as_f64().unwrap()) as u32,
                (window.inner_height().unwrap().as_f64().unwrap()) as u32,
            );
            cmds.push(Command::single(command::Action::Window(
                window::Action::Resize { width, height },
            )));
        }

        (app, Command::batch(cmds))
    }

    fn update(&mut self, message: Message) -> Command<Self::Message> {
        match message {
            Message::Section(i) => {
                if self.sections.get(i).is_some() {
                    self.current = i;
                }
            }
            Message::Event(iced::Event::Window(iced::window::Event::Resized { width, height })) => {
                #[cfg(target_arch = "wasm32")]
                {
                    use iced_native::{command, window};
                    return Command::single(command::Action::Window(window::Action::Resize {
                        width,
                        height,
                    }));
                }
            }
            _ => {}
        }
        Command::none()
    }

    fn subscription(&self) -> Subscription<Self::Message> {
        iced::subscription::events().map(Self::Message::Event)
    }

    fn view(&self) -> Element<Message> {
        let sidebar = container(
            column![
                image::liana_grey_logo(),
                Space::with_height(Length::Fixed(100.0)),
                self.sections.iter().enumerate().fold(
                    Column::new().spacing(10),
                    |col, (i, section)| col.push(
                        button(
                            container(text(section.title()))
                                .width(Length::Fill)
                                .padding(10)
                        )
                        .style(theme::Button::Menu(i == self.current))
                        .on_press(Message::Section(i))
                        .width(Length::Fixed(200.0))
                    )
                )
            ]
            .spacing(20),
        )
        .padding(20)
        .style(theme::Container::Foreground)
        .height(Length::Fill);

        container(row![
            sidebar.width(Length::FillPortion(2)),
            Space::with_width(Length::FillPortion(1)),
            container(scrollable(column![
                Space::with_height(Length::Fixed(150.0)),
                container(self.sections[self.current].view()).width(Length::Fill)
            ]))
            .width(Length::FillPortion(8)),
            Space::with_width(Length::FillPortion(1)),
        ])
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }

    fn theme(&self) -> theme::Theme {
        self.theme.clone()
    }
}

pub trait Section {
    fn title(&self) -> &'static str;
    fn view(&self) -> Element<Message>;
}
