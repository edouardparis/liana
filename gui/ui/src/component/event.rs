use crate::{
    color,
    component::{amount, badge, text},
    theme,
    widget::*,
};
use bitcoin::Amount;
use iced::{
    widget::{button, row},
    Alignment, Length,
};

use chrono::{DateTime, Local, Utc};

pub fn unconfirmed_outgoing_event<'a, T: Clone + 'a>(
    label: Option<Text<'a>>,
    amount: &Amount,
    msg: T,
) -> Container<'a, T> {
    Container::new(
        button(
            row!(
                row!(badge::spend(), Column::new().push_maybe(label),)
                    .spacing(10)
                    .align_items(Alignment::Center)
                    .width(Length::Fill),
                badge::unconfirmed(),
                row!(text::p1_regular("-"), amount::amount(amount))
                    .spacing(5)
                    .align_items(Alignment::Center),
            )
            .align_items(Alignment::Center)
            .padding(5)
            .spacing(20),
        )
        .on_press(msg)
        .style(theme::Button::TransparentBorder),
    )
    .style(theme::Container::Card(theme::Card::Simple))
}

pub fn confirmed_outgoing_event<'a, T: Clone + 'a>(
    label: Option<Text<'a>>,
    date: DateTime<Utc>,
    amount: &Amount,
    msg: T,
) -> Container<'a, T> {
    Container::new(
        button(
            row!(
                row!(
                    badge::spend(),
                    Column::new().push_maybe(label).push(
                        text::p2_regular(
                            date.with_timezone(&Local)
                                .format("%b. %d, %Y - %T")
                                .to_string()
                        )
                        .style(color::GREY_3)
                    )
                )
                .spacing(10)
                .align_items(Alignment::Center)
                .width(Length::Fill),
                row!(text::p1_regular("-"), amount::amount(amount))
                    .spacing(5)
                    .align_items(Alignment::Center),
            )
            .align_items(Alignment::Center)
            .padding(5)
            .spacing(20),
        )
        .on_press(msg)
        .style(theme::Button::TransparentBorder),
    )
    .style(theme::Container::Card(theme::Card::Simple))
}

pub fn unconfirmed_incoming_event<'a, T: Clone + 'a>(
    label: Option<Text<'a>>,
    amount: &Amount,
    msg: T,
) -> Container<'a, T> {
    Container::new(
        button(
            row!(
                row!(badge::receive(), Column::new().push_maybe(label))
                    .spacing(10)
                    .align_items(Alignment::Center)
                    .width(Length::Fill),
                badge::unconfirmed(),
                row!(text::p1_regular("+"), amount::amount(amount))
                    .spacing(5)
                    .align_items(Alignment::Center),
            )
            .align_items(Alignment::Center)
            .padding(5)
            .spacing(20),
        )
        .on_press(msg)
        .style(theme::Button::TransparentBorder),
    )
    .style(theme::Container::Card(theme::Card::Simple))
}

pub fn confirmed_incoming_event<'a, T: Clone + 'a>(
    label: Option<Text<'a>>,
    date: DateTime<Utc>,
    amount: &Amount,
    msg: T,
) -> Container<'a, T> {
    Container::new(
        button(
            row!(
                row!(
                    badge::receive(),
                    Column::new().push_maybe(label).push(
                        text::p2_regular(
                            date.with_timezone(&Local)
                                .format("%b. %d, %Y - %T")
                                .to_string()
                        )
                        .style(color::GREY_3)
                    )
                )
                .spacing(10)
                .align_items(Alignment::Center)
                .width(Length::Fill),
                row!(text::p1_regular("+"), amount::amount(amount))
                    .spacing(5)
                    .align_items(Alignment::Center),
            )
            .align_items(Alignment::Center)
            .padding(5)
            .spacing(20),
        )
        .on_press(msg)
        .style(theme::Button::TransparentBorder),
    )
    .style(theme::Container::Card(theme::Card::Simple))
}
