use iced::{
    widget::{
        container,
        scrollable::{Catalog, Rail, Scroller, Status, Style, StyleFn},
    },
    Border, Color, Shadow,
};

use super::Theme;

impl Catalog for Theme {
    type Class<'a> = StyleFn<'a, Self>;

    fn default<'a>() -> Self::Class<'a> {
        Box::new(primary)
    }

    fn style(&self, class: &Self::Class<'_>, status: Status) -> Style {
        class(self, status)
    }
}

pub fn primary(theme: &Theme, status: Status) -> Style {
    let rail = Rail {
        background: None,
        border: Border::default(),
        scroller: Scroller {
            color: theme.colors.general.scrollable,
            border: Border {
                radius: 8.0.into(),
                width: 0.0,
                color: Color::TRANSPARENT,
            },
        },
    };

    match status {
        Status::Active { .. } | Status::Hovered { .. } | Status::Dragged { .. } => Style {
            container: container::Style {
                text_color: None,
                background: None,
                border: Border {
                    radius: 8.0.into(),
                    width: 1.0,
                    color: Color::TRANSPARENT,
                },
                shadow: Shadow::default(),
            },
            vertical_rail: rail,
            horizontal_rail: rail,
            gap: None,
        },
    }
}
