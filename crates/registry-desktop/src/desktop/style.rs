use gpui::{prelude::*, *};

#[derive(Clone, Copy)]
pub struct Palette {
    pub canvas: u32,
    pub panel: u32,
    pub soft: u32,
    pub line: u32,
    pub ink: u32,
    pub muted: u32,
    pub accent: u32,
    pub action: u32,
    pub on_action: u32,
    pub selected: u32,
    pub review: u32,
    pub found: u32,
    pub error: u32,
    pub rail: u32,
    pub rail_line: u32,
    pub rail_text: u32,
    pub rail_muted: u32,
    pub rail_active: u32,
    pub copper: u32,
}

impl Palette {
    pub const fn light() -> Self {
        Self {
            canvas: 0xf5f5f0,
            panel: 0xfffefa,
            soft: 0xf0f1ec,
            line: 0xdedfd6,
            ink: 0x202d2a,
            muted: 0x58645f,
            accent: 0x30594e,
            action: 0x244c40,
            on_action: 0xffffff,
            selected: 0xe7efe7,
            review: 0x964f19,
            found: 0x34634d,
            error: 0xa23331,
            rail: 0x202b28,
            rail_line: 0x3d4a44,
            rail_text: 0xf4f3e9,
            rail_muted: 0xb1beb3,
            rail_active: 0x36483d,
            copper: 0xf2ab72,
        }
    }

    pub const fn dark() -> Self {
        Self {
            canvas: 0x1d2421,
            panel: 0x232c27,
            soft: 0x29342d,
            line: 0x404e44,
            ink: 0xf3f1e7,
            muted: 0xb1bfb2,
            accent: 0xa7d0b6,
            action: 0xb9d9bf,
            on_action: 0x1d3429,
            selected: 0x35483b,
            review: 0xf0ad76,
            found: 0xa5cfaf,
            error: 0xf3a19a,
            rail: 0x151e19,
            rail_line: 0x36443a,
            rail_text: 0xf4f3e9,
            rail_muted: 0xb1beb3,
            rail_active: 0x303f35,
            copper: 0xf2ab72,
        }
    }
}

#[derive(Clone, Copy)]
pub enum Icon {
    Grid,
    Layers,
    Clean,
    Coverage,
    Clock,
    Archive,
    Restore,
    Settings,
    Scan,
    Search,
    Chevron,
    Right,
    Copy,
    Close,
    Check,
    File,
    ArrowDown,
    Shield,
    Plus,
}

impl Icon {
    fn paths(self) -> &'static [&'static [(f32, f32)]] {
        match self {
            Self::Grid => &[
                &[(2., 2.), (7., 2.), (7., 7.), (2., 7.), (2., 2.)],
                &[(10., 2.), (15., 2.), (15., 7.), (10., 7.), (10., 2.)],
                &[(2., 10.), (7., 10.), (7., 15.), (2., 15.), (2., 10.)],
                &[(10., 10.), (15., 10.), (15., 15.), (10., 15.), (10., 10.)],
            ],
            Self::Layers => &[
                &[(1.5, 5.5), (8.5, 2.), (15.5, 5.5), (8.5, 9.), (1.5, 5.5)],
                &[(1.5, 9.), (8.5, 12.5), (15.5, 9.)],
                &[(1.5, 12.5), (8.5, 16.), (15.5, 12.5)],
            ],
            Self::Clean => &[
                &[(4., 13.), (11., 6.), (14., 9.), (7., 16.), (4., 13.)],
                &[(3., 2.), (3., 7.)],
                &[(0.5, 4.5), (5.5, 4.5)],
                &[(13., 1.), (13., 5.)],
                &[(11., 3.), (15., 3.)],
            ],
            Self::Coverage => &[
                &[(2., 3.), (15., 3.), (15., 14.), (2., 14.), (2., 3.)],
                &[(5., 7.), (7., 7.)],
                &[(5., 10.), (7., 10.)],
                &[(10., 7.), (12., 7.)],
                &[(10., 10.), (12., 10.)],
            ],
            Self::Clock => &[
                &[
                    (8.5, 1.5),
                    (13., 3.),
                    (15.5, 7.),
                    (15., 11.5),
                    (12., 15.),
                    (7., 15.5),
                    (3., 13.5),
                    (1.5, 9.),
                    (2.5, 4.5),
                    (8.5, 1.5),
                ],
                &[(8.5, 4.5), (8.5, 8.5), (11.5, 10.)],
            ],
            Self::Archive => &[
                &[(2., 2.5), (15., 2.5), (15., 6.), (2., 6.), (2., 2.5)],
                &[(3., 6.), (3., 14.5), (14., 14.5), (14., 6.)],
                &[(6.5, 9.), (10.5, 9.)],
            ],
            Self::Restore => &[
                &[(2., 3.), (2., 8.), (7., 8.)],
                &[
                    (2., 8.),
                    (4., 4.),
                    (8.5, 2.5),
                    (13., 4.),
                    (15., 8.5),
                    (13.5, 12.5),
                    (10., 14.5),
                    (6., 14.5),
                    (3.5, 12.5),
                ],
            ],
            Self::Settings => &[
                &[(2., 4.), (6., 4.)],
                &[(9., 4.), (15., 4.)],
                &[(6., 2.), (6., 6.)],
                &[(2., 8.5), (10., 8.5)],
                &[(13., 8.5), (15., 8.5)],
                &[(10., 6.5), (10., 10.5)],
                &[(2., 13.), (5., 13.)],
                &[(8., 13.), (15., 13.)],
                &[(5., 11.), (5., 15.)],
            ],
            Self::Scan => &[
                &[(2., 6.), (2., 2.), (6., 2.)],
                &[(11., 2.), (15., 2.), (15., 6.)],
                &[(15., 11.), (15., 15.), (11., 15.)],
                &[(6., 15.), (2., 15.), (2., 11.)],
                &[(4.5, 8.5), (12.5, 8.5)],
            ],
            Self::Search => &[
                &[
                    (7., 1.5),
                    (10., 2.5),
                    (12., 5.5),
                    (12., 8.5),
                    (10., 11.),
                    (7., 12.),
                    (4., 11.),
                    (2., 8.5),
                    (2., 5.5),
                    (4., 2.5),
                    (7., 1.5),
                ],
                &[(11., 11.), (15., 15.)],
            ],
            Self::Chevron => &[&[(4., 6.5), (8.5, 11.), (13., 6.5)]],
            Self::Right => &[
                &[(3., 8.5), (14., 8.5)],
                &[(10., 4.5), (14., 8.5), (10., 12.5)],
            ],
            Self::Copy => &[
                &[(5., 5.), (14.5, 5.), (14.5, 15.), (5., 15.), (5., 5.)],
                &[(11.5, 2.), (2., 2.), (2., 12.)],
            ],
            Self::Close => &[&[(4., 4.), (13., 13.)], &[(13., 4.), (4., 13.)]],
            Self::Check => &[&[(3., 8.5), (7., 12.5), (14., 4.5)]],
            Self::File => &[
                &[
                    (3., 2.),
                    (10., 2.),
                    (14., 6.),
                    (14., 15.),
                    (3., 15.),
                    (3., 2.),
                ],
                &[(10., 2.), (10., 6.), (14., 6.)],
                &[(6., 9.), (11., 9.)],
                &[(6., 12.), (11., 12.)],
            ],
            Self::ArrowDown => &[
                &[(8.5, 2.), (8.5, 11.)],
                &[(5., 8.), (8.5, 11.5), (12., 8.)],
                &[(3., 13.), (3., 15.), (14., 15.), (14., 13.)],
            ],
            Self::Shield => &[
                &[
                    (8.5, 1.5),
                    (14.5, 4.),
                    (14., 10.),
                    (12., 13.),
                    (8.5, 15.5),
                    (5., 13.),
                    (3., 10.),
                    (2.5, 4.),
                    (8.5, 1.5),
                ],
                &[(5.5, 8.), (7.5, 10.), (11.5, 6.)],
            ],
            Self::Plus => &[&[(4., 8.5), (13., 8.5)], &[(8.5, 4.), (8.5, 13.)]],
        }
    }
}

pub fn icon(symbol: Icon, color: u32, size: f32) -> impl IntoElement {
    canvas(
        move |bounds, _, _| {
            let scale = size / 17.;
            let mut path = PathBuilder::stroke(px(scale * 1.35));
            for points in symbol.paths() {
                for (index, (x, y)) in points.iter().enumerate() {
                    let p = bounds.origin + point(px(x * scale), px(y * scale));
                    if index == 0 {
                        path.move_to(p);
                    } else {
                        path.line_to(p);
                    }
                }
            }
            path.build().ok()
        },
        move |_, path, window, _| {
            if let Some(path) = path {
                window.paint_path(path, rgb(color));
            }
        },
    )
    .size(px(size))
    .flex_shrink_0()
}

#[derive(Clone, Copy)]
pub enum ButtonStyle {
    Primary,
    Secondary,
    Quiet,
    Selected,
}

pub fn button(
    palette: Palette,
    id: impl Into<ElementId>,
    title: impl Into<SharedString>,
    symbol: Option<Icon>,
    style: ButtonStyle,
    enabled: bool,
) -> Stateful<Div> {
    let id = id.into();
    #[cfg(test)]
    let selector = id.to_string();
    let (background, border, color) = match style {
        ButtonStyle::Primary => (palette.action, palette.action, palette.on_action),
        ButtonStyle::Secondary => (palette.panel, palette.line, palette.ink),
        ButtonStyle::Quiet => (palette.canvas, palette.canvas, palette.muted),
        ButtonStyle::Selected => (palette.selected, palette.selected, palette.accent),
    };
    let color = if enabled { color } else { palette.muted };
    let background = if enabled { background } else { palette.soft };
    let control = div()
        .id(id)
        .h(px(34.))
        .px_3()
        .gap_2()
        .flex()
        .items_center()
        .justify_center()
        .flex_shrink_0()
        .rounded(px(5.))
        .border_1()
        .border_color(rgb(if enabled { border } else { palette.line }))
        .bg(rgb(background))
        .text_color(rgb(color))
        .text_size(rems(0.79))
        .font_weight(FontWeight::MEDIUM)
        .when_some(symbol, |control, symbol| {
            control.child(icon(symbol, color, 14.))
        })
        .child(title.into());
    #[cfg(test)]
    let control = control.debug_selector(|| selector);
    control.when(enabled, |control| {
        control
            .focusable()
            .tab_stop(true)
            .cursor_pointer()
            .hover(|style| style.opacity(0.83))
            .focus(|style| style.border_color(rgb(palette.accent)))
    })
}

pub fn label(text: impl Into<SharedString>, color: u32) -> Div {
    div()
        .text_size(rems(0.68))
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(rgb(color))
        .child(text.into())
}

pub fn line(palette: Palette) -> Div {
    div()
        .h(px(1.))
        .w_full()
        .flex_shrink_0()
        .bg(rgb(palette.line))
}

pub fn mono() -> Font {
    font("Consolas")
}

pub fn field(
    palette: Palette,
    title: &str,
    value: impl Into<SharedString>,
    technical: bool,
) -> Div {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .w_full()
        .min_w_0()
        .child(label(title.to_uppercase(), palette.muted))
        .child(
            div()
                .text_size(rems(0.83))
                .text_color(rgb(palette.ink))
                .when(technical, |d| {
                    d.font(mono()).p_2().bg(rgb(palette.soft)).rounded(px(4.))
                })
                .child(value.into()),
        )
}
