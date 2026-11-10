use super::{
    model::{count, duration, timestamp},
    style::{button, icon, label, line, mono, ButtonStyle, Icon, Palette},
    Appearance, Desktop, Dismiss, Find, NextFocus, Page, PreviousFocus, RunScan, ToggleInspector,
};
use gpui::{prelude::*, *};
use gpui_component::{theme::ThemeMode, Theme};

impl Render for Desktop {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let dark = match self.preferences.appearance {
            Appearance::System => matches!(
                window.appearance(),
                WindowAppearance::Dark | WindowAppearance::VibrantDark
            ),
            Appearance::Light => false,
            Appearance::Dark => true,
        };
        let mode = if dark {
            ThemeMode::Dark
        } else {
            ThemeMode::Light
        };
        if Theme::global(cx).mode != mode {
            Theme::change(mode, Some(window), cx);
        }
        self.palette = if dark {
            Palette::dark()
        } else {
            Palette::light()
        };
        window.set_rem_size(px(match self.preferences.text_size {
            1 => 18.,
            2 => 20.,
            _ => 16.,
        }));
        let p = self.palette;
        let narrow = window.viewport_size().width < px(1120.);
        let root = div()
            .size_full()
            .min_h_0()
            .bg(rgb(p.canvas))
            .text_color(rgb(p.ink))
            .font(font("Segoe UI"))
            .text_size(rems(0.86))
            .track_focus(&self.focus)
            .key_context("Registry")
            .flex()
            .flex_col()
            .on_action(cx.listener(|this, _: &RunScan, window, cx| this.scan(window, cx)))
            .on_action(cx.listener(|this, _: &Find, window, cx| {
                if (this.page.has_results() || this.page == Page::Backups) && this.review.is_none()
                {
                    this.input.update(cx, |input, cx| input.focus(window, cx));
                }
            }))
            .on_action(cx.listener(|this, _: &Dismiss, window, cx| this.dismiss(window, cx)))
            .on_action(cx.listener(|this, _: &ToggleInspector, window, cx| {
                this.toggle_inspector(window, cx)
            }))
            .on_action(|_: &NextFocus, window, _| window.focus_next())
            .on_action(|_: &PreviousFocus, window, _| window.focus_prev());
        if let Some(review) = &self.review {
            return root.child(self.review_panel(review, cx));
        }
        let content = match self.page {
            Page::Explorer | Page::Clean | Page::Leftovers => {
                self.results(narrow, cx).into_any_element()
            }
            Page::Coverage => self.coverage(cx).into_any_element(),
            Page::History => self.history(cx).into_any_element(),
            Page::Backups => self.backups(cx).into_any_element(),
            Page::Recovery => self.recovery(cx).into_any_element(),
            Page::Settings => self.settings(cx).into_any_element(),
        };
        root.child(
            div()
                .flex()
                .flex_1()
                .min_h_0()
                .child(self.rail(narrow, cx))
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .flex_1()
                        .min_w_0()
                        .min_h_0()
                        .child(self.top_bar(cx))
                        .child(self.page_heading(narrow, cx))
                        .when_some(self.notice.as_ref(), |body, notice| {
                            body.child(
                                div()
                                    .mx(px(if narrow { 18. } else { 28. }))
                                    .mb_3()
                                    .p_3()
                                    .flex()
                                    .items_start()
                                    .justify_between()
                                    .gap_3()
                                    .bg(rgb(p.panel))
                                    .border_1()
                                    .border_color(rgb(if notice.error { p.error } else { p.line }))
                                    .rounded(px(5.))
                                    .child(
                                        div()
                                            .flex()
                                            .flex_col()
                                            .gap_1()
                                            .min_w_0()
                                            .flex_1()
                                            .child(
                                                div()
                                                    .font_weight(FontWeight::SEMIBOLD)
                                                    .child(notice.title.clone()),
                                            )
                                            .children(notice.details.iter().take(6).map(
                                                |detail| {
                                                    div()
                                                        .text_size(rems(0.76))
                                                        .text_color(rgb(p.muted))
                                                        .child(detail.clone())
                                                },
                                            )),
                                    )
                                    .child(
                                        button(
                                            p,
                                            "close-notice",
                                            "Dismiss",
                                            Some(Icon::Close),
                                            ButtonStyle::Quiet,
                                            true,
                                        )
                                        .on_click(
                                            cx.listener(|this, _, _, cx| {
                                                this.notice = None;
                                                cx.notify();
                                            }),
                                        ),
                                    ),
                            )
                        })
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .flex_1()
                                .min_h_0()
                                .px(px(if narrow { 18. } else { 28. }))
                                .pb_4()
                                .child(content),
                        ),
                ),
        )
        .child(self.status_bar(cx))
    }
}

impl Desktop {
    fn rail(&self, narrow: bool, cx: &mut Context<Self>) -> Div {
        let p = self.palette;
        let brand = div()
            .flex()
            .items_center()
            .gap_2()
            .px_3()
            .h(px(64.))
            .flex_shrink_0()
            .child(
                div()
                    .size(px(33.))
                    .flex()
                    .items_center()
                    .justify_center()
                    .border_1()
                    .border_color(rgb(p.rail_line))
                    .rounded(px(6.))
                    .child(icon(Icon::Grid, p.copper, 20.)),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .child(
                        div()
                            .text_size(rems(1.00))
                            .font_weight(FontWeight::SEMIBOLD)
                            .child("RustRegistry"),
                    )
                    .child(
                        div()
                            .text_size(rems(0.69))
                            .text_color(rgb(p.rail_muted))
                            .child("Windows registry doctor"),
                    ),
            );
        let mut links = div()
            .id("nav-scroll")
            .flex()
            .flex_col()
            .min_h_0()
            .flex_1()
            .overflow_y_scroll()
            .px_2();
        for (heading, pages) in [
            (
                "INSPECTION",
                &[
                    Page::Explorer,
                    Page::Leftovers,
                    Page::Coverage,
                    Page::History,
                ][..],
            ),
            ("CHANGES", &[Page::Clean, Page::Backups, Page::Recovery][..]),
        ] {
            links = links
                .child(
                    div()
                        .pt_5()
                        .pb_2()
                        .px_2()
                        .child(label(heading, p.rail_muted)),
                )
                .children(pages.iter().map(|&page| self.nav(page, cx)));
        }
        div()
            .flex()
            .flex_col()
            .w(px(if narrow { 188. } else { 218. }))
            .flex_shrink_0()
            .bg(rgb(p.rail))
            .text_color(rgb(p.rail_text))
            .px_2()
            .child(brand)
            .child(div().mx_3().h(px(1.)).bg(rgb(p.rail_line)))
            .child(links)
            .child(
                div()
                    .mx_2()
                    .py_3()
                    .border_t_1()
                    .border_color(rgb(p.rail_line))
                    .child(self.nav(Page::Settings, cx)),
            )
    }

    fn nav(&self, page: Page, cx: &mut Context<Self>) -> Stateful<Div> {
        let p = self.palette;
        let active = page == self.page;
        div()
            .id(page.title())
            .debug_selector(|| page.title().to_string())
            .h(px(36.))
            .mb(px(2.))
            .rounded(px(4.))
            .px_2()
            .gap_2()
            .flex()
            .items_center()
            .border_1()
            .border_color(rgb(if active { p.rail_line } else { p.rail }))
            .bg(rgb(if active { p.rail_active } else { p.rail }))
            .text_color(rgb(if active { p.rail_text } else { p.rail_muted }))
            .when(active, |d| d.font_weight(FontWeight::SEMIBOLD))
            .text_size(rems(0.79))
            .child(icon(
                page.icon(),
                if active { p.copper } else { p.rail_muted },
                15.,
            ))
            .child(div().truncate().child(page.title()))
            .when(self.job.is_none(), |d| {
                d.focusable()
                    .tab_stop(true)
                    .cursor_pointer()
                    .hover(|d| d.bg(rgb(p.rail_active)))
                    .focus(|d| d.border_color(rgb(p.copper)))
                    .on_click(
                        cx.listener(move |this, _, window, cx| this.set_page(page, window, cx)),
                    )
            })
    }

    fn top_bar(&self, cx: &mut Context<Self>) -> Div {
        let p = self.palette;
        let scan_enabled = self.job.is_none() && self.store.is_some();
        let scan_label = if self.report.is_some() {
            "Scan again"
        } else {
            "Run scan"
        };
        let source = if self.archived {
            "Saved scan"
        } else {
            "Local registry"
        };
        div()
            .flex()
            .items_center()
            .justify_between()
            .h(px(57.))
            .flex_shrink_0()
            .px_5()
            .border_b_1()
            .border_color(rgb(p.line))
            .bg(rgb(p.panel))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .min_w_0()
                    .child(icon(
                        if self.archived {
                            Icon::Archive
                        } else {
                            Icon::Grid
                        },
                        p.accent,
                        15.,
                    ))
                    .child(
                        div()
                            .flex_shrink_0()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(source),
                    )
                    .when_some(self.report.as_ref(), |d, report| {
                        d.child(
                            div()
                                .truncate()
                                .text_color(rgb(p.muted))
                                .text_size(rems(0.77))
                                .child(timestamp(report.started_at)),
                        )
                    }),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        div()
                            .font(mono())
                            .text_size(rems(0.7))
                            .text_color(rgb(p.muted))
                            .child("Ctrl+R"),
                    )
                    .child(
                        button(
                            p,
                            "run-scan",
                            scan_label,
                            Some(Icon::Scan),
                            ButtonStyle::Primary,
                            scan_enabled,
                        )
                        .when(scan_enabled, |d| {
                            d.on_click(cx.listener(|this, _, window, cx| this.scan(window, cx)))
                        }),
                    ),
            )
    }

    fn page_heading(&self, narrow: bool, cx: &mut Context<Self>) -> Div {
        let p = self.palette;
        let (title, description) = match self.page {
            Page::Explorer => ("Registry health", "Inspect references, startup entries and application registrations."),
            Page::Leftovers => ("Application leftovers", "Inspect correlated records from removed applications and the evidence behind each finding."),
            Page::Clean => ("Clean registry", "Review eligible changes and their exact registry values before applying them."),
            Page::Coverage => ("Scan coverage", "See which registry sections were read and where Windows limited access."),
            Page::History => ("Saved scans", "Reopen a local scan to inspect its findings and coverage."),
            Page::Backups => ("Backups & restore", "Inspect original registry values and review individual or bulk restoration."),
            Page::Recovery => ("Recovery Center", "Inspect completed and interrupted changes, and review what can be undone."),
            Page::Settings => ("Settings", "Set the appearance and text size for this workstation."),
        };
        let mut heading = div()
            .pt_5()
            .pb_4()
            .px(px(if narrow { 18. } else { 28. }))
            .flex_shrink_0()
            .flex()
            .items_end()
            .justify_between()
            .gap_3()
            .child(
                div()
                    .min_w_0()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        div()
                            .text_size(rems(2.12))
                            .line_height(rems(2.30))
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(title),
                    )
                    .child(
                        div()
                            .text_color(rgb(p.muted))
                            .text_size(rems(0.87))
                            .child(description),
                    ),
            );
        if matches!(self.page, Page::Backups | Page::Recovery | Page::History) {
            let page = self.page;
            let enabled = self.job.is_none() && self.store.is_some();
            heading = heading.child(
                button(
                    p,
                    "refresh-inventory",
                    "Refresh",
                    Some(Icon::Restore),
                    ButtonStyle::Secondary,
                    enabled,
                )
                .when(enabled, |d| {
                    d.on_click(
                        cx.listener(move |this, _, window, cx| this.refresh(page, window, cx)),
                    )
                }),
            );
        }
        heading
    }

    fn status_bar(&self, cx: &mut Context<Self>) -> Div {
        let p = self.palette;
        let mut bar = div()
            .flex()
            .h(px(36.))
            .items_center()
            .justify_between()
            .gap_3()
            .flex_shrink_0()
            .px_3()
            .bg(rgb(p.panel))
            .border_t_1()
            .border_color(rgb(p.line))
            .text_size(rems(0.73))
            .text_color(rgb(p.muted));
        if let Some(job) = &self.job {
            let title = if job.control.stopped() {
                "Stopping after the current item…"
            } else {
                job.title
            };
            bar = bar.child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .min_w_0()
                    .flex_1()
                    .child(icon(Icon::Scan, p.accent, 14.))
                    .child(
                        div()
                            .flex_shrink_0()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(title),
                    )
                    .when_some(job.progress.as_ref(), |d, progress| {
                        d.child(div().min_w_0().truncate().child(progress.current.clone()))
                            .child(
                                div()
                                    .flex_shrink_0()
                                    .font(mono())
                                    .child(format!("{}/{}", progress.completed, progress.total)),
                            )
                            .when_some(progress.entries, |d, entries| {
                                d.child(format!("{} entries", count(entries)))
                            })
                    }),
            );
            if job.stoppable && !job.control.stopped() {
                bar = bar.child(
                    button(p, "stop-job", "Stop", None, ButtonStyle::Quiet, true)
                        .h(px(28.))
                        .on_click(cx.listener(|this, _, _, cx| {
                            if let Some(job) = &this.job {
                                job.control.stop();
                            }
                            cx.notify();
                        })),
                );
            }
            return bar;
        }
        let scan_state = match (self.archived, self.stale, self.report.as_deref()) {
            (true, _, _) => "Saved scan · read-only",
            (_, true, _) => "Registry changed · run a fresh scan",
            (_, _, Some(report)) if report.cancelled => "Scan stopped · partial results",
            (_, _, Some(_)) => "Live scan complete",
            _ => "Ready · scan is read-only",
        };
        bar.child(
            div()
                .flex()
                .items_center()
                .gap_2()
                .child(icon(Icon::Shield, p.accent, 14.))
                .child(scan_state),
        )
        .child(self.report.as_ref().map_or_else(
            || "Windows Registry".to_string(),
            |report| {
                format!(
                    "{} sections   ·   {}",
                    count(report.scopes.len()),
                    duration(report.duration_ms)
                )
            },
        ))
    }

    fn settings(&self, cx: &mut Context<Self>) -> Div {
        let p = self.palette;
        let mut theme = div().flex().gap_2().flex_wrap();
        for (title, appearance) in [
            ("System", Appearance::System),
            ("Light", Appearance::Light),
            ("Dark", Appearance::Dark),
        ] {
            let style = if appearance == self.preferences.appearance {
                ButtonStyle::Selected
            } else {
                ButtonStyle::Secondary
            };
            theme = theme.child(
                button(p, title, title, None, style, true).on_click(cx.listener(
                    move |this, _, _, cx| {
                        this.preferences.appearance = appearance;
                        this.save_preferences(cx);
                    },
                )),
            );
        }
        let mut sizes = div().flex().gap_2().flex_wrap();
        for (size, title) in ["Default", "Large", "Extra large"].into_iter().enumerate() {
            let style = if size == self.preferences.text_size {
                ButtonStyle::Selected
            } else {
                ButtonStyle::Secondary
            };
            sizes = sizes.child(
                button(p, title, title, None, style, true).on_click(cx.listener(
                    move |this, _, _, cx| {
                        this.preferences.text_size = size;
                        this.save_preferences(cx);
                    },
                )),
            );
        }
        div()
            .flex()
            .flex_col()
            .max_w(px(720.))
            .gap_4()
            .p_4()
            .bg(rgb(p.panel))
            .border_1()
            .border_color(rgb(p.line))
            .rounded(px(6.))
            .child(label("APPEARANCE", p.muted))
            .child(theme)
            .child(line(p))
            .child(label("TEXT SIZE", p.muted))
            .child(sizes)
            .child(line(p))
            .child(label("LOCAL DATA", p.muted))
            .child(
                div()
                    .font(mono())
                    .text_size(rems(0.77))
                    .child(self.store.as_ref().map_or_else(
                        || "Unavailable".into(),
                        |s| s.directory.display().to_string(),
                    )),
            )
            .child(div().text_color(rgb(p.muted)).child(format!(
                "RustRegistry {} · MIT license",
                env!("CARGO_PKG_VERSION")
            )))
    }
}
