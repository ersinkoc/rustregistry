use super::{
    model::{category_name, count, location, status_name, view_name, CATEGORIES},
    style::{button, field, icon, label, line, mono, ButtonStyle, Icon},
    Desktop, NextEntry, Page, PreviousEntry,
};
use gpui::{prelude::*, *};
use gpui_component::{input::Input, scroll::ScrollableElement};
use registry_core::{changes::is_repair_candidate, EntryStatus, RegistryEntry};

impl Desktop {
    pub(super) fn results(&self, narrow: bool, cx: &mut Context<Self>) -> Div {
        let p = self.palette;
        let clean = self.page == Page::Clean;
        let enabled = self.job.is_none() && self.fresh_report().is_some();
        let display_table = self.report.is_some() && (!clean || !self.archived);
        let mut main = div().flex().flex_col().flex_1().min_w_0().min_h_0().gap_3();
        if self.page == Page::Explorer {
            main = main.child(self.summary(cx));
        }
        if clean {
            let has_checked = enabled && !self.checked.is_empty();
            main = main.child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .flex_wrap()
                    .child(
                        button(
                            p,
                            "review-selected",
                            format!("Review selected ({})", count(self.checked.len())),
                            Some(Icon::Check),
                            ButtonStyle::Primary,
                            has_checked,
                        )
                        .when(has_checked, |d| {
                            d.on_click(
                                cx.listener(|this, _, w, cx| this.prepare_clean("selected", w, cx)),
                            )
                        }),
                    )
                    .child(
                        button(
                            p,
                            "review-quick",
                            "Quick clean",
                            None,
                            ButtonStyle::Secondary,
                            enabled,
                        )
                        .when(enabled, |d| {
                            d.on_click(
                                cx.listener(|this, _, w, cx| this.prepare_clean("quick", w, cx)),
                            )
                        }),
                    )
                    .child(
                        button(
                            p,
                            "review-full",
                            "Full clean",
                            None,
                            ButtonStyle::Secondary,
                            enabled,
                        )
                        .when(enabled, |d| {
                            d.on_click(
                                cx.listener(|this, _, w, cx| this.prepare_clean("full", w, cx)),
                            )
                        }),
                    ),
            );
            main = main.child(div().text_size(rems(0.76)).text_color(rgb(p.muted))
                .child("Quick clean follows the category filter. Full clean checks every category. Usage history requires explicit selection."));
        }
        main.child(
            div()
                .flex()
                .flex_1()
                .min_h_0()
                .min_w_0()
                .bg(rgb(p.panel))
                .border_1()
                .border_color(rgb(p.line))
                .rounded(px(6.))
                .overflow_hidden()
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .flex_1()
                        .min_h_0()
                        .min_w_0()
                        .child(self.results_toolbar(cx))
                        .when(self.category_menu, |d| d.child(self.categories(cx)))
                        .child(
                            self.table_header(clean && enabled, narrow && self.inspector_visible),
                        )
                        .child(if display_table && !self.filtered.is_empty() {
                            self.entry_table(narrow && self.inspector_visible, cx)
                                .into_any_element()
                        } else {
                            self.results_empty(display_table, cx).into_any_element()
                        })
                        .child(self.table_footer(clean && enabled, cx)),
                )
                .when(self.inspector_visible, |d| {
                    d.child(self.inspector(narrow, cx))
                }),
        )
    }

    fn summary(&self, cx: &mut Context<Self>) -> Div {
        let p = self.palette;
        let total = self
            .report
            .as_ref()
            .map_or(0, |report| report.entries.len());
        let mut metrics = div()
            .flex()
            .min_w_0()
            .flex_shrink_0()
            .border_1()
            .border_color(rgb(p.line))
            .rounded(px(6.))
            .overflow_hidden()
            .bg(rgb(p.panel));
        for (index, (title, value, color, status)) in [
            ("Entries inspected", total, p.ink, None),
            (
                "Needs review",
                self.counts[1],
                p.review,
                Some(EntryStatus::Review),
            ),
            (
                "Targets found",
                self.counts[0],
                p.found,
                Some(EntryStatus::Found),
            ),
            (
                "Unverified",
                self.counts[2],
                p.muted,
                Some(EntryStatus::Unknown),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let active = self.report.is_some() && status == self.filter.status;
            metrics = metrics.child(
                div()
                    .id(("metric", index))
                    .flex_1()
                    .min_w_0()
                    .h(px(83.))
                    .px_4()
                    .pt_2()
                    .pb_2()
                    .flex()
                    .flex_col()
                    .justify_center()
                    .gap_1()
                    .border_b_2()
                    .border_color(rgb(if active { p.accent } else { p.panel }))
                    .when(index != 0, |d| d.border_l_1().border_color(rgb(p.line)))
                    .when(active, |d| d.bg(rgb(p.selected)))
                    .child(
                        div()
                            .text_size(rems(1.55))
                            .font_weight(FontWeight::SEMIBOLD)
                            .line_height(rems(1.68))
                            .text_color(rgb(color))
                            .child(if self.report.is_some() {
                                count(value)
                            } else {
                                "—".into()
                            }),
                    )
                    .child(
                        div()
                            .truncate()
                            .text_size(rems(0.75))
                            .text_color(rgb(p.muted))
                            .child(title),
                    )
                    .when(self.report.is_some(), |d| {
                        d.focusable()
                            .tab_stop(true)
                            .cursor_pointer()
                            .focus(|d| d.bg(rgb(p.selected)))
                            .hover(|d| d.bg(rgb(p.soft)))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.filter.status = status;
                                this.refilter();
                                cx.notify();
                            }))
                    }),
            );
        }
        metrics
    }

    fn results_toolbar(&self, cx: &mut Context<Self>) -> Div {
        let p = self.palette;
        let export_enabled = self.page != Page::Clean
            && self.job.is_none()
            && !self.archived
            && !self.filtered.is_empty();
        let mut toolbar = div()
            .flex()
            .gap_2()
            .items_center()
            .px_3()
            .py_2()
            .min_w_0()
            .flex_shrink_0()
            .border_b_1()
            .border_color(rgb(p.line))
            .child(
                div().flex_1().min_w(px(94.)).max_w(px(370.)).child(
                    Input::new(&self.input)
                        .h(px(34.))
                        .prefix(icon(Icon::Search, p.muted, 15.)),
                ),
            )
            .child(div().flex_grow().min_w_0());
        if self.page != Page::Leftovers {
            let category = self.filter.category.map_or("All categories", category_name);
            toolbar = toolbar.child(
                button(
                    p,
                    "categories",
                    category,
                    Some(Icon::Chevron),
                    ButtonStyle::Secondary,
                    true,
                )
                .on_click(cx.listener(|this, _, _, cx| {
                    this.category_menu = !this.category_menu;
                    cx.notify();
                })),
            );
        }
        if self.page != Page::Clean {
            toolbar = toolbar.child(
                button(
                    p,
                    "export-json",
                    "Export",
                    Some(Icon::ArrowDown),
                    ButtonStyle::Secondary,
                    export_enabled,
                )
                .when(export_enabled, |d| {
                    d.on_click(cx.listener(|this, _, w, cx| this.export(w, cx)))
                }),
            );
        }
        if !self.inspector_visible {
            toolbar = toolbar.child(
                button(
                    p,
                    "show-inspector",
                    "Inspector",
                    Some(Icon::File),
                    ButtonStyle::Secondary,
                    true,
                )
                .on_click(cx.listener(|this, _, w, cx| this.toggle_inspector(w, cx))),
            );
        }
        toolbar
    }

    fn categories(&self, cx: &mut Context<Self>) -> Stateful<Div> {
        let p = self.palette;
        div()
            .id("category-options")
            .flex()
            .flex_wrap()
            .gap_1()
            .p_2()
            .max_h(px(162.))
            .overflow_y_scroll()
            .bg(rgb(p.soft))
            .border_b_1()
            .border_color(rgb(p.line))
            .children(
                std::iter::once((None, "All categories"))
                    .chain(CATEGORIES.iter().map(|&(cat, label)| (Some(cat), label)))
                    .enumerate()
                    .map(|(index, (cat, label))| {
                        let style = if cat == self.filter.category {
                            ButtonStyle::Selected
                        } else {
                            ButtonStyle::Secondary
                        };
                        button(p, ("category-option", index), label, None, style, true)
                            .h(px(28.))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.filter.category = cat;
                                this.category_menu = false;
                                this.refilter();
                                cx.notify();
                            }))
                    }),
            )
    }

    fn table_header(&self, checkable: bool, narrow: bool) -> Div {
        let p = self.palette;
        div()
            .h(px(34.))
            .flex_shrink_0()
            .flex()
            .items_center()
            .gap_2()
            .px_3()
            .bg(rgb(p.soft))
            .border_b_1()
            .border_color(rgb(p.line))
            .when(checkable, |d| d.child(div().w(px(26.)).flex_shrink_0()))
            .child(label("REGISTRY ENTRY", p.muted).flex_1())
            .when(!narrow, |d| {
                d.child(label("CATEGORY", p.muted).w(px(128.)).flex_shrink_0())
            })
            .child(label("STATUS", p.muted).w(px(83.)).flex_shrink_0())
    }

    fn entry_table(&self, narrow: bool, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .id("table-focus")
            .debug_selector(|| "results-table".into())
            .track_focus(&self.table_focus)
            .tab_stop(true)
            .key_context("RegistryTable")
            .on_action(cx.listener(|this, _: &NextEntry, _, cx| this.step_entry(1, cx)))
            .on_action(cx.listener(|this, _: &PreviousEntry, _, cx| this.step_entry(-1, cx)))
            .flex_1()
            .min_h_0()
            .min_w_0()
            .overflow_hidden()
            .child(
                uniform_list(
                    "entry-table",
                    self.filtered.len(),
                    cx.processor(move |this, range: std::ops::Range<usize>, _, cx| {
                        let Some(report) = &this.report else {
                            return vec![];
                        };
                        range
                            .filter_map(|row| {
                                let index = *this.filtered.get(row)?;
                                Some(this.entry_row(&report.entries[index], index, narrow, cx))
                            })
                            .collect::<Vec<_>>()
                    }),
                )
                .track_scroll(self.results_scroll.clone())
                .size_full(),
            )
            .vertical_scrollbar(&self.results_scroll)
    }

    fn entry_row(
        &self,
        entry: &RegistryEntry,
        index: usize,
        narrow: bool,
        cx: &mut Context<Self>,
    ) -> Stateful<Div> {
        let p = self.palette;
        let active = self.selected == Some(index);
        let checkable = self.page == Page::Clean && self.fresh_report().is_some();
        let checked = self.checked.contains(&index);
        div()
            .id(("entry", index))
            .w_full()
            .h(px(51.))
            .px_3()
            .gap_2()
            .flex()
            .items_center()
            .border_b_1()
            .border_color(rgb(p.line))
            .cursor_pointer()
            .bg(rgb(if active { p.selected } else { p.panel }))
            .hover(|d| d.bg(rgb(if active { p.selected } else { p.soft })))
            .on_click(cx.listener(move |this, _, window, cx| {
                this.table_focus.focus(window);
                this.select(Some(index));
                cx.notify();
            }))
            .when(checkable, |d| {
                d.child(
                    button(
                        p,
                        ("entry-check", index),
                        "",
                        Some(if checked { Icon::Check } else { Icon::Plus }),
                        if checked {
                            ButtonStyle::Selected
                        } else {
                            ButtonStyle::Secondary
                        },
                        self.job.is_none(),
                    )
                    .size(px(26.))
                    .p_0()
                    .when(self.job.is_none(), |d| {
                        d.on_click(cx.listener(move |this, _, _, cx| {
                            cx.stop_propagation();
                            if !this.checked.remove(&index) {
                                this.checked.insert(index);
                            }
                            this.select(Some(index));
                            cx.notify();
                        }))
                    }),
                )
            })
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .flex_col()
                    .gap(px(2.))
                    .child(
                        div()
                            .truncate()
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_size(rems(0.82))
                            .child(entry.name.clone()),
                    )
                    .child(
                        div()
                            .truncate()
                            .font(mono())
                            .text_size(rems(0.69))
                            .text_color(rgb(p.muted))
                            .child(format!("{} · {}", view_name(&entry.view), location(entry))),
                    ),
            )
            .when(!narrow, |d| {
                d.child(
                    div()
                        .w(px(128.))
                        .flex_shrink_0()
                        .truncate()
                        .text_color(rgb(p.muted))
                        .text_size(rems(0.74))
                        .child(category_name(entry.category)),
                )
            })
            .child(
                self.status(entry.assessment.status)
                    .w(px(83.))
                    .flex_shrink_0(),
            )
    }

    fn status(&self, status: EntryStatus) -> Div {
        let p = self.palette;
        let color = match status {
            EntryStatus::Review => p.review,
            EntryStatus::Found => p.found,
            EntryStatus::Unknown => p.muted,
        };
        div()
            .flex()
            .items_center()
            .gap(px(5.))
            .text_color(rgb(color))
            .text_size(rems(0.73))
            .child(
                div()
                    .size(px(6.))
                    .rounded(px(1.))
                    .flex_shrink_0()
                    .bg(rgb(color)),
            )
            .child(status_name(status))
    }

    fn results_empty(&self, has_report: bool, cx: &mut Context<Self>) -> Div {
        let p = self.palette;
        let scanning = self
            .job
            .as_ref()
            .is_some_and(|job| job.title == "Scanning registry");
        let (title, description) = if scanning {
            (
                "Scanning the registry",
                "Section and entry counts appear in the status bar.",
            )
        } else if has_report && self.page == Page::Leftovers && self.groups.is_empty() {
            (
                "No correlated leftovers",
                "This scan found no application records with matching leftover evidence.",
            )
        } else if has_report {
            (
                "No matching entries",
                "Try a different search or clear the current filters.",
            )
        } else if self.page == Page::Clean && self.archived {
            (
                "A fresh scan is required",
                "Saved scans are available for inspection in Registry explorer.",
            )
        } else {
            (
                "No scan loaded",
                "Results will appear here with their registry location and assessment.",
            )
        };
        let can_scan = !has_report && self.job.is_none() && self.store.is_some();
        div()
            .flex_1()
            .min_h_0()
            .flex()
            .flex_col()
            .items_center()
            .justify_center()
            .gap_2()
            .p_4()
            .child(
                div()
                    .size(px(52.))
                    .flex()
                    .items_center()
                    .justify_center()
                    .bg(rgb(p.soft))
                    .border_1()
                    .border_color(rgb(p.line))
                    .rounded(px(8.))
                    .child(icon(
                        if has_report { Icon::Search } else { Icon::Scan },
                        p.accent,
                        26.,
                    )),
            )
            .child(
                div()
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_size(rems(1.03))
                    .child(title),
            )
            .child(
                div()
                    .max_w(px(305.))
                    .text_center()
                    .text_color(rgb(p.muted))
                    .text_size(rems(0.82))
                    .child(description),
            )
            .when(can_scan, |d| {
                d.child(
                    div()
                        .mt_2()
                        .flex()
                        .flex_wrap()
                        .justify_center()
                        .gap_2()
                        .child(
                            button(
                                p,
                                "run-first-scan",
                                "Run scan",
                                Some(Icon::Right),
                                ButtonStyle::Primary,
                                true,
                            )
                            .on_click(cx.listener(|this, _, w, cx| this.scan(w, cx))),
                        )
                        .when(self.page == Page::Explorer, |d| {
                            d.child(
                                button(
                                    p,
                                    "open-saved-scans",
                                    "Saved scans",
                                    Some(Icon::Clock),
                                    ButtonStyle::Secondary,
                                    true,
                                )
                                .on_click(
                                    cx.listener(|this, _, w, cx| {
                                        this.set_page(Page::History, w, cx)
                                    }),
                                ),
                            )
                        }),
                )
            })
    }

    fn table_footer(&self, can_check: bool, cx: &mut Context<Self>) -> Div {
        let p = self.palette;
        let status = self.filter.status.map_or("", status_name);
        let text = self.report.as_ref().map_or_else(
            || "No scan loaded".to_string(),
            |_| {
                if self.page == Page::Clean && self.archived {
                    return "Saved scan · inspection only".into();
                }
                format!(
                    "{} {}{}",
                    count(self.filtered.len()),
                    match (self.page, self.filtered.len()) {
                        (Page::Leftovers, 1) => "group",
                        (Page::Leftovers, _) => "groups",
                        (_, 1) => "entry",
                        _ => "entries",
                    },
                    if status.is_empty() {
                        String::new()
                    } else {
                        format!(" · {status}")
                    }
                )
            },
        );
        let filtered = !self.filter.query.is_empty()
            || self.filter.status.is_some()
            || (self.page != Page::Leftovers && self.filter.category.is_some());
        div()
            .flex()
            .items_center()
            .justify_between()
            .gap_1()
            .min_h(px(38.))
            .px_3()
            .border_t_1()
            .border_color(rgb(p.line))
            .text_color(rgb(p.muted))
            .text_size(rems(0.73))
            .child(text)
            .when(!can_check && filtered, |d| {
                d.child(
                    button(
                        p,
                        "reset-filters",
                        "Clear filters",
                        None,
                        ButtonStyle::Quiet,
                        true,
                    )
                    .h(px(28.))
                    .on_click(cx.listener(|this, _, w, cx| this.clear_filters(w, cx))),
                )
            })
            .when(can_check, |d| {
                d.child(
                    div()
                        .flex()
                        .gap_1()
                        .child(
                            button(
                                p,
                                "check-visible",
                                "Select filtered",
                                None,
                                ButtonStyle::Quiet,
                                !self.filtered.is_empty() && self.job.is_none(),
                            )
                            .h(px(28.))
                            .on_click(cx.listener(|this, _, _, cx| {
                                if this.job.is_none() && this.fresh_report().is_some() {
                                    this.checked.extend(this.filtered.iter().copied());
                                    cx.notify();
                                }
                            })),
                        )
                        .child(
                            button(
                                p,
                                "clear-entries",
                                "Clear",
                                None,
                                ButtonStyle::Quiet,
                                !self.checked.is_empty() && self.job.is_none(),
                            )
                            .h(px(28.))
                            .on_click(cx.listener(|this, _, _, cx| {
                                if this.job.is_none() {
                                    this.checked.clear();
                                    cx.notify();
                                }
                            })),
                        ),
                )
            })
    }

    fn inspector(&self, narrow: bool, cx: &mut Context<Self>) -> Div {
        let p = self.palette;
        let entry = self
            .detail_index
            .and_then(|index| self.report.as_ref()?.entries.get(index).map(|e| (index, e)));
        let header = div()
            .h(px(50.))
            .flex_shrink_0()
            .flex()
            .items_center()
            .justify_between()
            .gap_2()
            .px_3()
            .border_b_1()
            .border_color(rgb(p.line))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(icon(Icon::File, p.accent, 16.))
                    .child("Inspector"),
            )
            .child(
                div()
                    .flex()
                    .gap_1()
                    .when_some(entry.map(|(_, entry)| location(entry)), |d, path| {
                        d.child(
                            button(
                                p,
                                "copy-registry-path",
                                "Copy path",
                                Some(Icon::Copy),
                                ButtonStyle::Secondary,
                                true,
                            )
                            .h(px(28.))
                            .on_click(move |_, _, cx| {
                                cx.write_to_clipboard(ClipboardItem::new_string(path.clone()))
                            }),
                        )
                    })
                    .child(
                        button(
                            p,
                            "hide-inspector",
                            "Hide",
                            None,
                            ButtonStyle::Secondary,
                            true,
                        )
                        .h(px(28.))
                        .on_click(cx.listener(|this, _, w, cx| this.toggle_inspector(w, cx))),
                    ),
            );
        let mut panel = div()
            .debug_selector(|| "registry-inspector".into())
            .flex()
            .flex_col()
            .w(px(if narrow { 258. } else { 310. }))
            .flex_shrink_0()
            .border_l_1()
            .border_color(rgb(p.line))
            .bg(rgb(p.panel))
            .child(header);
        if let Some((index, entry)) = entry {
            let mut detail = div()
                .id("entry-detail")
                .track_scroll(&self.detail_scroll)
                .overflow_y_scroll()
                .flex()
                .flex_col()
                .flex_1()
                .min_h_0()
                .gap_3()
                .p_3()
                .child(label(
                    category_name(entry.category).to_uppercase(),
                    p.accent,
                ))
                .child(
                    div()
                        .text_size(rems(1.12))
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(entry.name.clone()),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(self.status(entry.assessment.status))
                        .child(
                            div()
                                .text_color(rgb(p.muted))
                                .text_size(rems(0.73))
                                .child(format!("· {} view", view_name(&entry.view))),
                        ),
                )
                .child(
                    div()
                        .text_size(rems(0.81))
                        .text_color(rgb(p.muted))
                        .child(entry.assessment.explanation.clone()),
                )
                .child(line(p))
                .child(field(p, "Registry key", location(entry), true))
                .child(
                    div()
                        .flex()
                        .gap_2()
                        .child(
                            field(
                                p,
                                "Value name",
                                if entry.value_name.is_empty() {
                                    "(Default)".to_string()
                                } else {
                                    entry.value_name.clone()
                                },
                                true,
                            )
                            .flex_1(),
                        )
                        .child(
                            field(p, "Type", entry.value_type.clone(), true)
                                .w_auto()
                                .flex_shrink_0(),
                        ),
                )
                .child(field(
                    p,
                    "Value data",
                    if entry.raw_value.is_empty() {
                        "(Empty)".into()
                    } else {
                        entry.raw_value.clone()
                    },
                    true,
                ));
            if let Some(target) = &entry.assessment.target {
                detail = detail.child(field(p, "Resolved target", target.clone(), true));
            }
            if let Some(publisher) = &entry.publisher {
                detail = detail.child(field(p, "Publisher", publisher.clone(), false));
            }
            if let Some(version) = &entry.version {
                detail = detail.child(field(p, "Version", version.clone(), false));
            }
            if let Some(evidence) = &entry.leftover_evidence {
                detail = detail
                    .child(line(p))
                    .child(label("CORRELATED APPLICATION", p.accent))
                    .child(field(
                        p,
                        "Application",
                        evidence.application_name.clone(),
                        false,
                    ))
                    .child(field(
                        p,
                        "Installation directory",
                        evidence.directory.clone(),
                        true,
                    ))
                    .child(field(p, "Executable", evidence.executable.clone(), true))
                    .child(field(p, "Uninstaller", evidence.uninstaller.clone(), true))
                    .child(field(
                        p,
                        "Uninstall registration",
                        evidence.uninstall_path.clone(),
                        true,
                    ))
                    .child(field(
                        p,
                        "Application registration",
                        evidence.application_path.clone(),
                        true,
                    ));
                if let Some(path) = &evidence.app_paths_companion {
                    detail = detail.child(field(p, "App Paths evidence", path.clone(), true));
                }
            }
            let mut related_candidates = Vec::new();
            if self.page == Page::Leftovers {
                if let (Some(group), Some(report)) = (
                    self.groups
                        .iter()
                        .find(|group| Some(group.anchor) == self.selected),
                    &self.report,
                ) {
                    detail = detail
                        .child(line(p))
                        .child(label("RELATED REGISTRY RECORDS", p.accent));
                    for &related in &group.related {
                        let item = &report.entries[related];
                        let eligible = self.fresh_report().is_some() && is_repair_candidate(item);
                        let selection = (group.anchor, related);
                        let included = !self.excluded_group_items.contains(&selection);
                        if eligible && included {
                            related_candidates.push(related);
                        }
                        let title = if item.value_name.is_empty() {
                            item.name.clone()
                        } else {
                            format!("{} · {}", category_name(item.category), item.value_name)
                        };
                        detail = detail.child(
                            div()
                                .flex()
                                .gap_1()
                                .child(
                                    button(
                                        p,
                                        ("related-entry", related),
                                        title,
                                        Some(Icon::File),
                                        if related == index {
                                            ButtonStyle::Selected
                                        } else {
                                            ButtonStyle::Secondary
                                        },
                                        true,
                                    )
                                    .flex_shrink()
                                    .min_w_0()
                                    .justify_start()
                                    .overflow_hidden()
                                    .on_click(cx.listener(
                                        move |this, _, _, cx| {
                                            this.inspect(Some(related));
                                            cx.notify();
                                        },
                                    )),
                                )
                                .when(eligible, |d| {
                                    d.child(
                                        button(
                                            p,
                                            ("include-related", related),
                                            if included { "Exclude" } else { "Include" },
                                            None,
                                            ButtonStyle::Quiet,
                                            true,
                                        )
                                        .on_click(
                                            cx.listener(move |this, _, _, cx| {
                                                if !this.excluded_group_items.remove(&selection) {
                                                    this.excluded_group_items.insert(selection);
                                                }
                                                cx.notify();
                                            }),
                                        ),
                                    )
                                }),
                        );
                    }
                }
            }
            panel = panel.child(
                div()
                    .relative()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_h_0()
                    .child(detail)
                    .vertical_scrollbar(&self.detail_scroll),
            );
            if self.fresh_report().is_some()
                && (is_repair_candidate(entry) || !related_candidates.is_empty())
            {
                let enabled = self.job.is_none();
                let mut actions = div()
                    .p_3()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .border_t_1()
                    .border_color(rgb(p.line));
                if is_repair_candidate(entry) {
                    actions = actions.child(
                        button(
                            p,
                            "review-entry",
                            "Review change",
                            Some(Icon::Right),
                            ButtonStyle::Primary,
                            enabled,
                        )
                        .when(enabled, |d| {
                            d.on_click(cx.listener(move |this, _, w, cx| {
                                this.prepare_entry(index, w, cx);
                            }))
                        }),
                    );
                }
                if !related_candidates.is_empty() {
                    actions = actions.child(
                        button(
                            p,
                            "review-leftover-group",
                            format!("Review group ({})", count(related_candidates.len())),
                            Some(Icon::Layers),
                            ButtonStyle::Secondary,
                            enabled,
                        )
                        .when(enabled, |d| {
                            d.on_click(cx.listener(move |this, _, w, cx| {
                                this.prepare_batch("selected", related_candidates.clone(), w, cx);
                            }))
                        }),
                    );
                }
                panel = panel.child(actions);
            }
            return panel;
        }
        panel.child(div().p_4().flex().flex_col().gap_2()
            .child(div().font_weight(FontWeight::SEMIBOLD).child("No entry selected"))
            .child(div().text_color(rgb(p.muted)).text_size(rems(0.83))
                .child("Select a result to see its assessment and original registry data."))
            .child(div().mt_4().pt_3().border_t_1().border_color(rgb(p.line))
                .flex().items_start().gap_2().text_size(rems(0.79)).text_color(rgb(p.muted))
                .child(icon(Icon::Shield, p.accent, 15.))
                .child(div().min_w_0().child("Scanning leaves the registry untouched. Changes require a separate review."))))
    }
}
