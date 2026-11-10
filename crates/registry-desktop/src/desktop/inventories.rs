use super::{
    model::{category_name, count, duration, pretty, timestamp, view_name},
    style::{button, field, icon, label, mono, ButtonStyle, Icon},
    Desktop,
};
use gpui::{prelude::*, *};
use gpui_component::input::Input;
use registry_core::journal::OperationKind;
use std::ops::Range;

impl Desktop {
    fn ledger(&self) -> Div {
        let p = self.palette;
        div()
            .flex()
            .flex_col()
            .min_h_0()
            .min_w_0()
            .flex_1()
            .bg(rgb(p.panel))
            .border_1()
            .border_color(rgb(p.line))
            .rounded(px(6.))
            .overflow_hidden()
    }

    fn inventory_header(&self, title: impl Into<SharedString>) -> Div {
        let p = self.palette;
        div()
            .flex()
            .items_center()
            .justify_between()
            .gap_3()
            .px_4()
            .py_2()
            .min_h(px(42.))
            .flex_shrink_0()
            .bg(rgb(p.soft))
            .border_b_1()
            .border_color(rgb(p.line))
            .child(label(title, p.muted))
    }

    fn inventory_empty(&self, title: &str, text: &str, symbol: Icon) -> Div {
        let p = self.palette;
        div()
            .flex()
            .flex_col()
            .flex_1()
            .items_center()
            .justify_center()
            .gap_2()
            .p_4()
            .child(
                div()
                    .size(px(46.))
                    .flex()
                    .items_center()
                    .justify_center()
                    .rounded(px(6.))
                    .bg(rgb(p.soft))
                    .child(icon(symbol, p.accent, 24.)),
            )
            .child(
                div()
                    .text_size(rems(1.04))
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(title.to_string()),
            )
            .child(
                div()
                    .text_size(rems(0.82))
                    .text_color(rgb(p.muted))
                    .text_center()
                    .child(text.to_string()),
            )
    }

    fn inventory_warnings(&self, warnings: &[String]) -> Stateful<Div> {
        let p = self.palette;
        div()
            .id("inventory-warnings")
            .max_h(px(114.))
            .overflow_y_scroll()
            .p_3()
            .border_b_1()
            .border_color(rgb(p.line))
            .bg(rgb(p.soft))
            .text_color(rgb(p.review))
            .text_size(rems(0.78))
            .children(warnings.iter().cloned().map(|warning| div().child(warning)))
    }

    fn inventory_row(
        &self,
        title: impl Into<SharedString>,
        description: impl Into<SharedString>,
    ) -> Div {
        let p = self.palette;
        div()
            .w_full()
            .h(px(65.))
            .px_4()
            .gap_3()
            .flex()
            .items_center()
            .border_b_1()
            .border_color(rgb(p.line))
            .child(
                div()
                    .min_w_0()
                    .flex_1()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        div()
                            .truncate()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(title.into()),
                    )
                    .child(
                        div()
                            .truncate()
                            .text_size(rems(0.75))
                            .text_color(rgb(p.muted))
                            .child(description.into()),
                    ),
            )
    }

    pub(super) fn coverage(&self, cx: &mut Context<Self>) -> Div {
        let p = self.palette;
        let Some(report) = &self.report else {
            return self.ledger().child(self.inventory_empty(
                "No coverage recorded",
                "Run a scan to inspect registry sections.",
                Icon::Coverage,
            ));
        };
        self.ledger()
            .child(self.inventory_header(format!(
                "{} SECTIONS · {}",
                count(report.scopes.len()),
                report.architecture
            )))
            .child(
                div()
                    .id("coverage-sections")
                    .flex()
                    .flex_col()
                    .min_h_0()
                    .flex_1()
                    .overflow_y_scroll()
                    .children(report.scopes.iter().enumerate().map(|(index, scope)| {
                        let path = format!("{}\\{}", scope.hive, scope.key_path);
                        div()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .p_3()
                            .border_b_1()
                            .border_color(rgb(p.line))
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .gap_2()
                                    .child(
                                        div()
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .child(category_name(scope.category)),
                                    )
                                    .child(label(
                                        format!(
                                            "{} · {} entries",
                                            pretty(&scope.status),
                                            count(scope.entries)
                                        ),
                                        p.accent,
                                    )),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(
                                        div()
                                            .min_w_0()
                                            .flex_1()
                                            .font(mono())
                                            .text_size(rems(0.76))
                                            .child(path.clone()),
                                    )
                                    .child(label(view_name(&scope.view), p.muted))
                                    .child(
                                        button(
                                            p,
                                            ("copy-section", index),
                                            "Copy",
                                            Some(Icon::Copy),
                                            ButtonStyle::Secondary,
                                            true,
                                        )
                                        .h(px(27.))
                                        .on_click(
                                            cx.listener(move |_, _, _, cx| {
                                                cx.write_to_clipboard(ClipboardItem::new_string(
                                                    path.clone(),
                                                ))
                                            }),
                                        ),
                                    ),
                            )
                            .children(scope.notes.iter().cloned().map(|note| {
                                div()
                                    .text_size(rems(0.77))
                                    .text_color(rgb(p.muted))
                                    .child(note)
                            }))
                    })),
            )
    }

    pub(super) fn history(&self, cx: &mut Context<Self>) -> Div {
        let p = self.palette;
        let Some(inventory) = &self.history else {
            return self.ledger().child(self.inventory_empty(
                if self.job.is_some() {
                    "Reading saved scans"
                } else {
                    "Saved scans are unavailable"
                },
                "Use Refresh to read the local archive.",
                Icon::Clock,
            ));
        };
        let enabled = self.job.is_none();
        self.ledger()
            .child(self.inventory_header(format!("{} SAVED SCANS", count(inventory.scans.len()))))
            .when(!inventory.warnings.is_empty(), |d| {
                d.child(self.inventory_warnings(&inventory.warnings))
            })
            .child(if inventory.scans.is_empty() {
                self.inventory_empty(
                    "No saved scans",
                    "Scans are saved locally after they run.",
                    Icon::Clock,
                )
                .into_any_element()
            } else {
                div()
                    .id("history-rows")
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .children(inventory.scans.iter().enumerate().map(|(index, scan)| {
                        let id = scan.id.clone();
                        self.inventory_row(
                            timestamp(scan.started_at),
                            format!(
                                "{} entries · {} sections · {}{}",
                                count(scan.entries),
                                scan.sections,
                                duration(scan.duration_ms),
                                if scan.cancelled { " · Stopped" } else { "" }
                            ),
                        )
                        .child(
                            button(
                                p,
                                ("open-scan", index),
                                "Open scan",
                                Some(Icon::Right),
                                ButtonStyle::Secondary,
                                enabled,
                            )
                            .when(enabled, |d| {
                                d.on_click(cx.listener(move |this, _, w, cx| {
                                    this.open_archive(id.clone(), w, cx)
                                }))
                            }),
                        )
                    }))
                    .into_any_element()
            })
    }

    pub(super) fn backups(&self, cx: &mut Context<Self>) -> Div {
        let p = self.palette;
        let Some(inventory) = &self.backups else {
            let title = if self.job.is_some() {
                "Reading backups"
            } else {
                "Backups need to be refreshed"
            };
            return self.ledger().child(self.inventory_empty(
                title,
                "Use Refresh to check the current state of your backups.",
                Icon::Archive,
            ));
        };
        let query = self.filter.query.trim().to_lowercase();
        let filtered: Vec<_> = inventory
            .backups
            .iter()
            .enumerate()
            .filter_map(|(index, item)| {
                (query.is_empty()
                    || [
                        &item.name,
                        &item.registry_path,
                        &item.value_name,
                        &item.state,
                    ]
                    .iter()
                    .any(|field| field.to_lowercase().contains(&query))
                    || pretty(&item.state).contains(&query))
                .then_some(index)
            })
            .collect();
        let enabled = self.job.is_none();
        let can_restore = enabled && !self.backup_checked.is_empty();
        let can_select = enabled
            && filtered
                .iter()
                .any(|&index| inventory.backups[index].state == "restore_available");
        let select_indices = filtered.clone();
        let toolbar = div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap_2()
            .p_2()
            .border_b_1()
            .border_color(rgb(p.line))
            .child(
                div()
                    .w(px(215.))
                    .child(Input::new(&self.input).h(px(34.)).prefix(icon(
                        Icon::Search,
                        p.muted,
                        15.,
                    ))),
            )
            .child(
                button(
                    p,
                    "select-backups",
                    "Select restorable",
                    None,
                    ButtonStyle::Secondary,
                    can_select,
                )
                .when(can_select, |d| {
                    d.on_click(cx.listener(move |this, _, _, cx| {
                        if let Some(inventory) = &this.backups {
                            this.backup_checked.extend(
                                select_indices
                                    .iter()
                                    .map(|&index| &inventory.backups[index])
                                    .filter(|item| item.state == "restore_available")
                                    .map(|item| item.id.clone()),
                            );
                            cx.notify();
                        }
                    }))
                }),
            )
            .child(
                button(
                    p,
                    "clear-backups",
                    "Clear",
                    None,
                    ButtonStyle::Quiet,
                    can_restore,
                )
                .when(can_restore, |d| {
                    d.on_click(cx.listener(|this, _, _, cx| {
                        this.backup_checked.clear();
                        cx.notify();
                    }))
                }),
            )
            .child(
                button(
                    p,
                    "restore-selected",
                    format!("Review selected ({})", count(self.backup_checked.len())),
                    Some(Icon::Restore),
                    ButtonStyle::Primary,
                    can_restore,
                )
                .when(can_restore, |d| {
                    d.on_click(cx.listener(|this, _, w, cx| this.prepare_undo(None, w, cx)))
                }),
            );
        self.ledger()
            .child(toolbar)
            .child(self.inventory_header(format!(
                "{} OF {} BACKUPS",
                count(filtered.len()),
                count(inventory.backups.len())
            )))
            .when(!inventory.warnings.is_empty(), |d| {
                d.child(self.inventory_warnings(&inventory.warnings))
            })
            .child(if filtered.is_empty() {
                self.inventory_empty(
                    "No backups to display",
                    "Backups are created when you apply a reviewed change.",
                    Icon::Archive,
                )
                .into_any_element()
            } else {
                uniform_list(
                    "backup-rows",
                    filtered.len(),
                    cx.processor(move |this, range: Range<usize>, _, cx| {
                        let Some(inventory) = &this.backups else {
                            return vec![];
                        };
                        range
                            .filter_map(|row| {
                                let index = *filtered.get(row)?;
                                let item = inventory.backups.get(index)?;
                                let restorable =
                                    item.state == "restore_available" && this.job.is_none();
                                let checked = this.backup_checked.contains(&item.id);
                                let toggle_id = item.id.clone();
                                let restore_id = item.id.clone();
                                let inspect_id = item.id.clone();
                                let inspecting = this.backup_inspected.as_deref() == Some(&item.id);
                                let line = this
                                    .inventory_row(
                                        item.name.clone(),
                                        format!(
                                            "{} · {} · {}",
                                            timestamp(item.created_at),
                                            view_name(&item.registry_view),
                                            item.registry_path
                                        ),
                                    )
                                    .id(("backup-row", index))
                                    .focusable()
                                    .tab_stop(true)
                                    .cursor_pointer()
                                    .when(inspecting, |d| d.bg(rgb(p.selected)))
                                    .hover(|d| d.bg(rgb(p.soft)))
                                    .focus(|d| d.bg(rgb(p.selected)))
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.backup_inspected = Some(inspect_id.clone());
                                        cx.notify();
                                    }))
                                    .child(label(
                                        pretty(&item.state),
                                        if restorable { p.found } else { p.muted },
                                    ))
                                    .child(
                                        button(
                                            p,
                                            ("check-backup", index),
                                            if checked { "Selected" } else { "Select" },
                                            Some(if checked { Icon::Check } else { Icon::Plus }),
                                            if checked {
                                                ButtonStyle::Selected
                                            } else {
                                                ButtonStyle::Secondary
                                            },
                                            restorable,
                                        )
                                        .when(
                                            restorable,
                                            |d| {
                                                d.on_click(cx.listener(move |this, _, _, cx| {
                                                    cx.stop_propagation();
                                                    if !this.backup_checked.remove(&toggle_id) {
                                                        this.backup_checked
                                                            .insert(toggle_id.clone());
                                                    }
                                                    cx.notify();
                                                }))
                                            },
                                        ),
                                    )
                                    .child(
                                        button(
                                            p,
                                            ("restore-backup", index),
                                            "Review restore",
                                            None,
                                            ButtonStyle::Secondary,
                                            restorable,
                                        )
                                        .when(
                                            restorable,
                                            |d| {
                                                d.on_click(cx.listener(move |this, _, w, cx| {
                                                    cx.stop_propagation();
                                                    this.prepare_restore(restore_id.clone(), w, cx)
                                                }))
                                            },
                                        ),
                                    );
                                Some(line)
                            })
                            .collect::<Vec<_>>()
                    }),
                )
                .flex_1()
                .min_h_0()
                .into_any_element()
            })
            .when_some(
                self.backup_inspected
                    .as_ref()
                    .and_then(|id| inventory.backups.iter().find(|item| &item.id == id)),
                |d, item| {
                    let path = item.registry_path.clone();
                    d.child(
                        div()
                            .id("backup-inspector")
                            .max_h(px(166.))
                            .overflow_y_scroll()
                            .flex_shrink_0()
                            .p_3()
                            .border_t_1()
                            .border_color(rgb(p.line))
                            .bg(rgb(p.soft))
                            .child(
                                div()
                                    .flex()
                                    .justify_between()
                                    .items_center()
                                    .gap_2()
                                    .child(
                                        div()
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .child(item.name.clone()),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .gap_2()
                                            .child(
                                                button(
                                                    p,
                                                    "copy-backup-location",
                                                    "Copy path",
                                                    Some(Icon::Copy),
                                                    ButtonStyle::Secondary,
                                                    true,
                                                )
                                                .h(px(28.))
                                                .on_click(move |_, _, cx| {
                                                    cx.write_to_clipboard(
                                                        ClipboardItem::new_string(path.clone()),
                                                    )
                                                }),
                                            )
                                            .child(
                                                button(
                                                    p,
                                                    "close-backup-inspector",
                                                    "Close",
                                                    Some(Icon::Close),
                                                    ButtonStyle::Secondary,
                                                    true,
                                                )
                                                .h(px(28.))
                                                .on_click(cx.listener(|this, _, _, cx| {
                                                    this.backup_inspected = None;
                                                    cx.notify();
                                                })),
                                            ),
                                    ),
                            )
                            .child(
                                div()
                                    .text_size(rems(0.78))
                                    .text_color(rgb(p.muted))
                                    .child(item.note.clone()),
                            )
                            .child(field(
                                p,
                                "Registry key and value",
                                format!(
                                    "{} · {} · {}",
                                    item.registry_path,
                                    view_name(&item.registry_view),
                                    if item.value_name.is_empty() {
                                        "(Default)"
                                    } else {
                                        &item.value_name
                                    }
                                ),
                                true,
                            )),
                    )
                },
            )
    }

    pub(super) fn recovery(&self, cx: &mut Context<Self>) -> Div {
        let p = self.palette;
        let Some(inventory) = &self.operations else {
            let title = if self.job.is_some() {
                "Reading operation journal"
            } else {
                "Journal needs to be refreshed"
            };
            return self.ledger().child(self.inventory_empty(
                title,
                "Use Refresh to read the local operation journal.",
                Icon::Restore,
            ));
        };
        self.ledger().child(self.inventory_header(format!("{} OPERATIONS", count(inventory.operations.len()))))
            .when(!inventory.warnings.is_empty(), |d| d.child(self.inventory_warnings(&inventory.warnings)))
            .child(if inventory.operations.is_empty() {
                self.inventory_empty("No recorded operations", "Confirmed registry changes and restores appear here.", Icon::Restore).into_any_element()
            } else {
                uniform_list("operation-rows", inventory.operations.len(), cx.processor(move |this, range: Range<usize>, _, cx| {
                    let Some(inventory) = &this.operations else { return vec![] };
                    range.filter_map(|index| {
                        let item = inventory.operations.get(index)?;
                        let id = item.id.clone();
                        let enabled = item.can_undo && this.job.is_none();
                        let kind = match item.kind { OperationKind::Clean => "Clean", OperationKind::Restore => "Restore", OperationKind::Undo => "Undo" };
                        let color = if item.state == "interrupted" { p.review } else { p.muted };
                        Some(this.inventory_row(format!("{kind} · {}", timestamp(item.created_at)),
                            format!("{} of {} attempted · {} applied · {} blocked · {} failed",
                                item.attempted, item.total, item.applied, item.blocked, item.failed))
                            .child(label(pretty(&item.state), color))
                            .child(button(p, ("undo-operation", index), "Review undo", Some(Icon::Restore), ButtonStyle::Secondary, enabled)
                                .when(enabled, |d| d.on_click(cx.listener(move |this, _, w, cx| this.prepare_undo(Some(id.clone()), w, cx))))))
                    }).collect::<Vec<_>>()
                })).flex_1().min_h_0().into_any_element()
            })
    }
}
