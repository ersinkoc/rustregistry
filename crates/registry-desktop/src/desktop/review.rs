use super::{
    model::{count, pretty, view_name},
    style::{button, field, icon, label, line, ButtonStyle, Icon, Palette},
    work::{Completed, Review},
    Desktop,
};
use chrono::Utc;
use gpui::{prelude::*, *};
use registry_core::changes::{ChangePlan, UndoItem};
use std::ops::Range;

impl Review {
    fn expiry(&self) -> u64 {
        match self {
            Self::Change(plan) => plan.expires_at,
            Self::Clean(plan) => plan.expires_at,
            Self::Undo(plan) => plan.expires_at,
        }
    }

    fn remaining(&self) -> u64 {
        self.expiry()
            .saturating_sub(Utc::now().timestamp_millis().max(0) as u64)
            .div_ceil(1000)
    }

    fn eligible(&self) -> bool {
        match self {
            Self::Change(_) => true,
            Self::Clean(plan) => !plan.items.is_empty(),
            Self::Undo(plan) => plan
                .items
                .iter()
                .any(|item| item.state == "restore_available"),
        }
    }
}

impl Desktop {
    fn apply_review(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.job.is_some()
            || !self.confirmed
            || self
                .review
                .as_ref()
                .is_none_or(|review| !review.eligible() || review.remaining() == 0)
        {
            return;
        }
        let Some(review) = self.review.take() else {
            return;
        };
        self.focus.focus(window);
        self.stale = self.report.is_some();
        self.checked.clear();
        self.backup_checked.clear();
        self.backups = None;
        self.operations = None;
        match review {
            Review::Change(plan) => self.launch(
                "Applying reviewed change",
                false,
                move |store, _| {
                    let result = store.change(|manager| manager.apply(&plan.token))?;
                    let mut details = vec![format!("Backup {}", result.backup_id)];
                    details.extend(result.operation_id.map(|id| format!("Operation {id}")));
                    Ok(Completed::Receipt {
                        title: result.message,
                        details,
                        registry_changed: true,
                    })
                },
                window,
                cx,
            ),
            Review::Clean(plan) => self.launch(
                "Applying reviewed clean",
                true,
                move |store, control| {
                    let result = store.change(|manager| {
                        manager.apply_clean_with_progress(
                            &plan.token,
                            || control.stopped(),
                            |update| control.change_progress(update),
                        )
                    })?;
                    let mut details = Vec::new();
                    if let Some(failed) = result.failed {
                        details.push(format!("{} · {}", failed.name, failed.reason));
                    }
                    details.extend(result.operation_id.map(|id| format!("Operation {id}")));
                    Ok(Completed::Receipt {
                        title: format!(
                            "{} changes applied · {} not attempted{}",
                            count(result.completed.len()),
                            count(result.not_attempted),
                            if result.cancelled { " · Stopped" } else { "" }
                        ),
                        details,
                        registry_changed: true,
                    })
                },
                window,
                cx,
            ),
            Review::Undo(plan) => self.launch(
                "Restoring reviewed originals",
                true,
                move |store, control| {
                    let result = store.change(|manager| {
                        manager.apply_undo_with_progress(
                            &plan.token,
                            || control.stopped(),
                            |update| control.change_progress(update),
                        )
                    })?;
                    let mut details: Vec<_> = result
                        .operation_id
                        .map(|id| format!("Operation {id}"))
                        .into_iter()
                        .collect();
                    details.extend(
                        result
                            .blocked
                            .iter()
                            .take(5)
                            .map(|item| format!("{} · {}", item.name, item.reason)),
                    );
                    Ok(Completed::Receipt {
                        title: format!(
                            "{} restored · {} already original · {} blocked · {} not attempted{}",
                            count(result.restored),
                            count(result.already_original),
                            count(result.blocked.len()),
                            count(result.not_attempted),
                            if result.cancelled { " · Stopped" } else { "" }
                        ),
                        details,
                        registry_changed: true,
                    })
                },
                window,
                cx,
            ),
        }
    }

    pub(super) fn review_panel(&self, review: &Review, cx: &mut Context<Self>) -> Div {
        let p = self.palette;
        let (title, message, apply) = match review {
            Review::Change(plan) if plan.action == "restore" =>
                ("Review restore".to_string(), "Review the original value and its exact registry location.", "Restore original"),
            Review::Change(_) =>
                ("Review registry change".to_string(), "A verified backup is saved before the selected change is applied.", "Apply change"),
            Review::Clean(plan) => (
                format!("Review {} clean", pretty(&plan.mode)),
                "A verified backup is saved for each attempted change. Live values are checked again before writing.",
                "Apply clean",
            ),
            Review::Undo(_) => (
                "Review undo".to_string(),
                "Eligible originals can be restored. Conflicts and values that already match their backups are skipped.",
                "Restore eligible originals",
            ),
        };
        let remaining = review.remaining();
        let enabled = remaining > 0 && review.eligible();
        let active = enabled && self.confirmed;
        let timer = if remaining == 0 {
            "Review expired · close and review again".to_string()
        } else {
            format!("Review expires in {}:{:02}", remaining / 60, remaining % 60)
        };
        let content = match review {
            Review::Change(plan) => div()
                .id("single-review")
                .overflow_y_scroll()
                .flex_1()
                .min_h_0()
                .child(self.change_detail(plan))
                .into_any_element(),
            Review::Clean(plan) => {
                let list = uniform_list(
                    "clean-review-rows",
                    plan.items.len() + plan.skipped.len(),
                    cx.processor(|this, range: Range<usize>, _, cx| {
                        let Some(Review::Clean(plan)) = &this.review else {
                            return vec![];
                        };
                        range
                            .map(|index| {
                                let (name, state, color) = if let Some(item) = plan.items.get(index)
                                {
                                    (item.name.clone(), pretty(&item.scope), this.palette.accent)
                                } else {
                                    (
                                        plan.skipped[index - plan.items.len()].name.clone(),
                                        "Skipped".into(),
                                        this.palette.review,
                                    )
                                };
                                this.review_row(index, name, state, color, cx)
                            })
                            .collect::<Vec<_>>()
                    }),
                );
                let detail = if let Some(item) = plan.items.get(self.review_index) {
                    self.change_detail(item)
                } else if let Some(item) = plan
                    .skipped
                    .get(self.review_index.saturating_sub(plan.items.len()))
                {
                    div()
                        .p_4()
                        .child(field(p, "Skipped", item.reason.clone(), false))
                } else {
                    div().p_4().child("No eligible changes were found.")
                };
                self.split_review(
                    format!(
                        "{} READY · {} SKIPPED",
                        count(plan.items.len()),
                        count(plan.skipped.len())
                    ),
                    list,
                    detail,
                )
                .into_any_element()
            }
            Review::Undo(plan) => {
                let list = uniform_list(
                    "undo-review-rows",
                    plan.items.len(),
                    cx.processor(|this, range: Range<usize>, _, cx| {
                        let Some(Review::Undo(plan)) = &this.review else {
                            return vec![];
                        };
                        range
                            .map(|index| {
                                let item = &plan.items[index];
                                let color = if item.state == "blocked" {
                                    this.palette.review
                                } else {
                                    this.palette.accent
                                };
                                this.review_row(
                                    index,
                                    item.name.clone(),
                                    pretty(&item.state),
                                    color,
                                    cx,
                                )
                            })
                            .collect::<Vec<_>>()
                    }),
                );
                let detail = plan.items.get(self.review_index).map_or_else(
                    || {
                        div()
                            .p_4()
                            .child("No originals were found for this review.")
                    },
                    |item| self.undo_detail(item),
                );
                let available = plan
                    .items
                    .iter()
                    .filter(|item| item.state == "restore_available")
                    .count();
                self.split_review(
                    format!(
                        "{} RESTORABLE · {} TOTAL",
                        count(available),
                        count(plan.items.len())
                    ),
                    list,
                    detail,
                )
                .into_any_element()
            }
        };
        div()
            .size_full()
            .min_h_0()
            .p_4()
            .flex()
            .items_center()
            .justify_center()
            .bg(rgb(p.soft))
            .child(
                div()
                    .w_full()
                    .max_w(px(940.))
                    .h_full()
                    .max_h(px(695.))
                    .min_h_0()
                    .flex()
                    .flex_col()
                    .bg(rgb(p.panel))
                    .border_1()
                    .border_color(rgb(p.line))
                    .rounded(px(7.))
                    .overflow_hidden()
                    .track_focus(&self.review_focus)
                    .child(
                        div()
                            .p_4()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .border_b_1()
                            .border_color(rgb(p.line))
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .text_size(rems(1.55))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child(icon(Icon::Shield, p.accent, 24.))
                                    .child(title),
                            )
                            .child(div().text_color(rgb(p.muted)).child(message)),
                    )
                    .child(content)
                    .child(
                        div()
                            .p_3()
                            .flex()
                            .flex_wrap()
                            .gap_2()
                            .items_center()
                            .justify_between()
                            .border_t_1()
                            .border_color(rgb(p.line))
                            .bg(rgb(p.soft))
                            .child(
                                button(
                                    p,
                                    "confirm-reviewed",
                                    if self.confirmed {
                                        "Reviewed"
                                    } else {
                                        "I reviewed the changes"
                                    },
                                    Some(if self.confirmed {
                                        Icon::Check
                                    } else {
                                        Icon::Plus
                                    }),
                                    if self.confirmed {
                                        ButtonStyle::Selected
                                    } else {
                                        ButtonStyle::Secondary
                                    },
                                    enabled,
                                )
                                .when(enabled, |d| {
                                    d.on_click(cx.listener(|this, _, _, cx| {
                                        this.confirmed = !this.confirmed;
                                        cx.notify();
                                    }))
                                }),
                            )
                            .child(
                                div()
                                    .text_size(rems(0.73))
                                    .text_color(rgb(if remaining > 0 { p.muted } else { p.error }))
                                    .child(timer),
                            )
                            .child(
                                div()
                                    .flex()
                                    .gap_2()
                                    .child(
                                        button(
                                            p,
                                            "cancel-review",
                                            "Cancel",
                                            None,
                                            ButtonStyle::Secondary,
                                            true,
                                        )
                                        .on_click(
                                            cx.listener(|this, _, w, cx| this.dismiss(w, cx)),
                                        ),
                                    )
                                    .child(
                                        button(
                                            p,
                                            "apply-review",
                                            apply,
                                            Some(Icon::Right),
                                            ButtonStyle::Primary,
                                            active,
                                        )
                                        .when(
                                            active,
                                            |d| {
                                                d.on_click(cx.listener(|this, _, w, cx| {
                                                    this.apply_review(w, cx)
                                                }))
                                            },
                                        ),
                                    ),
                            ),
                    ),
            )
    }

    fn split_review(&self, caption: String, list: UniformList, detail: Div) -> Div {
        let p = self.palette;
        div()
            .flex()
            .flex_1()
            .min_h_0()
            .child(
                div()
                    .w(px(300.))
                    .flex_shrink_0()
                    .flex()
                    .flex_col()
                    .min_h_0()
                    .border_r_1()
                    .border_color(rgb(p.line))
                    .child(
                        div()
                            .p_3()
                            .bg(rgb(p.soft))
                            .border_b_1()
                            .border_color(rgb(p.line))
                            .child(label(caption, p.muted)),
                    )
                    .child(list.flex_1().min_h_0()),
            )
            .child(
                div()
                    .id(("review-detail", self.review_index))
                    .min_w_0()
                    .min_h_0()
                    .flex_1()
                    .overflow_y_scroll()
                    .child(detail),
            )
    }

    fn review_row(
        &self,
        index: usize,
        name: String,
        status: String,
        color: u32,
        cx: &mut Context<Self>,
    ) -> Stateful<Div> {
        let p = self.palette;
        div()
            .id(("review-row", index))
            .w_full()
            .h(px(51.))
            .px_3()
            .flex()
            .flex_col()
            .justify_center()
            .gap_1()
            .border_b_1()
            .border_color(rgb(p.line))
            .bg(rgb(if index == self.review_index {
                p.selected
            } else {
                p.panel
            }))
            .focusable()
            .tab_stop(true)
            .cursor_pointer()
            .hover(|d| d.bg(rgb(p.soft)))
            .focus(|d| d.bg(rgb(p.selected)))
            .child(
                div()
                    .truncate()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(name),
            )
            .child(label(status, color))
            .on_click(cx.listener(move |this, _, _, cx| {
                this.review_index = index;
                cx.notify();
            }))
    }

    fn change_detail(&self, plan: &ChangePlan) -> Div {
        let p = self.palette;
        let mut detail = div()
            .p_4()
            .flex()
            .flex_col()
            .gap_3()
            .min_w_0()
            .child(
                div()
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_size(rems(1.17))
                    .child(plan.name.clone()),
            )
            .child(field(p, "Registry key", plan.registry_path.clone(), true))
            .child(
                div()
                    .flex()
                    .gap_3()
                    .flex_wrap()
                    .child(field(p, "View", view_name(&plan.registry_view), false).w_auto())
                    .child(
                        field(
                            p,
                            "Value name",
                            display_value(&plan.value_name, "(Default)"),
                            true,
                        )
                        .w_auto(),
                    )
                    .child(field(p, "Type", plan.value_type.clone(), false).w_auto()),
            )
            .child(field(
                p,
                "Original value",
                display_value(&plan.original_value, "(Empty)"),
                true,
            ))
            .child(field(
                p,
                "Result of this action",
                planned_result(plan),
                false,
            ));
        for (title, value) in [
            ("Resolved target", &plan.resolved_file),
            ("Original uninstall command", &plan.uninstall_command),
            ("Service executable", &plan.service_executable),
            ("Original open command", &plan.application_command),
        ] {
            if let Some(value) = value {
                detail = detail.child(field(p, title, value.clone(), true));
            }
        }
        if !plan.supporting_evidence.is_empty() {
            detail = detail.child(line(p)).children(
                plan.supporting_evidence
                    .iter()
                    .map(|(title, value)| field(p, title, value.clone(), true)),
            );
        }
        detail
    }

    fn undo_detail(&self, item: &UndoItem) -> Div {
        let p: Palette = self.palette;
        let mut detail = div()
            .p_4()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_size(rems(1.17))
                    .child(item.name.clone()),
            )
            .child(field(p, "State", pretty(&item.state), false))
            .child(field(p, "Registry key", item.registry_path.clone(), true))
            .child(field(p, "View", view_name(&item.registry_view), false))
            .child(field(
                p,
                "Value name",
                display_value(&item.value_name, "(Default)"),
                true,
            ))
            .child(field(p, "Backup", item.backup_id.clone(), true));
        if !item.reason.is_empty() {
            detail = detail.child(field(p, "Reason", item.reason.clone(), false));
        }
        if let Some(value) = &item.original {
            let bytes = value
                .bytes
                .iter()
                .take(128)
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
                .join(" ");
            detail = detail
                .child(field(
                    p,
                    "Original registry type",
                    value.kind.to_string(),
                    true,
                ))
                .child(field(
                    p,
                    "Original bytes",
                    if value.bytes.len() > 128 {
                        format!("{bytes} … ({} bytes)", count(value.bytes.len()))
                    } else {
                        bytes
                    },
                    true,
                ));
        }
        detail
    }
}

fn display_value(value: &str, empty: &str) -> String {
    if value.is_empty() {
        empty.to_string()
    } else {
        value.to_string()
    }
}

fn planned_result(plan: &ChangePlan) -> &'static str {
    if plan.action == "restore" {
        return "Restore the exact original registry value or configuration from the verified backup.";
    }
    match plan.scope.as_str() {
        "uninstall" => "Set SystemComponent to 1 to hide this installed-program listing.",
        "service" => "Change this service's startup configuration from Manual to Disabled.",
        "application" => "Add an empty NoOpenWith flag to hide the application from suggestions.",
        "shell_menu" => "Add an empty ProgrammaticAccessOnly flag to hide the context-menu item.",
        "sound_event" => "Replace this missing sound assignment with an empty REG_SZ value.",
        "run_history" => "Clear the reviewed Run dialog history snapshot.",
        "typed_paths" => "Clear the reviewed Explorer address history snapshot.",
        "application_leftover" => {
            "Remove the reviewed leftover value or update its search path as shown below."
        }
        _ => "Remove the reviewed registry value after verifying its backup.",
    }
}
