mod inventories;
mod model;
mod results;
mod review;
mod shell;
mod style;
#[cfg(test)]
mod ui_tests;
mod work;

use gpui::{prelude::*, *};
use gpui_component::{
    input::{InputEvent, InputState},
    Root,
};
use registry_core::{
    changes::{select_clean_entries, BackupInventory},
    history::HistoryInventory,
    journal::OperationInventory,
    report_exports::{export_findings, ExportRequest},
    Category, EntryStatus, ScanReport,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    mem,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use model::{count, leftover_groups, Filter, LeftoverGroup};
use style::{Icon, Palette};
use work::{Completed, Control, Progress, Review, Store};

actions!(
    registry,
    [
        RunScan,
        Find,
        ToggleInspector,
        Dismiss,
        NextFocus,
        PreviousFocus,
        NextEntry,
        PreviousEntry
    ]
);

pub fn run() {
    Application::new().run(|cx: &mut App| {
        gpui_component::init(cx);
        cx.bind_keys(key_bindings());
        let bounds = Bounds::centered(None, size(px(1320.), px(840.)), cx);
        let directory = dirs::data_local_dir().map(|root| root.join("dev.rustregistry.desktop"));
        let window = cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                window_min_size: Some(size(px(920.), px(640.))),
                titlebar: Some(TitlebarOptions {
                    title: Some("RustRegistry".into()),
                    ..Default::default()
                }),
                app_id: Some("dev.rustregistry.desktop".into()),
                ..Default::default()
            },
            move |window, cx| {
                let app = cx.new(|cx| Desktop::new(directory, window, cx));
                cx.new(|cx| Root::new(app, window, cx))
            },
        );
        if let Err(error) = window {
            eprintln!("RustRegistry could not open its window: {error:#}");
            cx.quit();
        }
        cx.on_window_closed(|cx| {
            if cx.windows().is_empty() {
                cx.quit();
            }
        })
        .detach();
    });
}

fn key_bindings() -> [KeyBinding; 8] {
    [
        KeyBinding::new("ctrl-r", RunScan, Some("Registry")),
        KeyBinding::new("ctrl-f", Find, Some("Registry")),
        KeyBinding::new("ctrl-i", ToggleInspector, Some("Registry")),
        KeyBinding::new("escape", Dismiss, Some("Registry")),
        KeyBinding::new("tab", NextFocus, Some("Registry")),
        KeyBinding::new("shift-tab", PreviousFocus, Some("Registry")),
        KeyBinding::new("down", NextEntry, Some("RegistryTable")),
        KeyBinding::new("up", PreviousEntry, Some("RegistryTable")),
    ]
}

#[cfg(test)]
mod tests {
    use super::{key_bindings, Find, RunScan, ToggleInspector};
    use gpui::{Action, Keystroke, Modifiers};

    #[test]
    fn desktop_shortcuts_match_windows_control_key_events() {
        let bindings = key_bindings();
        let commands: [(char, &dyn Action); 3] =
            [('r', &RunScan), ('f', &Find), ('i', &ToggleInspector)];
        for (key, action) in commands {
            let key_event = Keystroke {
                modifiers: Modifiers {
                    control: true,
                    ..Modifiers::default()
                },
                key: key.to_string(),
                key_char: None,
            };
            let binding = bindings
                .iter()
                .find(|binding| binding.action().partial_eq(action))
                .expect("command should have a shortcut");
            assert_eq!(
                binding.match_keystrokes(&[key_event]),
                Some(false),
                "Ctrl+{key} must match the command"
            );
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Page {
    Explorer,
    Leftovers,
    Clean,
    Coverage,
    History,
    Backups,
    Recovery,
    Settings,
}

impl Page {
    fn title(self) -> &'static str {
        match self {
            Self::Explorer => "Registry explorer",
            Self::Leftovers => "Application leftovers",
            Self::Clean => "Clean registry",
            Self::Coverage => "Scan coverage",
            Self::History => "Saved scans",
            Self::Backups => "Backups & restore",
            Self::Recovery => "Recovery Center",
            Self::Settings => "Settings",
        }
    }

    fn icon(self) -> Icon {
        match self {
            Self::Explorer => Icon::Grid,
            Self::Leftovers => Icon::Layers,
            Self::Clean => Icon::Clean,
            Self::Coverage => Icon::Coverage,
            Self::History => Icon::Clock,
            Self::Backups => Icon::Archive,
            Self::Recovery => Icon::Restore,
            Self::Settings => Icon::Settings,
        }
    }

    fn has_results(self) -> bool {
        matches!(self, Self::Explorer | Self::Leftovers | Self::Clean)
    }

    fn default_filter(self) -> Filter {
        Filter {
            category: (self == Self::Leftovers).then_some(Category::ApplicationLeftovers),
            ..Default::default()
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Appearance {
    #[default]
    System,
    Light,
    Dark,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
struct Preferences {
    appearance: Appearance,
    text_size: usize,
}

struct Job {
    title: &'static str,
    stoppable: bool,
    control: Control,
    progress: Option<Progress>,
}

struct Notice {
    title: String,
    details: Vec<String>,
    error: bool,
}

#[derive(Default)]
struct ResultsWorkspace {
    filter: Filter,
    selected: Option<usize>,
    detail_index: Option<usize>,
    results_scroll: UniformListScrollHandle,
    detail_scroll: ScrollHandle,
}

struct Desktop {
    page: Page,
    focus: FocusHandle,
    review_focus: FocusHandle,
    table_focus: FocusHandle,
    input: Entity<InputState>,
    store: Option<Store>,
    preferences: Preferences,
    palette: Palette,
    report: Option<Arc<ScanReport>>,
    archived: bool,
    stale: bool,
    counts: [usize; 3],
    filter: Filter,
    category_menu: bool,
    filtered: Vec<usize>,
    saved_workspaces: HashMap<Page, ResultsWorkspace>,
    selected: Option<usize>,
    detail_index: Option<usize>,
    inspector_visible: bool,
    groups: Vec<LeftoverGroup>,
    excluded_group_items: HashSet<(usize, usize)>,
    checked: HashSet<usize>,
    results_scroll: UniformListScrollHandle,
    detail_scroll: ScrollHandle,
    backups: Option<BackupInventory>,
    backup_inspected: Option<String>,
    backup_checked: HashSet<String>,
    operations: Option<OperationInventory>,
    history: Option<HistoryInventory>,
    review: Option<Review>,
    review_index: usize,
    confirmed: bool,
    job: Option<Job>,
    notice: Option<Notice>,
}

impl Desktop {
    fn new(directory: Option<PathBuf>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let store = directory.map(Store::new);
        let preferences = store
            .as_ref()
            .and_then(|store| std::fs::read(store.directory.join("desktop-preferences.json")).ok())
            .and_then(|json| serde_json::from_slice(&json).ok())
            .unwrap_or_default();
        let input = cx.new(|cx| InputState::new(window, cx).placeholder("Search entries"));
        cx.subscribe(&input, |this, input, event, cx| {
            if matches!(event, InputEvent::Change) {
                let value = input.read(cx).value();
                if this.filter.query == value.as_ref() {
                    return;
                }
                this.filter.query = value.to_string();
                if this.page.has_results() {
                    this.refilter();
                }
                cx.notify();
            }
        })
        .detach();
        let focus = cx.focus_handle();
        focus.focus(window);
        let notice = store.is_none().then(|| Notice {
            title: "Windows local storage is unavailable".into(),
            details: vec!["RustRegistry needs the Local AppData folder to protect changes.".into()],
            error: true,
        });
        Self {
            page: Page::Explorer,
            focus,
            review_focus: cx.focus_handle(),
            table_focus: cx.focus_handle(),
            input,
            store,
            preferences,
            palette: Palette::light(),
            report: None,
            archived: false,
            stale: false,
            counts: [0; 3],
            filter: Filter::default(),
            category_menu: false,
            filtered: Vec::new(),
            saved_workspaces: HashMap::new(),
            selected: None,
            detail_index: None,
            inspector_visible: true,
            groups: Vec::new(),
            excluded_group_items: HashSet::new(),
            checked: HashSet::new(),
            results_scroll: UniformListScrollHandle::new(),
            detail_scroll: ScrollHandle::new(),
            backups: None,
            backup_inspected: None,
            backup_checked: HashSet::new(),
            operations: None,
            history: None,
            review: None,
            review_index: 0,
            confirmed: false,
            job: None,
            notice,
        }
    }

    fn refilter(&mut self) {
        self.refresh_results();
        self.results_scroll.scroll_to_item(0, ScrollStrategy::Top);
    }

    fn refresh_results(&mut self) {
        self.filtered = self.report.as_ref().map_or_else(Vec::new, |report| {
            if self.page == Page::Clean && self.archived {
                return Vec::new();
            }
            let indices = self
                .filter
                .indices(&report.entries, self.page == Page::Clean);
            if self.page != Page::Leftovers {
                return indices;
            }
            let matched: HashSet<_> = indices.into_iter().collect();
            self.groups
                .iter()
                .filter(|group| group.related.iter().any(|index| matched.contains(index)))
                .map(|group| group.anchor)
                .collect()
        });
        if self
            .selected
            .is_none_or(|index| !self.filtered.contains(&index))
        {
            self.select(self.filtered.first().copied());
        }
    }

    fn select(&mut self, index: Option<usize>) {
        self.selected = index;
        self.inspect(index);
    }

    fn inspect(&mut self, index: Option<usize>) {
        self.detail_index = index;
        self.detail_scroll.set_offset(point(px(0.), px(0.)));
    }

    fn toggle_inspector(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.page.has_results() && self.review.is_none() {
            self.inspector_visible = !self.inspector_visible;
            if self.filtered.is_empty() {
                self.focus.focus(window);
            } else {
                self.table_focus.focus(window);
            }
            cx.notify();
        }
    }

    fn clear_filters(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.filter = self.page.default_filter();
        self.category_menu = false;
        self.input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.refilter();
        cx.notify();
    }

    fn step_entry(&mut self, offset: isize, cx: &mut Context<Self>) {
        if self.filtered.is_empty() {
            return;
        }
        let current = self
            .selected
            .and_then(|index| self.filtered.iter().position(|i| *i == index));
        let target = current.map_or(0, |index| {
            index
                .saturating_add_signed(offset)
                .min(self.filtered.len() - 1)
        });
        self.select(Some(self.filtered[target]));
        self.results_scroll.scroll_to_item(
            target,
            if offset < 0 {
                ScrollStrategy::Top
            } else {
                ScrollStrategy::Bottom
            },
        );
        cx.notify();
    }

    fn fresh_report(&self) -> Option<&Arc<ScanReport>> {
        self.report
            .as_ref()
            .filter(|report| !report.cancelled && !self.archived && !self.stale)
    }

    fn set_page(&mut self, page: Page, window: &mut Window, cx: &mut Context<Self>) {
        if self.review.is_some() || self.job.is_some() {
            return;
        }
        if self.page != page {
            if self.page.has_results() {
                self.saved_workspaces.insert(
                    self.page,
                    ResultsWorkspace {
                        filter: mem::take(&mut self.filter),
                        selected: self.selected.take(),
                        detail_index: self.detail_index.take(),
                        results_scroll: mem::take(&mut self.results_scroll),
                        detail_scroll: mem::take(&mut self.detail_scroll),
                    },
                );
            }
            self.page = page;
            self.category_menu = false;
            let workspace =
                self.saved_workspaces
                    .remove(&page)
                    .unwrap_or_else(|| ResultsWorkspace {
                        filter: page.default_filter(),
                        ..Default::default()
                    });
            self.filter = workspace.filter;
            self.selected = workspace.selected;
            self.detail_index = workspace.detail_index;
            self.results_scroll = workspace.results_scroll;
            self.detail_scroll = workspace.detail_scroll;
            self.input.update(cx, |input, cx| {
                input.set_value(self.filter.query.clone(), window, cx)
            });
            if page.has_results() {
                self.refresh_results();
            } else {
                self.filtered.clear();
            }
        }
        if matches!(page, Page::Backups | Page::Recovery | Page::History) {
            self.refresh(page, window, cx);
        }
        cx.notify();
    }

    fn save_preferences(&mut self, cx: &mut Context<Self>) {
        let result = (|| {
            let store = self
                .store
                .as_ref()
                .ok_or("Windows local storage is unavailable.")?;
            std::fs::create_dir_all(&store.directory).map_err(|e| e.to_string())?;
            let json = serde_json::to_vec(&self.preferences).map_err(|e| e.to_string())?;
            std::fs::write(store.directory.join("desktop-preferences.json"), json)
                .map_err(|e| e.to_string())
        })();
        if let Err(error) = result {
            self.notice = Some(Notice {
                title: "Could not save settings".into(),
                details: vec![error],
                error: true,
            });
        }
        cx.notify();
    }

    fn launch(
        &mut self,
        title: &'static str,
        stoppable: bool,
        work: impl FnOnce(Store, Control) -> Result<Completed, String> + Send + 'static,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(store) = self.store.clone().filter(|_| self.job.is_none()) else {
            return;
        };
        let control = Control::default();
        self.focus.focus(window);
        self.job = Some(Job {
            title,
            stoppable,
            control: control.clone(),
            progress: None,
        });
        self.notice = None;
        cx.notify();
        let worker = cx
            .background_executor()
            .spawn(async move { work(store, control) });
        cx.spawn_in(window, async move |this, cx| {
            let result = worker.await;
            let _ = this.update_in(cx, |this, window, cx| this.finish(result, window, cx));
        })
        .detach();
        if stoppable {
            cx.spawn(async move |this, cx| loop {
                cx.background_executor()
                    .timer(Duration::from_millis(80))
                    .await;
                let active = this.update(cx, |this, cx| {
                    let Some(job) = &mut this.job else {
                        return false;
                    };
                    if let Some(progress) = job.control.take_progress() {
                        job.progress = Some(progress);
                        cx.notify();
                    }
                    job.stoppable
                });
                if !matches!(active, Ok(true)) {
                    break;
                }
            })
            .detach();
        }
    }

    fn finish(
        &mut self,
        result: Result<Completed, String>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let title = self.job.take().map_or("Operation", |job| job.title);
        match result {
            Ok(Completed::Report(report, archived)) => {
                self.counts = [0; 3];
                for entry in &report.entries {
                    self.counts[match entry.assessment.status {
                        EntryStatus::Found => 0,
                        EntryStatus::Review => 1,
                        EntryStatus::Unknown => 2,
                    }] += 1;
                }
                if let Some(warning) = &report.history_warning {
                    self.notice = Some(Notice {
                        title: warning.clone(),
                        details: vec![],
                        error: true,
                    });
                }
                self.report = Some(Arc::new(report));
                self.groups = self
                    .report
                    .as_ref()
                    .map_or_else(Vec::new, |report| leftover_groups(&report.entries));
                self.excluded_group_items.clear();
                self.saved_workspaces.clear();
                self.archived = archived;
                self.stale = false;
                self.checked.clear();
                self.select(None);
                if archived {
                    self.clear_filters(window, cx);
                } else {
                    self.refilter();
                }
            }
            Ok(Completed::Backups(inventory)) => {
                let available: HashSet<_> = inventory
                    .backups
                    .iter()
                    .filter(|item| item.state == "restore_available")
                    .map(|item| &item.id)
                    .collect();
                self.backup_checked.retain(|id| available.contains(id));
                self.backups = Some(inventory);
            }
            Ok(Completed::Operations(inventory)) => self.operations = Some(inventory),
            Ok(Completed::History(inventory)) => self.history = Some(inventory),
            Ok(Completed::Review(review)) => {
                self.review = Some(review);
                self.review_index = 0;
                self.confirmed = false;
                self.review_focus.focus(window);
                cx.spawn(async move |this, cx| loop {
                    cx.background_executor().timer(Duration::from_secs(1)).await;
                    if !matches!(
                        this.update(cx, |this, cx| {
                            if this.review.is_none() {
                                return false;
                            }
                            cx.notify();
                            true
                        }),
                        Ok(true)
                    ) {
                        break;
                    }
                })
                .detach();
            }
            Ok(Completed::Receipt {
                title,
                details,
                registry_changed,
            }) => {
                self.notice = Some(Notice {
                    title,
                    details,
                    error: false,
                });
                if registry_changed {
                    let notice = self.notice.take();
                    self.refresh(self.page, window, cx);
                    self.notice = notice;
                }
            }
            Ok(Completed::Discarded) => {}
            Err(error) => {
                self.notice = Some(Notice {
                    title: title.into(),
                    details: vec![error],
                    error: true,
                })
            }
        }
        cx.notify();
    }

    fn scan(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.job.is_some() || self.review.is_some() {
            return;
        }
        self.set_page(Page::Explorer, window, cx);
        self.launch(
            "Scanning registry",
            true,
            |store, control| {
                control
                    .scan(&store)
                    .map(|report| Completed::Report(report, false))
            },
            window,
            cx,
        );
    }

    fn refresh(&mut self, page: Page, window: &mut Window, cx: &mut Context<Self>) {
        type Task = fn(Store, Control) -> Result<Completed, String>;
        let (title, action): (_, Task) = match page {
            Page::Backups => ("Reading backups", |store, _| {
                store.change(|m| m.inventory()).map(Completed::Backups)
            }),
            Page::Recovery => ("Reading operation journal", |store, _| {
                store
                    .change(|m| m.operation_inventory())
                    .map(Completed::Operations)
            }),
            Page::History => ("Reading saved scans", |store, _| {
                store.history().inventory().map(Completed::History)
            }),
            _ => return,
        };
        self.launch(title, false, action, window, cx);
    }

    fn open_archive(&mut self, id: String, window: &mut Window, cx: &mut Context<Self>) {
        self.set_page(Page::Explorer, window, cx);
        self.launch(
            "Opening saved scan",
            false,
            move |store, _| {
                store
                    .history()
                    .load(&id)
                    .map(|report| Completed::Report(report, true))
            },
            window,
            cx,
        );
    }

    fn export(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(report) = self.report.clone().filter(|_| !self.archived) else {
            return;
        };
        let export_indices: Vec<_> = if self.page == Page::Leftovers {
            let visible: HashSet<_> = self.filtered.iter().copied().collect();
            self.groups
                .iter()
                .filter(|group| visible.contains(&group.anchor))
                .flat_map(|group| group.related.iter().copied())
                .filter(|&index| report.entries[index].category == Category::ApplicationLeftovers)
                .collect::<HashSet<_>>()
                .into_iter()
                .collect()
        } else {
            self.filtered.clone()
        };
        let request = ExportRequest {
            scan_id: report.id.clone(),
            entry_ids: export_indices
                .iter()
                .map(|index| report.entries[*index].id.clone())
                .collect(),
            query: self.filter.query.clone(),
            category: self.filter.category,
            status: self.filter.status,
        };
        self.launch(
            "Exporting findings",
            false,
            move |store, _| {
                let result =
                    export_findings(&report, &request, &store.directory.join("reports-v1"))?;
                Ok(Completed::Receipt {
                    title: format!("Exported {} findings", count(result.entries)),
                    details: vec![result.path],
                    registry_changed: false,
                })
            },
            window,
            cx,
        );
    }

    fn prepare_entry(&mut self, index: usize, window: &mut Window, cx: &mut Context<Self>) {
        let Some(report) = self.fresh_report().cloned() else {
            return;
        };
        self.launch(
            "Checking live registry entry",
            false,
            move |store, _| {
                let plan =
                    store.change(|manager| manager.prepare_quarantine(&report.entries[index]))?;
                Ok(Completed::Review(Review::Change(Box::new(plan))))
            },
            window,
            cx,
        );
    }

    fn prepare_restore(&mut self, id: String, window: &mut Window, cx: &mut Context<Self>) {
        self.launch(
            "Checking backup against live registry",
            false,
            move |store, _| {
                let plan = store.change(|manager| manager.prepare_restore(&id))?;
                Ok(Completed::Review(Review::Change(Box::new(plan))))
            },
            window,
            cx,
        );
    }

    fn prepare_clean(&mut self, mode: &'static str, window: &mut Window, cx: &mut Context<Self>) {
        let indices = self.checked.iter().copied().collect();
        self.prepare_batch(mode, indices, window, cx);
    }

    fn prepare_batch(
        &mut self,
        mode: &'static str,
        indices: Vec<usize>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(report) = self.fresh_report().cloned() else {
            return;
        };
        let ids = if mode == "selected" {
            indices
                .into_iter()
                .map(|index| report.entries[index].id.clone())
                .collect()
        } else {
            Vec::new()
        };
        let category = if mode == "quick" {
            self.filter.category
        } else {
            None
        };
        self.launch(
            "Checking clean candidates",
            false,
            move |store, _| {
                let entries = select_clean_entries(&report.entries, mode, &ids, category)?;
                let plan = store.change(|manager| manager.prepare_clean(&entries, mode))?;
                Ok(Completed::Review(Review::Clean(plan)))
            },
            window,
            cx,
        );
    }

    fn prepare_undo(
        &mut self,
        operation: Option<String>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let ids: Vec<_> = self.backup_checked.iter().cloned().collect();
        self.launch(
            "Checking originals and live registry values",
            false,
            move |store, _| {
                let plan = store.change(|manager| match operation {
                    Some(id) => manager.prepare_undo_operation(&id),
                    None => manager.prepare_undo_backups(&ids),
                })?;
                Ok(Completed::Review(Review::Undo(plan)))
            },
            window,
            cx,
        );
    }

    fn dismiss(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.review.take().is_some() {
            self.focus.focus(window);
            self.launch(
                "Discarding review",
                false,
                |store, _| {
                    store.change(|manager| {
                        manager.cancel();
                        Ok(Completed::Discarded)
                    })
                },
                window,
                cx,
            );
        } else if self.category_menu {
            self.category_menu = false;
            cx.notify();
        } else if !self.filter.query.is_empty()
            && self.input.read(cx).focus_handle(cx).is_focused(window)
        {
            self.input
                .update(cx, |input, cx| input.set_value("", window, cx));
        }
    }
}
