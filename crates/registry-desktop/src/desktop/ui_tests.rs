use super::{key_bindings, Desktop, Page};
use gpui::{
    prelude::*, px, size, Bounds, Focusable, Modifiers, TestAppContext, VisualTestContext,
    WindowBounds, WindowOptions,
};
use gpui_component::Root;
use registry_core::{changes::STARTUP_KEY, journal::OperationKind};
use std::{io, path::PathBuf, ptr::null_mut};
use uuid::Uuid;
use windows_sys::Win32::System::Registry::{RegOverridePredefKey, HKEY};
use winreg::{enums::*, RegKey, RegValue};

struct RegistryFixture {
    software: RegKey,
    name: String,
    overrides: Vec<HKEY>,
}

impl RegistryFixture {
    fn new() -> (Self, RegKey) {
        let software = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags("Software", KEY_ALL_ACCESS)
            .expect("open the physical test parent before overriding HKCU");
        let name = format!("RustRegistry-DesktopTest-{}", Uuid::new_v4());
        let (root, disposition) = software
            .create_subkey_with_options_flags(&name, REG_OPTION_VOLATILE, KEY_ALL_ACCESS)
            .expect("create the disposable test root");
        assert_eq!(disposition, REG_CREATED_NEW_KEY);
        (
            Self {
                software,
                name,
                overrides: Vec::new(),
            },
            root,
        )
    }

    fn override_hive(&mut self, hive: HKEY, key: &RegKey) {
        // Windows confines this predefined-handle remapping to the test process.
        let status = unsafe { RegOverridePredefKey(hive, key.raw_handle()) };
        assert_eq!(status, 0, "override predefined key");
        self.overrides.push(hive);
    }
}

impl Drop for RegistryFixture {
    fn drop(&mut self) {
        for hive in self.overrides.drain(..).rev() {
            // Restore the mapping before allowing the process to use the predefined handle again.
            let status = unsafe { RegOverridePredefKey(hive, null_mut()) };
            if status != 0 {
                eprintln!("Could not reset the disposable test mapping: {status}");
            }
        }
        if let Err(error) = self.software.delete_subkey_all(&self.name) {
            eprintln!(
                "Could not remove the disposable test key {}: {error}",
                self.name
            );
        }
    }
}

fn volatile_key(parent: &RegKey, path: &str) -> RegKey {
    parent
        .create_subkey_with_options_flags(path, REG_OPTION_VOLATILE, KEY_ALL_ACCESS)
        .expect("create a key inside the disposable test root")
        .0
}

fn click(cx: &mut VisualTestContext, selector: &'static str) {
    let bounds = cx
        .debug_bounds(selector)
        .unwrap_or_else(|| panic!("Missing control {selector}"));
    cx.simulate_click(bounds.center(), Modifiers::none());
}

fn open_test_window(
    cx: &TestAppContext,
    directory: PathBuf,
) -> (gpui::Entity<Desktop>, VisualTestContext) {
    let window = cx.update(|cx| {
        gpui_component::init(cx);
        cx.bind_keys(key_bindings());
        let bounds = Bounds::centered(None, size(px(1320.), px(840.)), cx);
        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                ..Default::default()
            },
            |window, cx| {
                let view = cx.new(|cx| Desktop::new(Some(directory), window, cx));
                cx.new(|cx| Root::new(view, window, cx))
            },
        )
        .expect("open a GPUI test window")
    });
    let view = cx.update(|cx| {
        window
            .update(cx, |root, _, _| {
                root.view()
                    .clone()
                    .downcast::<Desktop>()
                    .expect("desktop root")
            })
            .expect("read the test window")
    });
    let visual = VisualTestContext::from_window(window.into(), cx);
    visual.run_until_parked();
    (view, visual)
}

#[gpui::test]
fn compact_desktop_reviews_applies_and_undoes_only_its_owned_value(cx: &mut TestAppContext) {
    let directory = tempfile::tempdir().expect("isolated desktop storage");
    let (view, mut ui) = open_test_window(cx, directory.path().to_path_buf());
    let (mut fixture, root) = RegistryFixture::new();
    let user = volatile_key(&root, "User");
    let machine = volatile_key(&root, "Machine");
    let startup = volatile_key(&user, STARTUP_KEY);
    let name = format!("RustRegistryDesktopFixture{}", Uuid::new_v4().simple());
    let missing = directory.path().join("absent-fixture.exe");
    startup
        .set_value(&name, &format!("\"{}\"", missing.display()))
        .expect("write the owned original");
    let original: RegValue = startup
        .get_raw_value(&name)
        .expect("read the exact original");
    fixture.override_hive(HKEY_CURRENT_USER, &user);
    fixture.override_hive(HKEY_LOCAL_MACHINE, &machine);

    ui.simulate_resize(size(px(920.), px(640.)));
    ui.run_until_parked();
    ui.simulate_keystrokes("ctrl-r");
    ui.update(|window, cx| {
        assert_eq!(window.viewport_size(), size(px(920.), px(640.)));
        let desktop = view.read(cx);
        let report = desktop
            .fresh_report()
            .expect("Ctrl+R should complete a live scan");
        assert!(report.entries.iter().any(|entry| entry.name == name));
    });

    ui.simulate_keystrokes("ctrl-f");
    ui.update(|window, cx| {
        assert!(view
            .read(cx)
            .input
            .read(cx)
            .focus_handle(cx)
            .is_focused(window))
    });
    ui.simulate_input(&name);
    ui.update(|_, cx| {
        let desktop = view.read(cx);
        assert_eq!(desktop.filtered.len(), 1);
        assert_eq!(
            desktop.report.as_ref().unwrap().entries[desktop.filtered[0]].name,
            name
        );
    });

    let table = ui.debug_bounds("results-table").expect("results table");
    let inspector = ui
        .debug_bounds("registry-inspector")
        .expect("registry inspector");
    assert!(table.right() <= inspector.left() && inspector.right() <= px(920.));
    ui.simulate_keystrokes("ctrl-i");
    ui.update(|_, cx| assert!(!view.read(cx).inspector_visible));
    assert!(ui.debug_bounds("results-table").unwrap().size.width > table.size.width);
    ui.simulate_keystrokes("ctrl-i");
    ui.update(|_, cx| assert!(view.read(cx).inspector_visible));
    assert_eq!(
        ui.debug_bounds("results-table").unwrap().size.width,
        table.size.width
    );

    click(&mut ui, Page::Coverage.title());
    click(&mut ui, Page::Explorer.title());
    ui.update(|_, cx| {
        let desktop = view.read(cx);
        assert_eq!(desktop.input.read(cx).value().as_ref(), name);
        assert_eq!(desktop.filtered.len(), 1);
        let report = desktop.report.as_ref().unwrap();
        assert_eq!(report.entries[desktop.detail_index.unwrap()].name, name);
    });

    click(&mut ui, "review-entry");
    let apply = ui
        .debug_bounds("apply-review")
        .expect("confirmation action");
    assert!(apply.right() <= px(920.) && apply.bottom() <= px(640.));
    click(&mut ui, "apply-review");
    ui.update(|_, cx| assert!(view.read(cx).review.is_some()));
    assert_eq!(startup.get_raw_value(&name).unwrap(), original);
    assert!(!directory.path().join("backups-v1").exists());

    click(&mut ui, "confirm-reviewed");
    click(&mut ui, "cancel-review");
    ui.update(|_, cx| assert!(view.read(cx).review.is_none()));
    assert_eq!(startup.get_raw_value(&name).unwrap(), original);
    assert!(!directory.path().join("backups-v1").exists());

    click(&mut ui, "review-entry");
    click(&mut ui, "confirm-reviewed");
    click(&mut ui, "apply-review");
    assert_eq!(
        startup.get_raw_value(&name).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    ui.update(|_, cx| {
        let desktop = view.read(cx);
        assert!(desktop.stale);
        assert!(desktop.notice.as_ref().is_some_and(|notice| !notice.error));
    });

    click(&mut ui, Page::Recovery.title());
    ui.update(|_, cx| {
        let desktop = view.read(cx);
        let operation = &desktop
            .operations
            .as_ref()
            .expect("operation journal")
            .operations[0];
        assert!(matches!(operation.kind, OperationKind::Clean) && operation.can_undo);
    });
    click(&mut ui, "undo-operation-0");
    click(&mut ui, "confirm-reviewed");
    click(&mut ui, "apply-review");
    assert_eq!(startup.get_raw_value(&name).unwrap(), original);
    ui.update(|_, cx| {
        let desktop = view.read(cx);
        let operations = &desktop
            .operations
            .as_ref()
            .expect("refreshed operation journal")
            .operations;
        assert!(operations.iter().any(
            |operation| matches!(operation.kind, OperationKind::Undo) && operation.applied == 1
        ));
    });

    click(&mut ui, Page::History.title());
    click(&mut ui, "open-scan-0");
    ui.update(|_, cx| {
        let desktop = view.read(cx);
        assert!(desktop.archived && desktop.fresh_report().is_none());
        assert!(desktop.input.read(cx).value().is_empty());
        assert!(!desktop.filtered.is_empty());
    });
    click(&mut ui, Page::Clean.title());
    ui.update(|_, cx| assert!(view.read(cx).filtered.is_empty()));
    assert_eq!(startup.get_raw_value(&name).unwrap(), original);
}
